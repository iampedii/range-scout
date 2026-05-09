package stormdns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"range-scout/internal/model"
	"range-scout/internal/stormdnsembed"
)

// keyMismatchAbortThreshold is the number of consecutive ErrKeyMismatch
// results across different resolvers that triggers a top-level abort,
// surfaced as ErrKeyMismatchAbort. Not user-configurable.
const keyMismatchAbortThreshold = 5

// Errors returned by Verify.
var (
	ErrInvalidConfig    = errors.New("stormdns.Verify: invalid Config")
	ErrKeyMismatchAbort = errors.New("stormdns.Verify: 5 consecutive ErrKeyMismatch results — check StormDNS Key")
)

// Prober is the surface Verify needs from stormdnsembed. Default impl forwards
// to stormdnsembed.ProbeMTU; tests inject fakes.
type Prober interface {
	ProbeMTU(ctx context.Context, opts stormdnsembed.ProbeOptions) stormdnsembed.ProbeResult
}

type defaultProber struct{}

func (defaultProber) ProbeMTU(ctx context.Context, opts stormdnsembed.ProbeOptions) stormdnsembed.ProbeResult {
	return stormdnsembed.ProbeMTU(ctx, opts)
}

// Config controls a Verify run.
type Config struct {
	Domain         string
	Key            string
	ScoreThreshold int
	QuerySize      int
	MTURetries     int
	Workers        int
	Timeout        time.Duration
	TestNearbyIPs  bool
	Prober         Prober // nil → default
}

// EventType enumerates progress event kinds.
type EventType int

const (
	EventProgress EventType = iota
	EventResolverPassed
	EventResolverFailed
)

// Event is a progress update emitted during Verify.
type Event struct {
	Type     EventType
	Resolver model.Resolver
	Tested   uint64
	Passed   uint64
	Total    uint64
}

// Result is what Verify returns.
type Result struct {
	Resolvers   []model.Resolver
	PassedCount uint64
	TestedCount uint64
	StartedAt   time.Time
	FinishedAt  time.Time
}

// Verify runs the StormDNS MTU probe against every score-eligible resolver in
// resolvers and returns the updated slice with StormDNSPassed/UpMTU/DownMTU
// fields populated.
func Verify(ctx context.Context, resolvers []model.Resolver, cfg Config, emit func(Event)) (Result, error) {
	if cfg.Domain == "" || cfg.Key == "" {
		return Result{}, fmt.Errorf("%w: Domain and Key are required", ErrInvalidConfig)
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 8
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.Prober == nil {
		cfg.Prober = defaultProber{}
	}

	out := make([]model.Resolver, len(resolvers))
	copy(out, resolvers)

	eligible := EligibleResolvers(out, cfg.ScoreThreshold)
	total := uint64(len(eligible))

	r := Result{Resolvers: out, StartedAt: time.Now()}
	if total == 0 {
		r.FinishedAt = time.Now()
		return r, nil
	}

	jobs := make(chan int, cfg.Workers)
	var tested, passed atomic.Uint64
	var consecutiveKeyMismatch atomic.Int32
	abortCtx, abortCancel := context.WithCancel(ctx)
	defer abortCancel()

	var wg sync.WaitGroup
	for w := 0; w < cfg.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if abortCtx.Err() != nil {
					return
				}
				res := cfg.Prober.ProbeMTU(abortCtx, stormdnsembed.ProbeOptions{
					ResolverIP:   out[idx].IP,
					ResolverPort: 53,
					Domain:       cfg.Domain,
					Key:          cfg.Key,
					QuerySize:    cfg.QuerySize,
					Retries:      cfg.MTURetries,
					Timeout:      cfg.Timeout,
				})
				out[idx].StormDNSChecked = true
				out[idx].StormDNSPassed = res.Passed
				out[idx].UpMTUBytes = res.UpMTUBytes
				out[idx].DownMTUBytes = res.DownMTUBytes
				out[idx].StormDNSLatencyMS = res.Latency.Milliseconds()
				if res.Err != nil {
					out[idx].StormDNSError = res.Err.Error()
				}

				tested.Add(1)
				if res.Passed {
					passed.Add(1)
					consecutiveKeyMismatch.Store(0)
					if emit != nil {
						emit(Event{Type: EventResolverPassed, Resolver: out[idx], Tested: tested.Load(), Passed: passed.Load(), Total: total})
					}
				} else {
					if errors.Is(res.Err, stormdnsembed.ErrKeyMismatch) {
						if consecutiveKeyMismatch.Add(1) >= keyMismatchAbortThreshold {
							abortCancel()
						}
					} else {
						consecutiveKeyMismatch.Store(0)
					}
					if emit != nil {
						emit(Event{Type: EventResolverFailed, Resolver: out[idx], Tested: tested.Load(), Passed: passed.Load(), Total: total})
					}
				}
			}
		}()
	}

dispatch:
	for _, idx := range eligible {
		select {
		case <-abortCtx.Done():
			break dispatch
		case jobs <- idx:
		}
	}
	close(jobs)
	wg.Wait()

	r.PassedCount = passed.Load()
	r.TestedCount = tested.Load()
	r.FinishedAt = time.Now()

	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	if consecutiveKeyMismatch.Load() >= keyMismatchAbortThreshold {
		return r, ErrKeyMismatchAbort
	}
	return r, nil
}
