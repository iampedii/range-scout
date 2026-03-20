package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"range-scout/internal/dnstt"
	"range-scout/internal/export"
	"range-scout/internal/model"
	"range-scout/internal/operators"
	"range-scout/internal/prefixes"
	"range-scout/internal/ripestat"
	"range-scout/internal/scanner"
)

type screen string

type scanSaveScope string
type targetSourceMode string

const (
	screenOperators screen = "operators"
	screenScanner   screen = "scanner"
	screenDNSTT     screen = "dnstt"

	scanSaveRecursiveOnly scanSaveScope = "recursive only"
	scanSaveAllDNSHosts   scanSaveScope = "all dns hosts"
	scanSaveDNSTTPassed   scanSaveScope = "dnstt passed only"

	targetSourceRIPE      targetSourceMode = "Automatic API Fetch"
	targetSourceImportTXT targetSourceMode = "Import TXT"
	targetSourcePaste     targetSourceMode = "Paste Targets"

	activityRenderLimit = 6
	targetPreviewLimit  = 3
	workflowBarWidth    = 16
	formNoteWrapWidth   = 24
	uiSeparatorLine     = "────────────────────────"
	operatorPlaceholder = "Paste or Import"
	customOperatorKey   = "custom"
	customOperatorName  = "Custom Targets"
)

var clipboardWriter = writeClipboardText

type scanProgress struct {
	Scanned   uint64
	Total     uint64
	Reachable uint64
	Recursive uint64
}

type dnsttProgress struct {
	Tested uint64
	Total  uint64
	Tunnel uint64
	E2E    uint64
}

type ui struct {
	app   *tview.Application
	pages *tview.Pages

	header       *tview.TextView
	operatorList *tview.List
	details      *tview.TextView
	commands     *tview.Flex
	form         *tview.Form
	buttonRows   []*tview.Form
	activity     *tview.TextView
	status       *tview.TextView

	operators []model.Operator
	mode      screen
	selected  int

	client      *ripestat.Client
	lookupCache map[string]model.LookupResult
	scanCache   map[string]model.ScanResult

	activeScanOperator  string
	liveProgress        scanProgress
	liveResolvers       []model.Resolver
	scanCancel          context.CancelFunc
	activeDNSTTOperator string
	liveDNSTTProgress   dnsttProgress
	dnsttCancel         context.CancelFunc

	prefixPath          string
	scanFormat          string
	scanPath            string
	scanSaveScope       scanSaveScope
	scanRanges          map[string][]string
	targetSources       map[string]targetSourceMode
	importPaths         map[string]string
	pasteBuffers        map[string]string
	prefixSuggestedPath string
	scanSuggestedPath   string
	scanWorkers         string
	scanTimeoutMS       string
	scanHostLimit       string
	scanPort            string
	scanProtocol        string
	scanProbeURL1       string
	scanProbeURL2       string
	dnsttDomain         string
	dnsttPubkey         string
	dnsttTimeoutMS      string
	dnsttE2ETimeoutS    string
	dnsttQuerySize      string
	dnsttE2EPort        string
	activityLines       []string
	lastStatusLine      string
	lockSelection       bool
}

func newUI() *ui {
	u := &ui{
		app:              tview.NewApplication(),
		pages:            tview.NewPages(),
		header:           tview.NewTextView(),
		operatorList:     tview.NewList(),
		details:          tview.NewTextView(),
		commands:         tview.NewFlex().SetDirection(tview.FlexRow),
		form:             tview.NewForm(),
		buttonRows:       []*tview.Form{tview.NewForm(), tview.NewForm(), tview.NewForm()},
		activity:         tview.NewTextView(),
		status:           tview.NewTextView(),
		operators:        operators.All(),
		selected:         -1,
		mode:             screenOperators,
		client:           ripestat.NewClient(),
		lookupCache:      make(map[string]model.LookupResult),
		scanCache:        make(map[string]model.ScanResult),
		scanFormat:       export.FormatTXT.String(),
		scanSaveScope:    scanSaveRecursiveOnly,
		scanRanges:       make(map[string][]string),
		targetSources:    make(map[string]targetSourceMode),
		importPaths:      make(map[string]string),
		pasteBuffers:     make(map[string]string),
		scanWorkers:      "256",
		scanTimeoutMS:    "1200",
		scanHostLimit:    "50000",
		scanPort:         "53",
		scanProtocol:     string(scanner.ProtocolUDP),
		scanProbeURL1:    "https://github.com",
		scanProbeURL2:    "https://example.com",
		dnsttTimeoutMS:   "3000",
		dnsttE2ETimeoutS: "20",
		dnsttQuerySize:   "",
		dnsttE2EPort:     "53",
	}

	u.configureViews()
	u.populateOperators()
	u.updateDefaultPaths()
	u.rebuildForm()
	u.addActivity("Ready")
	u.renderAll()
	u.setStatus("Ready. Select an operator for Automatic API Fetch, or use Import TXT / Paste Targets without one.")

	rightColumn := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(u.commands, 0, 1, false).
		AddItem(u.activity, 10, 0, false)

	body := tview.NewFlex().
		AddItem(u.operatorList, 32, 0, true).
		AddItem(u.details, 0, 1, false).
		AddItem(rightColumn, 42, 0, false)

	main := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(u.header, 3, 0, false).
		AddItem(body, 0, 1, true).
		AddItem(u.status, 4, 0, false)

	u.pages.AddPage("main", main, true, true)
	u.app.SetRoot(u.pages, true)
	u.app.SetFocus(u.operatorList)
	u.app.SetInputCapture(u.handleKeys)
	u.app.EnableMouse(true)
	u.app.EnablePaste(true)

	return u
}

func (u *ui) Run() error {
	return u.app.Run()
}

func (u *ui) configureViews() {
	u.header.
		SetDynamicColors(true).
		SetBorder(true).
		SetTitle("range-scout")

	u.operatorList.
		ShowSecondaryText(false).
		SetBorder(true).
		SetTitle("Operators")
	u.operatorList.SetChangedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		if u.lockSelection {
			return
		}
		if u.busyRunning() {
			u.restoreSelectedOperator()
			u.setStatus("An operation is running. Stop it before changing operator.")
			return
		}
		u.selected = u.operatorIndexFromList(index)
		u.updateDefaultPaths()
		u.rebuildForm()
		u.renderAll()
	})
	u.operatorList.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		if u.busyRunning() {
			u.setStatus("An operation is running. Stop it before loading or switching.")
			u.addActivity("Load blocked: operation active")
			u.restoreSelectedOperator()
			return
		}
		u.selected = u.operatorIndexFromList(index)
		u.loadTargets()
	})

	u.details.
		SetDynamicColors(true)
	u.details.SetBorder(true)
	u.details.SetTitle("Details")
	u.details.SetWrap(false)

	u.form.
		SetBorder(true)
	u.form.SetTitle("Commands")
	u.form.SetButtonsAlign(tview.AlignLeft)
	for _, row := range u.buttonRows {
		row.SetBorder(false)
		row.SetButtonsAlign(tview.AlignLeft)
	}

	u.activity.
		SetDynamicColors(true)
	u.activity.SetBorder(true)
	u.activity.SetTitle("Activity Log")
	u.activity.SetWrap(true)

	u.status.
		SetDynamicColors(true).
		SetBorder(true).
		SetTitle("Status")
}

func (u *ui) populateOperators() {
	u.operatorList.AddItem(operatorPlaceholder, "", 0, nil)
	for _, op := range u.operators {
		u.operatorList.AddItem(fmt.Sprintf("%s [%s]", op.Name, strings.Join(op.ASNs, ", ")), "", 0, nil)
	}
	u.restoreSelectedOperator()
}

func (u *ui) handleKeys(event *tcell.EventKey) *tcell.EventKey {
	if u.pages.HasPage("range-picker") || u.pages.HasPage("paste-targets") || u.pages.HasPage("confirm-exit") {
		return event
	}

	if u.focusIsEditable() {
		if event.Key() == tcell.KeyEsc {
			u.app.SetFocus(u.operatorList)
			return nil
		}
		return event
	}

	if u.busyRunning() {
		switch {
		case event.Rune() == 'q':
			u.confirmExit()
			return nil
		case event.Key() == tcell.KeyTab:
			u.cycleFocus()
			return nil
		case event.Key() == tcell.KeyBacktab:
			u.reverseFocus()
			return nil
		case event.Rune() == 'x':
			u.stopActiveOperation()
			return nil
		case event.Rune() == 'p' || event.Rune() == 'd' || event.Rune() == 'f' || event.Rune() == 's' || event.Rune() == 'g' || event.Rune() == 't':
			u.blockDuringBusy("Another operation is blocked while a task is running.")
			return nil
		}
		switch event.Key() {
		case tcell.KeyUp, tcell.KeyDown, tcell.KeyEnter, tcell.KeyPgUp, tcell.KeyPgDn, tcell.KeyHome, tcell.KeyEnd:
			if u.app.GetFocus() == u.operatorList {
				u.setStatus("An operation is running. Stop it before changing operator.")
				return nil
			}
		}
	}

	switch {
	case event.Key() == tcell.KeyTab:
		u.cycleFocus()
		return nil
	case event.Key() == tcell.KeyBacktab:
		u.reverseFocus()
		return nil
	case event.Rune() == 'q':
		u.confirmExit()
		return nil
	case event.Rune() == 'p':
		u.mode = screenOperators
		u.rebuildForm()
		u.renderAll()
		return nil
	case event.Rune() == 'd':
		if u.mode == screenDNSTT {
			u.backToScanner()
			return nil
		}
		u.openScanner()
		return nil
	case event.Rune() == 'f':
		u.loadTargets()
		return nil
	case event.Rune() == 's':
		if u.mode == screenOperators {
			u.savePrefixes()
		} else if u.mode == screenScanner && u.hasCompletedDNSTT(u.currentTargetKey()) {
			u.setStatus("Open Test DNSTT to export passed resolvers.")
			u.addActivity("Export redirected: open DNSTT screen for passed results")
		} else {
			u.saveResolvers()
		}
		return nil
	case event.Rune() == 'g' && u.mode == screenScanner:
		u.startScan()
		return nil
	case event.Rune() == 't' && u.mode == screenScanner:
		u.openDNSTTSetup()
		return nil
	case event.Rune() == 't' && u.mode == screenDNSTT:
		u.startDNSTTTest()
		return nil
	case event.Rune() == 'x' && (u.mode == screenScanner || u.mode == screenDNSTT):
		u.stopActiveOperation()
		return nil
	}

	return event
}

func (u *ui) cycleFocus() {
	targets := u.focusTargets()
	current := u.app.GetFocus()
	for index, target := range targets {
		if target == current {
			u.app.SetFocus(targets[(index+1)%len(targets)])
			return
		}
	}
	u.app.SetFocus(targets[0])
}

func (u *ui) reverseFocus() {
	targets := u.focusTargets()
	current := u.app.GetFocus()
	for index, target := range targets {
		if target == current {
			u.app.SetFocus(targets[(index-1+len(targets))%len(targets)])
			return
		}
	}
	u.app.SetFocus(targets[len(targets)-1])
}

func (u *ui) focusIsEditable() bool {
	if formHasEditableFocus(u.form) {
		return true
	}

	switch u.app.GetFocus().(type) {
	case *tview.InputField, *tview.DropDown:
		return true
	default:
		return false
	}
}

func formHasEditableFocus(form *tview.Form) bool {
	if form == nil {
		return false
	}
	for index := 0; index < form.GetFormItemCount(); index++ {
		item := form.GetFormItem(index)
		if item == nil || !item.HasFocus() {
			continue
		}
		switch item.(type) {
		case *tview.InputField, *tview.DropDown:
			return true
		}
	}
	return false
}

func (u *ui) currentOperator() (model.Operator, bool) {
	if u.selected < 0 || u.selected >= len(u.operators) {
		return model.Operator{}, false
	}
	return u.operators[u.selected], true
}

func (u *ui) selectedOperator() model.Operator {
	if len(u.operators) == 0 {
		return model.Operator{}
	}
	if u.selected < 0 || u.selected >= len(u.operators) {
		u.selected = 0
	}
	return u.operators[u.selected]
}

func (u *ui) hasSelectedOperator() bool {
	_, ok := u.currentOperator()
	return ok
}

func (u *ui) currentOperatorKey() string {
	if operator, ok := u.currentOperator(); ok {
		return operator.Key
	}
	return ""
}

func customTargetsOperator() model.Operator {
	return model.Operator{
		Key:  customOperatorKey,
		Name: customOperatorName,
	}
}

func (u *ui) currentTargetOperator() model.Operator {
	if operator, ok := u.currentOperator(); ok {
		return operator
	}
	return customTargetsOperator()
}

func (u *ui) currentTargetKey() string {
	return u.currentTargetOperator().Key
}

func (u *ui) currentDisplayOperator() (model.Operator, bool) {
	if operator, ok := u.currentOperator(); ok {
		return operator, true
	}
	if u.hasFetchedPrefixes(customOperatorKey) || u.hasCompletedScan(customOperatorKey) || u.activeScanOperator == customOperatorKey || u.activeDNSTTOperator == customOperatorKey {
		return customTargetsOperator(), true
	}
	return model.Operator{}, false
}

func (u *ui) operatorIndexFromList(index int) int {
	index--
	if index < 0 || index >= len(u.operators) {
		return -1
	}
	return index
}

func (u *ui) listIndexForOperatorSelection() int {
	if !u.hasSelectedOperator() {
		return 0
	}
	return u.selected + 1
}

func (u *ui) rebuildForm() {
	u.form.Clear(true)
	u.clearButtonRows()

	if u.busyRunning() {
		if u.dnsttRunning() {
			u.form.SetTitle("Commands - DNSTT Running")
			u.addButtonRow(0, buttonSpec{label: "Stop DNSTT", action: u.stopDNSTTTest})
		} else {
			u.form.SetTitle("Commands - Scan Running")
			u.addButtonRow(0, buttonSpec{label: "Stop Scan", action: u.stopScan})
		}
		u.rebuildCommands()
		return
	}

	_, hasOperator := u.currentOperator()
	targetOperator := u.currentTargetOperator()
	targetKey := targetOperator.Key

	switch u.mode {
	case screenOperators:
		sourceMode := u.selectedTargetSource(targetKey)
		u.form.SetTitle("Commands - Targets")
		u.form.AddFormItem(u.newTargetSourceDropDown("Load From", targetSourceOptions(hasOperator), sourceMode, func(value targetSourceMode) {
			u.setSelectedTargetSource(targetKey, value)
			u.updateDefaultPaths()
			u.rebuildForm()
			u.renderAll()
		}))
		if !hasOperator {
			u.addWrappedReadOnlyInput("Load Note", "Automatic API Fetch unlocks after you select an operator")
		}
		if sourceMode == targetSourceImportTXT {
			u.form.AddFormItem(u.newInput("Import File", u.importPath(targetKey), func(value string) {
				u.setImportPath(targetKey, value)
			}))
			u.addWrappedReadOnlyInput("Import Note", "TXT only. One IPv4 CIDR or single IPv4 per line. # comments ignored")
		} else if sourceMode == targetSourcePaste {
			u.form.AddFormItem(u.newReadOnlyInput("Paste Status", u.pasteStatus(targetKey)))
			u.addWrappedReadOnlyInput("Paste Note", "Open Paste Targets to paste one IPv4 CIDR or IPv4 address per line")
		}
		if sourceMode == targetSourcePaste {
			u.addButtonRow(0, buttonSpec{label: "Paste Targets", action: u.openPasteTargetsModal})
		} else {
			u.addButtonRow(0, buttonSpec{label: primaryLoadButtonLabel(sourceMode), action: u.loadTargets})
		}
		if u.hasFetchedPrefixes(targetKey) {
			u.form.AddFormItem(u.newReadOnlyInput("Save As", export.FormatTXT.String()))
			u.form.AddFormItem(u.newInput("Save To", u.prefixPath, func(value string) { u.prefixPath = value }))
			u.addButtonRow(1,
				buttonSpec{label: "Save Targets", action: u.savePrefixes},
				buttonSpec{label: "Scan Setup", action: u.openScanner},
			)
		}
	case screenScanner:
		if !hasOperator && !u.hasFetchedPrefixes(targetKey) && !u.hasCompletedScan(targetKey) && u.activeScanOperator != targetKey && u.activeDNSTTOperator != targetKey {
			u.form.SetTitle("Commands - DNS Scan")
			u.addButtonRow(2, buttonSpec{label: "Back", action: u.backToPrefixes})
			u.rebuildCommands()
			return
		}
		operatorKey := targetKey
		scanCompleted := u.hasCompletedScan(operatorKey)
		canRunDNSTT := scanCompleted && u.hasDNSTTCandidates(operatorKey)
		canExport := scanCompleted && !u.hasCompletedDNSTT(operatorKey)

		u.form.SetTitle("Commands - DNS Scan")
		u.ensureScanRangeSelection(operatorKey)
		u.form.AddFormItem(u.newSectionHeader("DNS Scan", "Configure and run"))
		u.form.AddFormItem(u.newReadOnlyInput("Targets", u.selectedScanSummary(operatorKey)))
		u.form.AddFormItem(u.newInput("Workers", u.scanWorkers, func(value string) { u.scanWorkers = value }))
		u.form.AddFormItem(u.newInput("Timeout", u.scanTimeoutMS, func(value string) { u.scanTimeoutMS = value }))
		u.form.AddFormItem(u.newInput("Host Limit", u.scanHostLimit, func(value string) { u.scanHostLimit = value }))
		u.form.AddFormItem(u.newInput("Port", u.scanPort, func(value string) { u.scanPort = value }))
		u.form.AddFormItem(u.newScanProtocolDropDown("Protocol", u.scanProtocol, func(value string) { u.scanProtocol = value }))
		u.addWrappedReadOnlyInput("Probe Note", "Make sure each probe is accessible through your network")
		u.form.AddFormItem(u.newInput("Probe URL 1", u.scanProbeURL1, func(value string) { u.scanProbeURL1 = value }))
		u.form.AddFormItem(u.newInput("Probe URL 2", u.scanProbeURL2, func(value string) { u.scanProbeURL2 = value }))
		u.form.AddFormItem(u.newSectionHeader("Next Step", "Open DNSTT setup after scan"))
		if scanCompleted {
			u.form.AddFormItem(u.newReadOnlyInput("DNSTT Setup", "Ready after completed scan"))
			u.addWrappedReadOnlyInput("DNSTT Note", "Test DNSTT opens the dedicated DNSTT setup screen")
		} else {
			u.form.AddFormItem(u.newReadOnlyInput("DNSTT Setup", "Unlocked after completed scan"))
		}

		u.addButtonRow(0,
			buttonSpec{label: "Pick Targets", action: u.openRangePicker},
			buttonSpec{label: "Start Scan", action: u.startScan},
		)
		if canRunDNSTT || canExport {
			specs := make([]buttonSpec, 0, 2)
			if canRunDNSTT {
				specs = append(specs, buttonSpec{label: "Test DNSTT", action: u.openDNSTTSetup})
			}
			if canExport {
				specs = append(specs, buttonSpec{label: "Export", action: u.saveResolvers})
			}
			u.addButtonRow(1, specs...)
		}
		u.addButtonRow(2,
			buttonSpec{label: "Back", action: u.backToPrefixes},
		)
	case screenDNSTT:
		operatorKey := targetKey
		if !u.hasCompletedScan(operatorKey) && u.activeScanOperator != operatorKey {
			u.form.SetTitle("Commands - DNSTT E2E")
			u.addButtonRow(2, buttonSpec{label: "Back", action: u.backToScanner})
			u.rebuildCommands()
			return
		}
		dnsttCompleted := u.hasCompletedDNSTT(operatorKey)

		u.form.SetTitle("Commands - DNSTT E2E")
		u.form.AddFormItem(u.newSectionHeader("DNSTT Tunnel", "Configure and run"))
		u.form.AddFormItem(u.newReadOnlyInput("Tunnel Stage", "Ready after completed scan"))
		u.addWrappedReadOnlyInput("Tunnel Note", "Checks only healthy recursive resolvers through the DNSTT domain")
		u.form.AddFormItem(u.newInput("DNSTT Domain", u.dnsttDomain, func(value string) { u.dnsttDomain = value }))
		u.form.AddFormItem(u.newInput("DNSTT Timeout", u.dnsttTimeoutMS, func(value string) { u.dnsttTimeoutMS = value }))
		u.form.AddFormItem(u.newInput("Query Size", u.dnsttQuerySize, func(value string) { u.dnsttQuerySize = value }))

		u.form.AddFormItem(u.newSectionHeader("DNSTT E2E", "Optional after tunnel"))
		u.form.AddFormItem(u.newReadOnlyInput("E2E Stage", u.dnsttE2EStageLabel()))
		u.addWrappedReadOnlyInput("E2E Note", "Requires dnstt-client and Pubkey. Uses the resolver IP with E2E Port for SOCKS5 CONNECT")
		u.form.AddFormItem(u.newReadOnlyInput("DNSTT Client", u.dnsttClientFieldValue()))
		u.form.AddFormItem(u.newInput("DNSTT Pubkey", u.dnsttPubkey, func(value string) { u.dnsttPubkey = value }))
		u.form.AddFormItem(u.newInput("E2E Timeout", u.dnsttE2ETimeoutS, func(value string) { u.dnsttE2ETimeoutS = value }))
		u.form.AddFormItem(u.newInput("E2E Port", u.dnsttE2EPort, func(value string) { u.dnsttE2EPort = value }))

		u.form.AddFormItem(u.newSectionHeader("Export", "Save current stage results"))
		if dnsttCompleted {
			u.form.AddFormItem(u.newFormatDropDown("Format", u.scanFormat, func(value string) {
				u.scanFormat = value
				u.updateDefaultPaths()
				u.rebuildForm()
				u.renderAll()
			}))
			u.form.AddFormItem(u.newReadOnlyInput("Save Scope", string(u.effectiveScanSaveScope(operatorKey))))
			u.form.AddFormItem(u.newInput("Path", u.scanPath, func(value string) { u.scanPath = value }))
		} else {
			u.form.AddFormItem(u.newReadOnlyInput("Format", "Unlocked after DNSTT"))
			u.form.AddFormItem(u.newReadOnlyInput("Save Scope", "Unlocked after DNSTT"))
			u.form.AddFormItem(u.newReadOnlyInput("Path", "Unlocked after DNSTT"))
		}

		u.addButtonRow(0, buttonSpec{label: "Start DNSTT", action: u.startDNSTTTest})
		if dnsttCompleted {
			u.addButtonRow(
				1,
				buttonSpec{label: "Export Passed", action: u.saveResolvers},
				buttonSpec{label: "Copy Passed", action: u.copyPassedResolvers},
			)
		}
		u.addButtonRow(2, buttonSpec{label: "Back", action: u.backToScanner})
	}
	u.rebuildCommands()
}

func (u *ui) newInput(label, value string, onChange func(string)) *tview.InputField {
	field := tview.NewInputField().SetLabel(label + ": ").SetText(value)
	field.SetChangedFunc(onChange)
	return field
}

func (u *ui) addWrappedReadOnlyInput(label, value string) {
	lines := wrapFormValue(value, formNoteWrapWidth)
	if len(lines) == 0 {
		lines = []string{""}
	}
	for index, line := range lines {
		lineLabel := ""
		if index == 0 {
			lineLabel = label
		}
		u.form.AddFormItem(u.newReadOnlyInput(lineLabel, line))
	}
}

type buttonSpec struct {
	label  string
	action func()
}

func (u *ui) clearButtonRows() {
	for _, row := range u.buttonRows {
		row.Clear(true)
	}
}

func (u *ui) addButtonRow(index int, specs ...buttonSpec) {
	if index < 0 || index >= len(u.buttonRows) {
		return
	}
	for _, spec := range specs {
		if spec.label == "" || spec.action == nil {
			continue
		}
		u.buttonRows[index].AddButton(spec.label, spec.action)
	}
}

func (u *ui) rebuildCommands() {
	u.commands.Clear()
	u.commands.AddItem(u.form, 0, 1, false)
	for _, row := range u.buttonRows {
		if row.GetButtonCount() > 0 {
			u.commands.AddItem(row, 3, 0, false)
		}
	}
}

func (u *ui) focusTargets() []tview.Primitive {
	targets := []tview.Primitive{u.operatorList, u.details, u.form}
	for _, row := range u.buttonRows {
		if row.GetButtonCount() > 0 {
			targets = append(targets, row)
		}
	}
	return targets
}

func (u *ui) hasButton(label string) bool {
	if u.form.GetButtonIndex(label) != -1 {
		return true
	}
	for _, row := range u.buttonRows {
		if row.GetButtonIndex(label) != -1 {
			return true
		}
	}
	return false
}

func (u *ui) newReadOnlyInput(label, value string) *tview.InputField {
	labelText := ""
	if strings.TrimSpace(label) != "" {
		labelText = label + ": "
	}
	field := tview.NewInputField().SetLabel(labelText).SetText(value)
	field.SetDisabled(true)
	return field
}

func (u *ui) newSectionHeader(label, value string) *tview.InputField {
	field := tview.NewInputField().SetLabel(label + ": ").SetText(value)
	field.SetDisabled(true)
	return field
}

func (u *ui) newFormatDropDown(label, selected string, onChange func(string)) *tview.DropDown {
	options := []string{export.FormatTXT.String(), export.FormatCSV.String(), export.FormatJSON.String()}
	currentIndex := 0
	for i, option := range options {
		if option == selected {
			currentIndex = i
			break
		}
	}
	dropdown := tview.NewDropDown().SetLabel(label+": ").SetOptions(options, nil)
	dropdown.SetCurrentOption(currentIndex)
	dropdown.SetSelectedFunc(func(text string, index int) {
		if text != "" {
			onChange(text)
		}
	})
	return dropdown
}

func (u *ui) newTargetSourceDropDown(label string, options []targetSourceMode, selected targetSourceMode, onChange func(targetSourceMode)) *tview.DropDown {
	if len(options) == 0 {
		options = []targetSourceMode{targetSourceImportTXT, targetSourcePaste}
	}
	labels := make([]string, 0, len(options))
	currentIndex := 0
	for i, option := range options {
		labels = append(labels, string(option))
		if option == selected {
			currentIndex = i
			break
		}
	}
	dropdown := tview.NewDropDown().SetLabel(label+": ").SetOptions(labels, nil)
	dropdown.SetCurrentOption(currentIndex)
	dropdown.SetSelectedFunc(func(text string, index int) {
		if text != "" {
			onChange(targetSourceMode(text))
		}
	})
	return dropdown
}

func (u *ui) newScanSaveScopeDropDown(label string, selected scanSaveScope, onChange func(scanSaveScope)) *tview.DropDown {
	options := []string{string(scanSaveRecursiveOnly), string(scanSaveAllDNSHosts)}
	currentIndex := 0
	for i, option := range options {
		if option == string(selected) {
			currentIndex = i
			break
		}
	}
	dropdown := tview.NewDropDown().SetLabel(label+": ").SetOptions(options, nil)
	dropdown.SetCurrentOption(currentIndex)
	dropdown.SetSelectedFunc(func(text string, index int) {
		if text != "" {
			onChange(scanSaveScope(text))
		}
	})
	return dropdown
}

func (u *ui) newScanProtocolDropDown(label, selected string, onChange func(string)) *tview.DropDown {
	options := []string{string(scanner.ProtocolUDP), string(scanner.ProtocolTCP), string(scanner.ProtocolBoth)}
	currentIndex := 0
	for i, option := range options {
		if option == selected {
			currentIndex = i
			break
		}
	}
	dropdown := tview.NewDropDown().SetLabel(label+": ").SetOptions(options, nil)
	dropdown.SetCurrentOption(currentIndex)
	dropdown.SetSelectedFunc(func(text string, index int) {
		if text != "" {
			onChange(text)
		}
	})
	return dropdown
}

func (u *ui) renderAll() {
	u.renderHeader()
	u.renderDetails()
	u.renderActivity()
	u.renderStatus()
}

func (u *ui) renderHeader() {
	modeLabel := "Targets"
	if u.mode == screenScanner {
		modeLabel = "DNS Scan"
	} else if u.mode == screenDNSTT {
		modeLabel = "DNSTT E2E"
	}

	operatorName := "No Operator Selected"
	viewKey := ""
	if operator, ok := u.currentDisplayOperator(); ok {
		operatorName = operator.Name
		viewKey = operator.Key
	}
	line1 := fmt.Sprintf("[yellow]%s[-]  [cyan]%s[-]", operatorName, modeLabel)
	line2 := "p targets  f load  q exit"
	if u.mode == screenScanner && viewKey != "" {
		operatorKey := viewKey
		parts := []string{"p targets", "d dns", "g scan"}
		if u.hasCompletedScan(operatorKey) && !u.hasCompletedDNSTT(operatorKey) {
			parts = append(parts, "s export")
		}
		if u.hasDNSTTCandidates(operatorKey) {
			parts = append(parts, "t dnstt")
		}
		parts = append(parts, "q exit")
		line2 = strings.Join(parts, "  ")
	} else if u.mode == screenDNSTT && viewKey != "" {
		operatorKey := viewKey
		parts := []string{"p targets", "d dns", "t start"}
		if u.hasCompletedDNSTT(operatorKey) {
			parts = append(parts, "s export")
		}
		parts = append(parts, "q exit")
		line2 = strings.Join(parts, "  ")
	} else if viewKey != "" && u.hasFetchedPrefixes(viewKey) {
		line2 = "p targets  f load  s save  d dns  q exit"
	}
	if u.busyRunning() {
		line2 = "task active: stop or quit only"
	}
	u.header.SetText(line1 + "\n" + line2)
}

func (u *ui) openScanner() {
	operator := u.currentTargetOperator()
	if !u.hasFetchedPrefixes(operator.Key) {
		u.setStatus("Load targets before opening the scanner.")
		u.addActivity(fmt.Sprintf("Scan view blocked for %s: load targets first", operator.Name))
		return
	}
	u.mode = screenScanner
	u.updateDefaultPaths()
	u.rebuildForm()
	u.renderAll()
}

func (u *ui) openDNSTTSetup() {
	operator := u.currentTargetOperator()
	result, ok := u.scanCache[operator.Key]
	if !ok || len(result.Resolvers) == 0 || !u.hasCompletedScan(operator.Key) {
		u.setStatus("Run a DNS scan first before opening DNSTT setup.")
		u.addActivity(fmt.Sprintf("DNSTT setup blocked for %s: no scan results", operator.Name))
		return
	}
	if !u.hasDNSTTCandidates(operator.Key) {
		u.setStatus("No healthy recursive resolvers are available for DNSTT testing.")
		u.addActivity(fmt.Sprintf("DNSTT setup blocked for %s: no healthy resolvers", operator.Name))
		return
	}
	u.mode = screenDNSTT
	u.updateDefaultPaths()
	u.rebuildForm()
	u.renderAll()
}

func (u *ui) backToPrefixes() {
	if u.busyRunning() {
		u.blockDuringBusy("Back is blocked while a task is running.")
		return
	}
	u.mode = screenOperators
	u.rebuildForm()
	u.renderAll()
}

func (u *ui) backToScanner() {
	if u.busyRunning() {
		u.blockDuringBusy("Back is blocked while a task is running.")
		return
	}
	u.mode = screenScanner
	u.rebuildForm()
	u.renderAll()
}

func (u *ui) openRangePicker() {
	operator := u.currentTargetOperator()
	lookup, ok := u.lookupCache[operator.Key]
	if !ok || len(lookup.Entries) == 0 {
		u.setStatus("Load targets before choosing scan targets.")
		u.addActivity(fmt.Sprintf("Target picker blocked for %s: load targets first", operator.Name))
		return
	}
	customTargets := lookupUsesCustomTargets(lookup)

	u.ensureScanRangeSelection(operator.Key)
	selected := make(map[string]bool, len(u.scanRanges[operator.Key]))
	for _, prefix := range u.scanRanges[operator.Key] {
		selected[prefix] = true
	}

	search := tview.NewInputField().
		SetLabel("Filter: ").
		SetText("").
		SetPlaceholder("CIDR, IP, slash, or fragment")
	search.SetPlaceholderTextColor(tcell.ColorGray)
	list := tview.NewList()
	list.ShowSecondaryText(false)
	list.SetBorder(true)
	list.SetTitle("Pick Scan Targets")
	list.SetWrapAround(false)

	visibleIndices := make([]int, 0, len(lookup.Entries))
	currentIndex := 0
	refreshList := func(query string, keepPrefix string) {
		list.Clear()
		visibleIndices = visibleIndices[:0]
		currentIndex = 0
		for _, index := range filterPrefixEntryIndexes(lookup.Entries, query) {
			entry := lookup.Entries[index]
			list.AddItem(scanRangeLabel(entry, customTargets, selected[entry.Prefix]), "", 0, nil)
			if entry.Prefix == keepPrefix {
				currentIndex = len(visibleIndices)
			}
			visibleIndices = append(visibleIndices, index)
		}
		if len(visibleIndices) == 0 {
			list.AddItem("No matching targets", "", 0, nil)
			currentIndex = 0
		}
		list.SetCurrentItem(currentIndex)
	}

	toggleSelected := func(listIndex int) {
		if listIndex < 0 || listIndex >= len(visibleIndices) {
			return
		}
		entry := lookup.Entries[visibleIndices[listIndex]]
		if selected[entry.Prefix] {
			delete(selected, entry.Prefix)
		} else {
			selected[entry.Prefix] = true
		}
		refreshList(search.GetText(), entry.Prefix)
	}
	refreshList("", firstSelectedPrefix(u.selectedScanPrefixes(operator.Key)))

	closePicker := func() {
		u.pages.RemovePage("range-picker")
		u.app.SetFocus(u.form)
	}

	list.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		toggleSelected(index)
	})
	list.SetDoneFunc(func() {
		closePicker()
		u.renderAll()
	})
	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyRune:
			if event.Rune() == ' ' {
				toggleSelected(list.GetCurrentItem())
				return nil
			}
			if event.Rune() == 'q' {
				closePicker()
				u.renderAll()
				return nil
			}
		case tcell.KeyEscape:
			closePicker()
			u.renderAll()
			return nil
		case tcell.KeyTab:
			u.app.SetFocus(search)
			return nil
		}
		if event.Rune() == '/' {
			u.app.SetFocus(search)
			return nil
		}
		return event
	})

	search.SetChangedFunc(func(text string) {
		currentPrefix := ""
		if item := list.GetCurrentItem(); item >= 0 && item < len(visibleIndices) {
			currentPrefix = lookup.Entries[visibleIndices[item]].Prefix
		}
		refreshList(text, currentPrefix)
	})
	search.SetDoneFunc(func(key tcell.Key) {
		switch key {
		case tcell.KeyEscape:
			closePicker()
			u.renderAll()
		default:
			u.app.SetFocus(list)
		}
	})

	applySelection := func() {
		chosen := make([]string, 0, len(lookup.Entries))
		for _, entry := range lookup.Entries {
			if selected[entry.Prefix] {
				chosen = append(chosen, entry.Prefix)
			}
		}
		u.scanRanges[operator.Key] = chosen
		u.addActivity(fmt.Sprintf("Selected %d targets for %s", len(chosen), operator.Name))
		closePicker()
		u.rebuildForm()
		u.renderAll()
	}

	selectAll := func() {
		for _, entry := range lookup.Entries {
			selected[entry.Prefix] = true
		}
		refreshList(search.GetText(), firstVisiblePrefix(lookup.Entries, visibleIndices))
	}

	deselectAll := func() {
		clear(selected)
		refreshList(search.GetText(), firstVisiblePrefix(lookup.Entries, visibleIndices))
	}

	actions := tview.NewForm().
		AddButton("Select All", selectAll).
		AddButton("Deselect All", deselectAll).
		AddButton("Done", applySelection).
		AddButton("Cancel", func() {
			closePicker()
			u.renderAll()
		})
	actions.SetButtonsAlign(tview.AlignLeft)

	content := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(search, 3, 0, true).
		AddItem(list, 0, 1, false).
		AddItem(actions, 3, 0, false)

	frame := tview.NewFrame(content).
		SetBorders(1, 1, 1, 1, 1, 1)
	frame.AddText("Filter examples: 94.182, /24, 109.230. Enter or Space toggles. Select All / Deselect All update the full set.", false, tview.AlignCenter, tcell.ColorYellow)

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(frame, 0, 3, true).
			AddItem(nil, 0, 1, false), 0, 2, true).
		AddItem(nil, 0, 1, false)

	u.pages.AddPage("range-picker", modal, true, true)
	u.app.SetFocus(search)
}

func (u *ui) renderDetails() {
	var builder strings.Builder
	operator, ok := u.currentDisplayOperator()
	if !ok {
		if u.mode == screenScanner {
			u.details.SetTitle("DNS Scan Details")
			builder.WriteString("No operator selected.\n")
			builder.WriteString("Import TXT or Paste Targets first, then open Scan Setup.\n")
			builder.WriteString("Automatic API Fetch unlocks after you choose an operator.\n")
			builder.WriteString("Default save paths stay generic until you choose one.\n")
		} else if u.mode == screenDNSTT {
			u.details.SetTitle("DNSTT Details")
			builder.WriteString("No operator selected.\n")
			builder.WriteString("Load targets, run a DNS scan, then open Test DNSTT.\n")
			builder.WriteString("Automatic API Fetch unlocks after you choose an operator.\n")
			builder.WriteString("Default save paths stay generic until you choose one.\n")
		} else {
			u.details.SetTitle("Target Details")
			builder.WriteString("No operator selected.\n")
			builder.WriteString("Import TXT or Paste Targets are available without selecting an operator.\n")
			builder.WriteString("Automatic API Fetch unlocks after you choose an operator.\n")
			builder.WriteString("Default save paths stay generic until you choose one.\n")
		}
		u.details.SetText(builder.String())
		return
	}

	switch u.mode {
	case screenOperators:
		u.details.SetTitle("Target Details")
		fmt.Fprintf(&builder, "Operator: %s\n", operator.Name)
		fmt.Fprintf(&builder, "ASNs: %s\n\n", displayOperatorASNs(operator))
		if result, ok := u.lookupCache[operator.Key]; ok {
			fmt.Fprintf(&builder, "Loaded: %s\n", result.FetchedAt.Format("2006-01-02 15:04:05"))
			fmt.Fprintf(&builder, "Source: %s\n", result.SourceLabel)
			if result.SourcePath != "" {
				fmt.Fprintf(&builder, "File: %s\n", result.SourcePath)
			}
			fmt.Fprintf(&builder, "Targets: %s  Addresses: %s  Scan Hosts: %s\n\n",
				formatCount(uint64(len(result.Entries))),
				formatCount(result.TotalAddresses),
				formatCount(result.TotalScanHosts),
			)
			if len(result.Warnings) > 0 {
				builder.WriteString("Warnings:\n")
				for _, warning := range result.Warnings {
					fmt.Fprintf(&builder, "  - %s\n", warning)
				}
				builder.WriteString("\n")
			}
			if lookupUsesCustomTargets(result) {
				builder.WriteString("Loaded Targets\n")
				for index, entry := range result.Entries {
					fmt.Fprintf(&builder, "%02d  %-18s  %10s addr  %10s scan\n",
						index+1,
						displayTargetEntry(entry, true),
						formatCount(entry.TotalAddresses),
						formatCount(entry.ScanHosts),
					)
				}
			} else {
				builder.WriteString("Prefixes\n")
				for index, entry := range result.Entries {
					fmt.Fprintf(&builder, "%02d  %-18s  %-22s  %10s addr  %10s scan\n",
						index+1,
						entry.Prefix,
						prefixes.CompactASNLabel(entry.SourceASNs),
						formatCount(entry.TotalAddresses),
						formatCount(entry.ScanHosts),
					)
				}
			}
		} else {
			switch u.selectedTargetSource(operator.Key) {
			case targetSourceImportTXT:
				builder.WriteString("No imported targets loaded yet.\n")
				builder.WriteString("Set Import File to a .txt file with one IPv4 CIDR or IPv4 address per line, then press Enter, use Import TXT, or press 'f'.\n")
			case targetSourcePaste:
				builder.WriteString("No pasted targets loaded yet.\n")
				builder.WriteString("Open Paste Targets and paste one IPv4 CIDR or IPv4 address per line.\n")
			default:
				builder.WriteString("No target data loaded yet.\n")
				builder.WriteString("Press Enter on the selected operator, use Load Targets, or press 'f'.\n")
			}
		}
	case screenScanner:
		u.details.SetTitle("DNS Scan Details")
		operatorKey := operator.Key
		progress, resolvers := u.currentScanState(operatorKey)
		dnsttState := u.currentDNSTTState(operatorKey)
		stableCount := countStableResolvers(resolvers)
		_, hasCachedResult := u.scanCache[operatorKey]
		activeScanForCurrentOperator := u.activeScanOperator == operatorKey && u.scanCancel != nil
		activeDNSTTForCurrentOperator := u.activeDNSTTOperator == operatorKey && u.dnsttCancel != nil
		lookup, lookupLoaded := u.lookupCache[operatorKey]
		customTargets := lookupLoaded && lookupUsesCustomTargets(lookup)
		u.writeStageWorkflow(&builder, operatorKey, lookup, lookupLoaded, progress, dnsttState, activeScanForCurrentOperator, activeDNSTTForCurrentOperator, stableCount)
		fmt.Fprintf(&builder, "Operator: %s\n", operator.Name)
		fmt.Fprintf(&builder, "ASNs: %s\n\n", displayOperatorASNs(operator))

		writeDetailSectionHeader(&builder, "DNS Scan")
		if lookupLoaded {
			fmt.Fprintf(&builder, "Source: %s\n", lookup.SourceLabel)
			if lookup.SourcePath != "" {
				fmt.Fprintf(&builder, "File: %s\n", lookup.SourcePath)
			}
		}
		fmt.Fprintf(&builder, "Selected targets: %s\n", u.selectedScanSummary(operatorKey))
		if entries, err := u.selectedScanEntries(operatorKey); err == nil && len(entries) > 0 {
			fmt.Fprintf(&builder, "Selected IPs: %s\n", formatCount(totalPrefixAddresses(entries)))
			fmt.Fprintf(&builder, "Target preview: %s\n", selectedTargetPreview(entries, customTargets, targetPreviewLimit))
			builder.WriteString("Use Pick Targets for the full list.\n")
		}
		fmt.Fprintf(&builder, "Protocol: %s  Port: %s\n", displayScanProtocol(u.scanProtocol), displayScanPort(u.scanPort))
		fmt.Fprintf(&builder, "Probe URLs: %s | %s\n", displayProbeURL(u.scanProbeURL1), displayProbeURL(u.scanProbeURL2))
		builder.WriteString("Note: make sure each probe is accessible through your network.\n")
		if !hasCachedResult && u.activeScanOperator != operator.Key {
			writeScanOptionGuide(&builder)
		}
		if !activeScanForCurrentOperator {
			fmt.Fprintf(&builder, "Targets: %s  Scanned: %s  Reachable: %s  Recursive: %s  Stable: %s  Progress: %s %s\n",
				formatCount(progress.Total),
				formatCount(progress.Scanned),
				formatCount(progress.Reachable),
				formatCount(progress.Recursive),
				formatCount(stableCount),
				meterBar(progress.Scanned, progress.Total, 20),
				percent(progress.Scanned, progress.Total),
			)
			builder.WriteString("\n")
		}
		if u.activeScanOperator != "" && u.activeScanOperator != operator.Key {
			fmt.Fprintf(&builder, "Background scan running for %s.\n\n", u.operatorName(u.activeScanOperator))
		}

		writeDetailSectionHeader(&builder, "Export")
		if result, ok := u.scanCache[operator.Key]; ok && !activeScanForCurrentOperator {
			fmt.Fprintf(&builder, "Last finished: %s\n", result.FinishedAt.Format("2006-01-02 15:04:05"))
			fmt.Fprintf(&builder, "Workers: %d  Timeout: %d ms  Host Limit: %d  Protocol: %s  Port: %d\n",
				result.Workers,
				result.TimeoutMillis,
				result.HostLimit,
				displayScanProtocol(result.Protocol),
				displayResultPort(result.Port),
			)
			fmt.Fprintf(&builder, "Export mode: %s\n", u.effectiveScanSaveScope(operator.Key))
			fmt.Fprintf(&builder, "Cached reachability: %s DNS hosts  %s recursive  %s stable\n",
				formatCount(result.ReachableCount),
				formatCount(result.RecursiveCount),
				formatCount(countStableResolvers(result.Resolvers)),
			)
			if !result.DNSTTFinishedAt.IsZero() {
				fmt.Fprintf(&builder, "Last DNSTT: %s\n", result.DNSTTFinishedAt.Format("2006-01-02 15:04:05"))
				builder.WriteString("Next: open Test DNSTT to export only DNSTT-passed resolvers.\n\n")
			} else {
				builder.WriteString("Last DNSTT: not run yet\n")
				builder.WriteString("Next: run Test DNSTT for tunnel validation, or Export to save scan results.\n\n")
			}
		} else if !activeScanForCurrentOperator {
			if u.hasCompletedDNSTT(operator.Key) {
				builder.WriteString("DNSTT finished for this operator.\n")
				builder.WriteString("Next: open Test DNSTT to export passed resolvers.\n\n")
			} else {
				fmt.Fprintf(&builder, "Export mode: %s\n\n", u.effectiveScanSaveScope(operator.Key))
				builder.WriteString("No completed scan cached for this operator.\n")
				builder.WriteString("Next: Start Scan to unlock Test DNSTT and Export.\n\n")
			}
		} else {
			fmt.Fprintf(&builder, "Export mode: %s\n\n", u.effectiveScanSaveScope(operator.Key))
		}
		if len(resolvers) == 0 {
			if activeScanForCurrentOperator {
				builder.WriteString("No DNS services reached yet for this run.\n")
			} else {
				builder.WriteString("No DNS services reached yet.\n")
				builder.WriteString("Load targets, then start a scan with the form or press 'g'.\n")
			}
		} else {
			builder.WriteString("DNS Hosts\n")
			for index, resolver := range resolvers {
				status := "dns-only"
				if resolver.Stable {
					status = "stable"
				} else if resolver.RecursionAvailable {
					status = "recursive"
				}
				fmt.Fprintf(&builder, "%02d  %-15s  %-4s  %-9s  RA=%-5t  %-8s  %5d ms  %-7s  %s\n",
					index+1,
					resolver.IP,
					displayTransport(resolver.Transport),
					status,
					resolver.RecursionAdvertised,
					resolver.ResponseCode,
					resolver.LatencyMillis,
					dnsttStatusLabel(resolver),
					resolver.Prefix,
				)
				if showDNSTTError(resolver) {
					fmt.Fprintf(&builder, "    dnstt error: %s\n", displayDNSTTError(resolver.DNSTTError))
				}
			}
		}
	case screenDNSTT:
		u.details.SetTitle("DNSTT Details")
		operatorKey := operator.Key
		progress, resolvers := u.currentScanState(operatorKey)
		dnsttState := u.currentDNSTTState(operatorKey)
		stableCount := countStableResolvers(resolvers)
		activeScanForCurrentOperator := u.activeScanOperator == operatorKey && u.scanCancel != nil
		activeDNSTTForCurrentOperator := u.activeDNSTTOperator == operatorKey && u.dnsttCancel != nil
		lookup, lookupLoaded := u.lookupCache[operatorKey]
		u.writeStageWorkflow(&builder, operatorKey, lookup, lookupLoaded, progress, dnsttState, activeScanForCurrentOperator, activeDNSTTForCurrentOperator, stableCount)
		fmt.Fprintf(&builder, "Operator: %s\n", operator.Name)
		fmt.Fprintf(&builder, "ASNs: %s\n\n", displayOperatorASNs(operator))

		writeDetailSectionHeader(&builder, "DNS Scan")
		fmt.Fprintf(&builder, "Selected targets: %s\n", u.selectedScanSummary(operatorKey))
		fmt.Fprintf(&builder, "Protocol: %s  Port: %s\n", displayScanProtocol(u.scanProtocol), displayScanPort(u.scanPort))
		fmt.Fprintf(&builder, "Healthy recursive resolvers: %s\n\n", formatCount(countDNSTTCandidates(resolvers)))

		writeDetailSectionHeader(&builder, "DNSTT Setup")
		fmt.Fprintf(&builder, "Domain: %s\n", displayDNSTTDomain(u.dnsttDomain))
		fmt.Fprintf(&builder, "Timeout: %s ms  Query Size: %s\n", displayDNSTTTimeout(u.dnsttTimeoutMS), displayDNSTTQuerySize(u.dnsttQuerySize))
		fmt.Fprintf(&builder, "Pubkey: %s\n", displayDNSTTPubkey(u.dnsttPubkey))
		fmt.Fprintf(&builder, "E2E Timeout: %s s  E2E Port: %s\n", displayDNSTTE2ETimeout(u.dnsttE2ETimeoutS), displayDNSTTE2EPort(u.dnsttE2EPort))
		if path, ok := u.dnsttClientPath(); ok {
			fmt.Fprintf(&builder, "DNSTT Client: %s\n", path)
		} else if warning := u.dnsttClientWarning(); warning != "" {
			builder.WriteString("DNSTT Client: missing\n")
			fmt.Fprintf(&builder, "Warning: %s\n", warning)
		} else {
			builder.WriteString("DNSTT Client: optional for tunnel-only mode\n")
		}
		builder.WriteString("\n")

		writeDetailSectionHeader(&builder, "DNSTT Results")
		if activeDNSTTForCurrentOperator {
			fmt.Fprintf(&builder, "DNSTT running: tested %s/%s  tunnel %s  e2e %s\n\n",
				formatCount(dnsttState.Tested),
				formatCount(dnsttState.Total),
				formatCount(dnsttState.Tunnel),
				formatCount(dnsttState.E2E),
			)
		} else if u.activeDNSTTOperator != "" && u.activeDNSTTOperator != operator.Key {
			fmt.Fprintf(&builder, "Background DNSTT running for %s.\n\n", u.operatorName(u.activeDNSTTOperator))
		}
		fmt.Fprintf(&builder, "DNSTT candidates: %s  Checked: %s  Tunnel OK: %s  E2E OK: %s\n\n",
			formatCount(dnsttState.Total),
			formatCount(dnsttState.Tested),
			formatCount(dnsttState.Tunnel),
			formatCount(dnsttState.E2E),
		)

		writeDetailSectionHeader(&builder, "Export")
		if result, ok := u.scanCache[operatorKey]; ok && !result.DNSTTFinishedAt.IsZero() && !activeDNSTTForCurrentOperator {
			fmt.Fprintf(&builder, "Last DNSTT: %s\n", result.DNSTTFinishedAt.Format("2006-01-02 15:04:05"))
			builder.WriteString("Next: Export Passed saves only DNSTT-passed resolvers.\n\n")
		} else if !activeDNSTTForCurrentOperator {
			builder.WriteString("No completed DNSTT run cached for this operator.\n")
			builder.WriteString("Next: Start DNSTT to unlock Export Passed.\n\n")
		}
		if len(resolvers) == 0 {
			builder.WriteString("No DNS services reached yet.\n")
		} else {
			builder.WriteString("DNS Hosts\n")
			for index, resolver := range resolvers {
				status := "dns-only"
				if resolver.Stable {
					status = "stable"
				} else if resolver.RecursionAvailable {
					status = "recursive"
				}
				fmt.Fprintf(&builder, "%02d  %-15s  %-4s  %-9s  RA=%-5t  %-8s  %5d ms  %-7s  %s\n",
					index+1,
					resolver.IP,
					displayTransport(resolver.Transport),
					status,
					resolver.RecursionAdvertised,
					resolver.ResponseCode,
					resolver.LatencyMillis,
					dnsttStatusLabel(resolver),
					resolver.Prefix,
				)
				if showDNSTTError(resolver) {
					fmt.Fprintf(&builder, "    dnstt error: %s\n", displayDNSTTError(resolver.DNSTTError))
				}
			}
		}
	}

	u.details.SetText(builder.String())
}

func (u *ui) currentScanState(operatorKey string) (scanProgress, []model.Resolver) {
	if u.activeScanOperator == operatorKey && u.scanCancel != nil {
		return u.liveProgress, u.liveResolvers
	}
	if result, ok := u.scanCache[operatorKey]; ok {
		return scanProgress{
			Scanned:   result.ScannedTargets,
			Total:     result.TotalTargets,
			Reachable: result.ReachableCount,
			Recursive: result.RecursiveCount,
		}, result.Resolvers
	}
	return scanProgress{}, nil
}

func (u *ui) currentDNSTTState(operatorKey string) dnsttProgress {
	if u.activeDNSTTOperator == operatorKey && u.dnsttCancel != nil {
		return u.liveDNSTTProgress
	}
	if result, ok := u.scanCache[operatorKey]; ok {
		return dnsttProgress{
			Tested: result.DNSTTChecked,
			Total:  countDNSTTCandidates(result.Resolvers),
			Tunnel: result.DNSTTTunnel,
			E2E:    result.DNSTTE2E,
		}
	}
	return dnsttProgress{}
}

func (u *ui) loadTargets() {
	targetKey := u.currentTargetKey()
	switch u.selectedTargetSource(targetKey) {
	case targetSourceImportTXT:
		u.importTargets()
	case targetSourcePaste:
		u.openPasteTargetsModal()
	default:
		if !u.hasSelectedOperator() {
			u.setStatus("Automatic API Fetch requires selecting an operator. Use Import TXT or Paste Targets instead.")
			u.addActivity("Automatic API fetch blocked: no operator selected")
			return
		}
		u.fetchPrefixes()
	}
}

func (u *ui) fetchPrefixes() {
	if u.busyRunning() {
		u.blockDuringBusy("Load blocked while a task is running.")
		return
	}
	operator, ok := u.currentOperator()
	if !ok {
		u.setStatus("Automatic API Fetch requires selecting an operator. Use Import TXT or Paste Targets instead.")
		u.addActivity("Automatic API fetch blocked: no operator selected")
		return
	}
	u.setStatus(fmt.Sprintf("Loading operator targets for %s...", operator.Name))
	u.addActivity(fmt.Sprintf("Load started for %s", operator.Name))
	u.rebuildForm()
	u.renderAll()

	go func(op model.Operator) {
		result, err := u.client.LookupOperator(context.Background(), op)
		u.app.QueueUpdateDraw(func() {
			if len(result.Entries) > 0 {
				u.lookupCache[op.Key] = result
				delete(u.scanCache, op.Key)
				u.ensureScanRangeSelection(op.Key)
			}
			if err != nil && len(result.Entries) == 0 {
				u.setStatus(fmt.Sprintf("Load failed for %s: %v", op.Name, err))
				u.addActivity(fmt.Sprintf("Load failed for %s", op.Name))
			} else if err != nil {
				u.setStatus(fmt.Sprintf("Loaded %s targets for %s with warnings. Use Save Targets to export them.", formatCount(uint64(len(result.Entries))), op.Name))
				u.addActivity(fmt.Sprintf("Loaded %s targets for %s with warnings", formatCount(uint64(len(result.Entries))), op.Name))
			} else {
				u.setStatus(fmt.Sprintf("Loaded %s targets for %s. Use Save Targets to export them.", formatCount(uint64(len(result.Entries))), op.Name))
				u.addActivity(fmt.Sprintf("Loaded %s targets for %s", formatCount(uint64(len(result.Entries))), op.Name))
			}
			u.rebuildForm()
			u.renderAll()
		})
	}(operator)
}

func (u *ui) importTargets() {
	if u.busyRunning() {
		u.blockDuringBusy("Import blocked while a task is running.")
		return
	}
	operator := u.currentTargetOperator()
	importPath := strings.TrimSpace(u.importPath(operator.Key))
	if importPath == "" {
		u.setStatus("TXT path is empty. Choose a file with IPv4 CIDRs or IPv4 addresses.")
		u.addActivity(fmt.Sprintf("Import skipped for %s: empty TXT path", operator.Name))
		return
	}

	u.setStatus(fmt.Sprintf("Importing targets for %s...", operator.Name))
	u.addActivity(fmt.Sprintf("Import started for %s from %s", operator.Name, importPath))
	u.rebuildForm()
	u.renderAll()

	go func(op model.Operator, path string) {
		data, err := os.ReadFile(path)
		result := model.LookupResult{}
		if err == nil {
			result, err = parseCustomTargets(op, string(targetSourceImportTXT), path, string(data))
		}

		u.app.QueueUpdateDraw(func() {
			if len(result.Entries) > 0 {
				u.lookupCache[op.Key] = result
				delete(u.scanCache, op.Key)
				u.ensureScanRangeSelection(op.Key)
			}
			if err != nil && len(result.Entries) == 0 {
				u.setStatus(fmt.Sprintf("Import failed for %s: %v", op.Name, err))
				u.addActivity(fmt.Sprintf("Import failed for %s", op.Name))
			} else if len(result.Warnings) > 0 {
				u.setStatus(fmt.Sprintf("Imported %s targets for %s with warnings. Use Save Targets to export them.", formatCount(uint64(len(result.Entries))), op.Name))
				u.addActivity(fmt.Sprintf("Imported %s targets for %s with warnings", formatCount(uint64(len(result.Entries))), op.Name))
			} else {
				u.setStatus(fmt.Sprintf("Imported %s targets for %s. Use Save Targets to export them.", formatCount(uint64(len(result.Entries))), op.Name))
				u.addActivity(fmt.Sprintf("Imported %s targets for %s", formatCount(uint64(len(result.Entries))), op.Name))
			}
			u.rebuildForm()
			u.renderAll()
		})
	}(operator, importPath)
}

func (u *ui) openPasteTargetsModal() {
	if u.busyRunning() {
		u.blockDuringBusy("Paste blocked while a task is running.")
		return
	}

	operator := u.currentTargetOperator()
	textArea := tview.NewTextArea().
		SetWrap(false).
		SetPlaceholder("198.51.100.0/24\n198.51.100.10\n# comments supported")
	textArea.SetBorder(true).SetTitle("Paste Targets")
	textArea.SetText(u.pasteBuffer(operator.Key), false)
	textArea.SetOffset(0, 0)

	help := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true)
	updateHelp := func(message string) {
		if strings.TrimSpace(message) != "" {
			help.SetText(message)
			return
		}
		status := u.pasteStatusFromText(textArea.GetText())
		if status == "No pasted targets yet" {
			help.SetText("Paste one IPv4 CIDR or IPv4 address per line. Empty lines and # comments are ignored. Ctrl-V works.")
			return
		}
		help.SetText(fmt.Sprintf(
			"Paste one IPv4 CIDR or IPv4 address per line. Empty lines and # comments are ignored. %s. Ctrl-V works.",
			status,
		))
	}
	textArea.SetChangedFunc(func() {
		updateHelp("")
	})
	updateHelp("")

	closeModal := func() {
		u.pages.RemovePage("paste-targets")
		u.app.SetFocus(u.form)
	}

	applyPaste := func() {
		result, err := parseCustomTargets(operator, string(targetSourcePaste), "", textArea.GetText())
		if err != nil {
			updateHelp(fmt.Sprintf("[red]%v[-]", err))
			return
		}

		u.setPasteBuffer(operator.Key, textArea.GetText())
		u.lookupCache[operator.Key] = result
		delete(u.scanCache, operator.Key)
		u.ensureScanRangeSelection(operator.Key)

		if len(result.Warnings) > 0 {
			u.setStatus(fmt.Sprintf("Pasted %s targets for %s with warnings. Use Save Targets to export them.", formatCount(uint64(len(result.Entries))), operator.Name))
			u.addActivity(fmt.Sprintf("Pasted %s targets for %s with warnings", formatCount(uint64(len(result.Entries))), operator.Name))
		} else {
			u.setStatus(fmt.Sprintf("Pasted %s targets for %s. Use Save Targets to export them.", formatCount(uint64(len(result.Entries))), operator.Name))
			u.addActivity(fmt.Sprintf("Pasted %s targets for %s", formatCount(uint64(len(result.Entries))), operator.Name))
		}

		closeModal()
		u.rebuildForm()
		u.renderAll()
	}

	var actions *tview.Form
	textArea.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc:
			closeModal()
			u.renderAll()
			return nil
		case tcell.KeyCtrlS:
			applyPaste()
			return nil
		case tcell.KeyTab:
			if actions != nil {
				u.app.SetFocus(actions)
			}
			return nil
		}
		return event
	})

	actions = tview.NewForm().
		AddButton("Apply", applyPaste).
		AddButton("Cancel", func() {
			closeModal()
			u.renderAll()
		})
	actions.SetButtonsAlign(tview.AlignLeft)
	actions.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyTab:
			u.app.SetFocus(textArea)
			return nil
		case tcell.KeyEsc:
			closeModal()
			u.renderAll()
			return nil
		}
		return event
	})

	content := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(textArea, 0, 1, true).
		AddItem(help, 3, 0, false).
		AddItem(actions, 3, 0, false)

	frame := tview.NewFrame(content).
		SetBorders(1, 1, 1, 1, 1, 1)
	frame.AddText("Paste targets for the current selection. Apply replaces the current loaded target set. Ctrl-S applies.", false, tview.AlignCenter, tcell.ColorYellow)

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(frame, 0, 4, true).
			AddItem(nil, 0, 1, false), 0, 3, true).
		AddItem(nil, 0, 1, false)

	u.pages.AddPage("paste-targets", modal, true, true)
	u.app.SetFocus(textArea)
}

func (u *ui) savePrefixes() {
	if u.busyRunning() {
		u.blockDuringBusy("Target save blocked while a task is running.")
		return
	}
	operator := u.currentTargetOperator()
	savePath := u.preparePrefixSaveTarget(operator)
	u.rebuildForm()
	u.renderAll()
	result, ok := u.lookupCache[operator.Key]
	if !ok || len(result.Entries) == 0 {
		u.setStatus("No targets available yet.")
		u.addActivity("Target save skipped: nothing loaded")
		return
	}

	format := export.FormatTXT
	if err := export.SavePrefixes(savePath, format, result); err != nil {
		u.setStatus(fmt.Sprintf("Save failed: %v", err))
		u.addActivity(fmt.Sprintf("Target save failed for %s", operator.Name))
		return
	}
	u.rebuildForm()
	u.renderAll()
	u.setStatus(fmt.Sprintf("Saved targets to %s", savePath))
	u.addActivity(fmt.Sprintf("Saved %s targets for %s", formatCount(uint64(len(result.Entries))), operator.Name))
}

func (u *ui) startScan() {
	if u.busyRunning() {
		u.blockDuringBusy("Scan start blocked while another task is running.")
		return
	}
	operator := u.currentTargetOperator()
	selectedEntries, err := u.selectedScanEntries(operator.Key)
	if err != nil {
		u.setStatus(err.Error())
		u.addActivity(fmt.Sprintf("Scan blocked for %s: %v", operator.Name, err))
		return
	}
	if len(selectedEntries) == 0 {
		u.setStatus("Load targets first before starting a scan.")
		u.addActivity(fmt.Sprintf("Scan blocked for %s: load targets first", operator.Name))
		return
	}
	if u.scanCancel != nil {
		u.setStatus("A scan is already running.")
		u.addActivity("Scan start ignored: another scan is active")
		return
	}

	cfg, err := u.scanConfig()
	if err != nil {
		u.setStatus(err.Error())
		u.addActivity(fmt.Sprintf("Scan config invalid for %s", operator.Name))
		return
	}

	u.activeScanOperator = operator.Key
	u.liveProgress = scanProgress{Total: prefixes.EstimateScanTargets(selectedEntries, cfg.HostLimit)}
	u.liveResolvers = nil
	ctx, cancel := context.WithCancel(context.Background())
	u.scanCancel = cancel
	u.setStatus(fmt.Sprintf("Scanning %s...", operator.Name))
	u.addActivity(fmt.Sprintf(
		"Scan started for %s on %s using %s/%d with %d workers over %s targets",
		operator.Name,
		u.selectedScanSummary(operator.Key),
		cfg.Protocol,
		cfg.Port,
		cfg.Workers,
		formatCount(u.liveProgress.Total),
	))
	u.rebuildForm()
	u.renderAll()

	go func(op model.Operator, entries []model.PrefixEntry, config scanner.Config) {
		result, err := scanner.Scan(ctx, op, entries, config, func(event scanner.Event) {
			u.app.QueueUpdateDraw(func() {
				if u.activeScanOperator != op.Key {
					return
				}
				switch event.Type {
				case scanner.EventProgress:
					u.liveProgress = scanProgress{
						Scanned:   event.Scanned,
						Total:     event.Total,
						Reachable: event.Reachable,
						Recursive: event.Recursive,
					}
				case scanner.EventResolver:
					if event.Item != nil {
						u.liveResolvers = append(slices.Clone(u.liveResolvers), *event.Item)
					}
				}
				u.renderAll()
			})
		})

		u.app.QueueUpdateDraw(func() {
			u.scanCancel = nil
			u.activeScanOperator = ""
			if result.TotalTargets > 0 || len(result.Resolvers) > 0 {
				u.scanCache[op.Key] = result
			}
			if errors.Is(err, context.Canceled) {
				u.setStatus(fmt.Sprintf("Scan canceled for %s. Partial results are available in memory. Use Export to save them.", op.Name))
				u.addActivity(fmt.Sprintf("Scan canceled for %s after %s targets", op.Name, formatCount(result.ScannedTargets)))
			} else if err != nil {
				u.setStatus(fmt.Sprintf("Scan failed for %s: %v", op.Name, err))
				u.addActivity(fmt.Sprintf("Scan failed for %s", op.Name))
			} else {
				u.setStatus(fmt.Sprintf(
					"Scan finished for %s: %s DNS hosts, %s recursive. Use Export to save results.",
					op.Name,
					formatCount(result.ReachableCount),
					formatCount(result.RecursiveCount),
				))
				u.addActivity(fmt.Sprintf(
					"Scan finished for %s: %s checked, %s DNS hosts, %s recursive",
					op.Name,
					formatCount(result.ScannedTargets),
					formatCount(result.ReachableCount),
					formatCount(result.RecursiveCount),
				))
			}
			u.updateDefaultPaths()
			u.rebuildForm()
			u.renderAll()
		})
	}(operator, selectedEntries, cfg)
}

func (u *ui) startDNSTTTest() {
	if u.busyRunning() {
		u.blockDuringBusy("DNSTT test blocked while another task is running.")
		return
	}

	operator := u.currentTargetOperator()
	result, ok := u.scanCache[operator.Key]
	if !ok || len(result.Resolvers) == 0 {
		u.setStatus("Run a DNS scan first before testing DNSTT.")
		u.addActivity(fmt.Sprintf("DNSTT blocked for %s: no scan results", operator.Name))
		return
	}

	cfg, err := u.dnsttConfig(result.Port)
	if err != nil {
		u.setStatus(err.Error())
		u.addActivity(fmt.Sprintf("DNSTT config invalid for %s", operator.Name))
		return
	}
	e2ESkipped := false
	if strings.TrimSpace(cfg.Pubkey) != "" {
		binaryPath, findErr := dnstt.FindClientBinary()
		if findErr != nil {
			e2ESkipped = true
			cfg.Pubkey = ""
			u.addActivity(fmt.Sprintf("DNSTT e2e skipped for %s: dnstt-client not found, install it for e2e", operator.Name))
		} else {
			cfg.BinaryPath = binaryPath
		}
	}

	candidates := countDNSTTCandidates(result.Resolvers)
	if candidates == 0 {
		u.setStatus("No healthy recursive resolvers are available for DNSTT testing.")
		u.addActivity(fmt.Sprintf("DNSTT blocked for %s: no healthy resolvers", operator.Name))
		return
	}

	u.activeDNSTTOperator = operator.Key
	u.liveDNSTTProgress = dnsttProgress{Total: candidates}
	ctx, cancel := context.WithCancel(context.Background())
	u.dnsttCancel = cancel
	if e2ESkipped {
		u.setStatus(fmt.Sprintf("Testing DNSTT for %s in tunnel-only mode. Install dnstt-client for e2e.", operator.Name))
	} else {
		u.setStatus(fmt.Sprintf("Testing DNSTT for %s...", operator.Name))
	}
	u.addActivity(fmt.Sprintf(
		"DNSTT started for %s on %s healthy resolvers using %s",
		operator.Name,
		formatCount(candidates),
		displayDNSTTDomain(cfg.Domain),
	))
	u.rebuildForm()
	u.renderAll()

	go func(op model.Operator, baseResult model.ScanResult, config dnstt.Config) {
		updatedResolvers, summary, err := dnstt.Test(ctx, baseResult.Resolvers, config, func(event dnstt.Event) {
			u.app.QueueUpdateDraw(func() {
				if u.activeDNSTTOperator != op.Key {
					return
				}
				if event.Type == dnstt.EventResolver && event.Item != nil {
					cached := u.scanCache[op.Key]
					cached.Resolvers = mergeResolver(cached.Resolvers, *event.Item)
					cached.Resolvers = sortResolversForDisplay(cached.Resolvers)
					u.scanCache[op.Key] = cached
				}
				u.liveDNSTTProgress = dnsttProgress{
					Tested: event.Tested,
					Total:  event.Total,
					Tunnel: event.Tunnel,
					E2E:    event.E2E,
				}
				u.renderAll()
			})
		})

		u.app.QueueUpdateDraw(func() {
			u.dnsttCancel = nil
			u.activeDNSTTOperator = ""

			finalResult := baseResult
			finalResult.Resolvers = updatedResolvers
			finalResult.Resolvers = sortResolversForDisplay(finalResult.Resolvers)
			finalResult.DNSTTDomain = strings.TrimSpace(config.Domain)
			finalResult.DNSTTChecked = summary.Checked
			finalResult.DNSTTTunnel = summary.TunnelOK
			finalResult.DNSTTE2E = summary.E2EOK
			finalResult.DNSTTTimeoutMS = int(config.Timeout.Milliseconds())
			finalResult.DNSTTE2ETimeS = int(config.E2ETimeout.Seconds())
			finalResult.DNSTTQuerySize = config.QuerySize
			finalResult.DNSTTE2EPort = config.E2EPort
			finalResult.DNSTTE2EEnabled = strings.TrimSpace(config.Pubkey) != ""
			finalResult.DNSTTStartedAt = summary.StartedAt
			finalResult.DNSTTFinishedAt = summary.FinishedAt
			u.scanCache[op.Key] = finalResult

			if errors.Is(err, context.Canceled) {
				u.setStatus(fmt.Sprintf("DNSTT canceled for %s. Partial results are available in memory.", op.Name))
				u.addActivity(fmt.Sprintf("DNSTT canceled for %s after %s resolvers", op.Name, formatCount(summary.Checked)))
			} else if err != nil {
				u.setStatus(fmt.Sprintf("DNSTT failed for %s: %v", op.Name, err))
				u.addActivity(fmt.Sprintf("DNSTT failed for %s", op.Name))
			} else {
				if e2ESkipped {
					u.setStatus(fmt.Sprintf(
						"DNSTT finished for %s: %s tunnel-ready, e2e skipped because dnstt-client was not found.",
						op.Name,
						formatCount(summary.TunnelOK),
					))
					u.addActivity(fmt.Sprintf(
						"DNSTT finished for %s: %s checked, %s tunnel-ready, e2e skipped",
						op.Name,
						formatCount(summary.Checked),
						formatCount(summary.TunnelOK),
					))
				} else {
					u.setStatus(fmt.Sprintf(
						"DNSTT finished for %s: %s tunnel-ready, %s e2e-ready.",
						op.Name,
						formatCount(summary.TunnelOK),
						formatCount(summary.E2EOK),
					))
					u.addActivity(fmt.Sprintf(
						"DNSTT finished for %s: %s checked, %s tunnel-ready, %s e2e-ready",
						op.Name,
						formatCount(summary.Checked),
						formatCount(summary.TunnelOK),
						formatCount(summary.E2EOK),
					))
				}
			}
			u.updateDefaultPaths()
			u.rebuildForm()
			u.renderAll()
		})
	}(operator, result, cfg)
}

func (u *ui) stopScan() {
	if u.scanCancel == nil {
		u.setStatus("No active scan to stop.")
		u.addActivity("Stop ignored: no active scan")
		return
	}
	u.scanCancel()
	u.setStatus("Stopping active scan...")
	u.addActivity("Stop requested for active scan")
}

func (u *ui) stopDNSTTTest() {
	if u.dnsttCancel == nil {
		u.setStatus("No active DNSTT test to stop.")
		u.addActivity("Stop ignored: no active DNSTT test")
		return
	}
	u.dnsttCancel()
	u.setStatus("Stopping active DNSTT test...")
	u.addActivity("Stop requested for active DNSTT test")
}

func (u *ui) stopActiveOperation() {
	if u.scanRunning() {
		u.stopScan()
		return
	}
	if u.dnsttRunning() {
		u.stopDNSTTTest()
		return
	}
	u.setStatus("No active task to stop.")
	u.addActivity("Stop ignored: no active task")
}

func (u *ui) saveResolvers() {
	if u.busyRunning() {
		u.blockDuringBusy("Resolver export blocked while a task is running.")
		return
	}
	operator := u.currentTargetOperator()
	saveScope := u.effectiveScanSaveScope(operator.Key)
	savePath := u.prepareScanSaveTarget(operator)
	u.rebuildForm()
	u.renderAll()
	result, ok := u.scanCache[operator.Key]
	if !ok {
		progress, resolvers := u.currentScanState(operator.Key)
		selectedEntries, selectedErr := u.selectedScanEntries(operator.Key)
		if progress.Total == 0 && len(resolvers) == 0 {
			u.setStatus("No scan results available yet.")
			u.addActivity("Resolver save skipped: no scan results")
			return
		}
		result = model.ScanResult{
			Operator:       operator,
			Prefixes:       slices.Clone(selectedEntries),
			Resolvers:      resolvers,
			TotalTargets:   progress.Total,
			ScannedTargets: progress.Scanned,
			ReachableCount: progress.Reachable,
			RecursiveCount: progress.Recursive,
			Workers:        mustInt(u.scanWorkers, 256),
			TimeoutMillis:  mustInt(u.scanTimeoutMS, 1200),
			HostLimit:      mustUint64(u.scanHostLimit, 50000),
			Port:           mustPort(u.scanPort, 53),
			Protocol:       mustProtocol(u.scanProtocol, string(scanner.ProtocolUDP)),
			StartedAt:      time.Now(),
			FinishedAt:     time.Now(),
		}
		if selectedErr != nil {
			result.Warnings = append(result.Warnings, selectedErr.Error())
		}
	}

	format, err := export.ParseFormat(u.scanFormat)
	if err != nil {
		u.setStatus(err.Error())
		u.addActivity("Resolver save failed: invalid export format")
		return
	}

	if u.hasCompletedDNSTT(operator.Key) {
		result = filterScanResult(result, saveScope)
		if len(result.Resolvers) == 0 {
			u.setStatus(fmt.Sprintf("No matching scan results for %s.", saveScope))
			u.addActivity(fmt.Sprintf("Resolver export skipped for %s: no %s", operator.Name, saveScope))
			return
		}
		if err := export.SaveResolvers(savePath, format, result); err != nil {
			u.setStatus(fmt.Sprintf("Save failed: %v", err))
			u.addActivity(fmt.Sprintf("Resolver save failed for %s", operator.Name))
			return
		}
		u.rebuildForm()
		u.renderAll()
		u.setStatus(fmt.Sprintf("Saved resolvers to %s", savePath))
		u.addActivity(fmt.Sprintf(
			"Saved %s for %s using %s",
			formatCount(result.ReachableCount),
			operator.Name,
			saveScope,
		))
		return
	}

	filtered := filterScanResult(result, saveScope)
	if len(filtered.Resolvers) == 0 && result.ScannedTargets == 0 {
		u.setStatus("No scan results available yet.")
		u.addActivity("Resolver save skipped: no scan results")
		return
	}

	if err := export.SaveResolvers(savePath, format, filtered); err != nil {
		u.setStatus(fmt.Sprintf("Save failed: %v", err))
		u.addActivity(fmt.Sprintf("Resolver save failed for %s", operator.Name))
		return
	}

	failureResult, failureReady, err := buildScanFailureExport(result, filtered.Resolvers)
	if err != nil {
		u.setStatus(fmt.Sprintf("Failure export build failed: %v", err))
		u.addActivity(fmt.Sprintf("Failure export build failed for %s", operator.Name))
		return
	}

	statusLine := fmt.Sprintf("Saved scan success to %s", savePath)
	activityLine := fmt.Sprintf(
		"Saved %s scan successes for %s using %s",
		formatCount(filtered.ReachableCount),
		operator.Name,
		saveScope,
	)

	if failureReady {
		failurePath := pairedOutputPath(savePath, operator.Key, u.scanFailureExportPrefix(operator.Key), format, time.Now())
		if err := export.SaveFailedHosts(failurePath, format, failureResult); err != nil {
			u.setStatus(fmt.Sprintf("Failure save failed: %v", err))
			u.addActivity(fmt.Sprintf("Failure export save failed for %s", operator.Name))
			return
		}
		statusLine = fmt.Sprintf("Saved scan success to %s and failures to %s", savePath, failurePath)
		activityLine = fmt.Sprintf(
			"Saved %s scan successes and %s failures for %s",
			formatCount(filtered.ReachableCount),
			formatCount(failureResult.FailedCount),
			operator.Name,
		)
	} else if result.ScannedTargets < result.TotalTargets {
		statusLine = fmt.Sprintf("Saved scan success to %s. Failure export skipped because the scan was partial.", savePath)
		activityLine = fmt.Sprintf(
			"Saved %s scan successes for %s; failure export skipped because only %s of %s targets were scanned",
			formatCount(filtered.ReachableCount),
			operator.Name,
			formatCount(result.ScannedTargets),
			formatCount(result.TotalTargets),
		)
	}

	u.rebuildForm()
	u.renderAll()
	u.setStatus(statusLine)
	u.addActivity(activityLine)
}

func (u *ui) copyPassedResolvers() {
	if u.busyRunning() {
		u.blockDuringBusy("Copy blocked while a task is running.")
		return
	}

	operator := u.currentTargetOperator()
	result, ok := u.scanCache[operator.Key]
	if !ok || !u.hasCompletedDNSTT(operator.Key) {
		u.setStatus("Run a DNSTT test first before copying passed resolvers.")
		u.addActivity(fmt.Sprintf("Copy passed skipped for %s: no DNSTT results", operator.Name))
		return
	}

	filtered := filterScanResult(result, scanSaveDNSTTPassed)
	if len(filtered.Resolvers) == 0 {
		u.setStatus("No passed DNSTT resolvers are available to copy.")
		u.addActivity(fmt.Sprintf("Copy passed skipped for %s: no passed resolvers", operator.Name))
		return
	}

	lines := make([]string, 0, len(filtered.Resolvers))
	for _, resolver := range filtered.Resolvers {
		lines = append(lines, resolver.IP)
	}
	if err := clipboardWriter(strings.Join(lines, "\n")); err != nil {
		u.setStatus(fmt.Sprintf("Copy failed: %v", err))
		u.addActivity(fmt.Sprintf("Copy passed failed for %s", operator.Name))
		return
	}

	u.setStatus(fmt.Sprintf("Copied %s passed resolvers to the clipboard.", formatCount(uint64(len(lines)))))
	u.addActivity(fmt.Sprintf("Copied %s passed resolvers for %s", formatCount(uint64(len(lines))), operator.Name))
}

func (u *ui) scanConfig() (scanner.Config, error) {
	workers, err := strconv.Atoi(strings.TrimSpace(u.scanWorkers))
	if err != nil || workers <= 0 {
		return scanner.Config{}, fmt.Errorf("workers must be a positive integer")
	}
	timeoutMS, err := strconv.Atoi(strings.TrimSpace(u.scanTimeoutMS))
	if err != nil || timeoutMS <= 0 {
		return scanner.Config{}, fmt.Errorf("timeout must be a positive integer in milliseconds")
	}
	hostLimitText := strings.TrimSpace(u.scanHostLimit)
	hostLimit := uint64(0)
	if hostLimitText != "" {
		hostLimit, err = strconv.ParseUint(hostLimitText, 10, 64)
		if err != nil {
			return scanner.Config{}, fmt.Errorf("host limit must be a whole number")
		}
	}
	portText := strings.TrimSpace(u.scanPort)
	port := 53
	if portText != "" {
		port, err = strconv.Atoi(portText)
		if err != nil || port <= 0 || port > 65535 {
			return scanner.Config{}, fmt.Errorf("port must be an integer between 1 and 65535")
		}
	}
	protocol, err := scanner.ParseProtocol(u.scanProtocol)
	if err != nil {
		return scanner.Config{}, err
	}
	probeDomain1, err := scanner.NormalizeProbeDomain(u.scanProbeURL1)
	if err != nil {
		return scanner.Config{}, fmt.Errorf("probe url 1: %w", err)
	}
	probeDomain2, err := scanner.NormalizeProbeDomain(u.scanProbeURL2)
	if err != nil {
		return scanner.Config{}, fmt.Errorf("probe url 2: %w", err)
	}

	return scanner.Config{
		Workers:          workers,
		Timeout:          time.Duration(timeoutMS) * time.Millisecond,
		HostLimit:        hostLimit,
		Port:             port,
		Protocol:         protocol,
		StabilityDomains: []string{probeDomain1, probeDomain2},
	}, nil
}

func (u *ui) dnsttConfig(port int) (dnstt.Config, error) {
	if strings.TrimSpace(u.dnsttDomain) == "" {
		return dnstt.Config{}, fmt.Errorf("dnstt domain is required")
	}

	timeoutMS, err := strconv.Atoi(strings.TrimSpace(u.dnsttTimeoutMS))
	if err != nil || timeoutMS <= 0 {
		return dnstt.Config{}, fmt.Errorf("dnstt timeout must be a positive integer in milliseconds")
	}

	e2eTimeoutText := strings.TrimSpace(u.dnsttE2ETimeoutS)
	e2eTimeoutSeconds := 0
	if e2eTimeoutText != "" {
		e2eTimeoutSeconds, err = strconv.Atoi(e2eTimeoutText)
		if err != nil || e2eTimeoutSeconds <= 0 {
			return dnstt.Config{}, fmt.Errorf("e2e timeout must be a positive integer in seconds")
		}
	}

	querySize := 0
	querySizeText := strings.TrimSpace(u.dnsttQuerySize)
	if querySizeText != "" {
		querySize, err = strconv.Atoi(querySizeText)
		if err != nil || querySize < 0 {
			return dnstt.Config{}, fmt.Errorf("query size must be zero or greater")
		}
	}

	e2ePortText := strings.TrimSpace(u.dnsttE2EPort)
	e2ePort := 53
	if e2ePortText != "" {
		e2ePort, err = strconv.Atoi(e2ePortText)
		if err != nil || e2ePort <= 0 || e2ePort > 65535 {
			return dnstt.Config{}, fmt.Errorf("e2e port must be an integer between 1 and 65535")
		}
	}

	targetPort := port
	if targetPort <= 0 {
		targetPort = mustPort(u.scanPort, 53)
	}

	workers := mustInt(u.scanWorkers, 256)
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}

	return dnstt.Config{
		Workers:    workers,
		Timeout:    time.Duration(timeoutMS) * time.Millisecond,
		E2ETimeout: time.Duration(e2eTimeoutSeconds) * time.Second,
		Port:       targetPort,
		Domain:     strings.TrimSpace(u.dnsttDomain),
		Pubkey:     strings.TrimSpace(u.dnsttPubkey),
		QuerySize:  querySize,
		E2EPort:    e2ePort,
	}, nil
}

func (u *ui) updateDefaultPaths() {
	operatorKey := u.currentOperatorKey()
	suggested := defaultOutputPath(operatorKey, u.targetExportPrefix(operatorKey), export.FormatTXT)
	if strings.TrimSpace(u.prefixPath) == "" || u.prefixPath == u.prefixSuggestedPath {
		u.prefixPath = suggested
	}
	u.prefixSuggestedPath = suggested
	scanFormat, err := export.ParseFormat(u.scanFormat)
	if err == nil {
		suggested := defaultOutputPath(operatorKey, u.scanExportPrefix(operatorKey), scanFormat)
		if strings.TrimSpace(u.scanPath) == "" || u.scanPath == u.scanSuggestedPath {
			u.scanPath = suggested
		}
		u.scanSuggestedPath = suggested
	}
}

func (u *ui) preparePrefixSaveTarget(operator model.Operator) string {
	if strings.TrimSpace(u.prefixPath) == "" || u.prefixPath == u.prefixSuggestedPath {
		u.prefixPath = defaultOutputPath(operator.Key, u.targetExportPrefix(operator.Key), export.FormatTXT)
		u.prefixSuggestedPath = u.prefixPath
	}
	return strings.TrimSpace(u.prefixPath)
}

func (u *ui) prepareScanSaveTarget(operator model.Operator) string {
	if strings.TrimSpace(u.scanPath) == "" || u.scanPath == u.scanSuggestedPath {
		format, err := export.ParseFormat(u.scanFormat)
		if err == nil {
			u.scanPath = defaultOutputPath(operator.Key, u.scanExportPrefix(operator.Key), format)
			u.scanSuggestedPath = u.scanPath
		}
	}
	return strings.TrimSpace(u.scanPath)
}

func (u *ui) hasFetchedPrefixes(operatorKey string) bool {
	result, ok := u.lookupCache[operatorKey]
	return ok && len(result.Entries) > 0
}

func (u *ui) hasCompletedScan(operatorKey string) bool {
	result, ok := u.scanCache[operatorKey]
	if !ok {
		return false
	}
	return result.ScannedTargets > 0 || len(result.Resolvers) > 0 || !result.FinishedAt.IsZero()
}

func (u *ui) hasCompletedDNSTT(operatorKey string) bool {
	result, ok := u.scanCache[operatorKey]
	if !ok {
		return false
	}
	return result.DNSTTChecked > 0 || result.DNSTTTunnel > 0 || result.DNSTTE2E > 0 || !result.DNSTTFinishedAt.IsZero()
}

func (u *ui) hasDNSTTCandidates(operatorKey string) bool {
	result, ok := u.scanCache[operatorKey]
	if !ok {
		return false
	}
	return countDNSTTCandidates(result.Resolvers) > 0
}

func (u *ui) effectiveScanSaveScope(operatorKey string) scanSaveScope {
	if u.hasCompletedDNSTT(operatorKey) {
		return scanSaveDNSTTPassed
	}
	return u.scanSaveScope
}

func (u *ui) ensureScanRangeSelection(operatorKey string) {
	lookup, ok := u.lookupCache[operatorKey]
	if !ok || len(lookup.Entries) == 0 {
		delete(u.scanRanges, operatorKey)
		return
	}

	if _, ok := u.scanRanges[operatorKey]; !ok {
		u.selectAllScanRanges(operatorKey)
		return
	}

	available := make(map[string]struct{}, len(lookup.Entries))
	filtered := make([]string, 0, len(lookup.Entries))
	for _, entry := range lookup.Entries {
		available[entry.Prefix] = struct{}{}
	}
	for _, prefix := range u.scanRanges[operatorKey] {
		if _, ok := available[prefix]; ok {
			filtered = append(filtered, prefix)
		}
	}
	u.scanRanges[operatorKey] = filtered
}

func (u *ui) selectAllScanRanges(operatorKey string) {
	lookup, ok := u.lookupCache[operatorKey]
	if !ok || len(lookup.Entries) == 0 {
		delete(u.scanRanges, operatorKey)
		return
	}
	selected := make([]string, 0, len(lookup.Entries))
	for _, entry := range lookup.Entries {
		selected = append(selected, entry.Prefix)
	}
	u.scanRanges[operatorKey] = selected
}

func (u *ui) clearScanRangeSelection(operatorKey string) {
	if _, ok := u.lookupCache[operatorKey]; !ok {
		delete(u.scanRanges, operatorKey)
		return
	}
	u.scanRanges[operatorKey] = []string{}
}

func (u *ui) selectedScanPrefixes(operatorKey string) []string {
	u.ensureScanRangeSelection(operatorKey)
	if selected, ok := u.scanRanges[operatorKey]; ok {
		return slices.Clone(selected)
	}
	return nil
}

func (u *ui) selectedScanSummary(operatorKey string) string {
	selected := u.selectedScanPrefixes(operatorKey)
	switch len(selected) {
	case 0:
		return "No targets selected"
	case 1:
		if entry, ok := u.lookupEntry(operatorKey, selected[0]); ok {
			return displayTargetEntry(entry, u.lookupUsesCustomTargets(operatorKey))
		}
		return selected[0]
	default:
		return fmt.Sprintf("%d targets selected", len(selected))
	}
}

func (u *ui) selectedScanEntries(operatorKey string) ([]model.PrefixEntry, error) {
	lookup, ok := u.lookupCache[operatorKey]
	if !ok || len(lookup.Entries) == 0 {
		return nil, fmt.Errorf("load targets first before starting a scan")
	}
	u.ensureScanRangeSelection(operatorKey)
	if len(u.scanRanges[operatorKey]) == 0 {
		return nil, fmt.Errorf("select at least one target before starting a scan")
	}
	selected := make(map[string]struct{}, len(u.scanRanges[operatorKey]))
	for _, prefix := range u.scanRanges[operatorKey] {
		selected[prefix] = struct{}{}
	}
	entries := make([]model.PrefixEntry, 0, len(selected))
	for _, entry := range lookup.Entries {
		if _, ok := selected[entry.Prefix]; ok {
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("selected scan targets are no longer available")
	}
	return entries, nil
}

func (u *ui) scanRunning() bool {
	return u.scanCancel != nil
}

func (u *ui) dnsttRunning() bool {
	return u.dnsttCancel != nil
}

func (u *ui) busyRunning() bool {
	return u.scanRunning() || u.dnsttRunning()
}

func (u *ui) restoreSelectedOperator() {
	if u.operatorList == nil {
		return
	}
	u.lockSelection = true
	u.operatorList.SetCurrentItem(u.listIndexForOperatorSelection())
	u.lockSelection = false
}

func (u *ui) blockDuringBusy(message string) {
	u.setStatus(message)
	u.addActivity("Operation blocked: task active")
}

func (u *ui) confirmExit() {
	message := "Close the application?"
	if u.scanCancel != nil {
		message = "A scan is running. Exit and stop it?"
	} else if u.dnsttCancel != nil {
		message = "A DNSTT test is running. Exit and stop it?"
	}
	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"Exit", "Stay"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			u.pages.RemovePage("confirm-exit")
			if buttonLabel == "Exit" {
				if u.scanCancel != nil {
					u.scanCancel()
				}
				if u.dnsttCancel != nil {
					u.dnsttCancel()
				}
				u.app.Stop()
			}
		})
	u.pages.AddPage("confirm-exit", modal, true, true)
}

func (u *ui) setStatus(message string) {
	u.lastStatusLine = message
	u.renderStatus()
}

func (u *ui) renderStatus() {
	modeLabel := "target mode"
	if u.mode == screenScanner {
		modeLabel = "dns mode"
	} else if u.mode == screenDNSTT {
		modeLabel = "dnstt mode"
	}
	line1 := fmt.Sprintf("%s (%s)", u.lastStatusLine, modeLabel)
	line2 := "Enter loads from the list. Tab cycles focus. Mouse works on the list and form."
	if u.scanRunning() {
		progress, resolvers := u.currentScanState(u.activeScanOperator)
		line2 = fmt.Sprintf(
			"Scan %s: %s %s  scanned %s/%s  reachable %s  recursive %s  stable %s",
			u.operatorName(u.activeScanOperator),
			meterBar(progress.Scanned, progress.Total, 16),
			percent(progress.Scanned, progress.Total),
			formatCount(progress.Scanned),
			formatCount(progress.Total),
			formatCount(progress.Reachable),
			formatCount(progress.Recursive),
			formatCount(countStableResolvers(resolvers)),
		)
	} else if u.dnsttRunning() {
		progress := u.currentDNSTTState(u.activeDNSTTOperator)
		line2 = fmt.Sprintf(
			"DNSTT %s: %s %s  tested %s/%s  tunnel %s  e2e %s",
			u.operatorName(u.activeDNSTTOperator),
			meterBar(progress.Tested, progress.Total, 16),
			percent(progress.Tested, progress.Total),
			formatCount(progress.Tested),
			formatCount(progress.Total),
			formatCount(progress.Tunnel),
			formatCount(progress.E2E),
		)
	}
	u.status.SetText(fmt.Sprintf("%s\n%s", line1, line2))
}

func (u *ui) addActivity(message string) {
	timestamp := time.Now().Format("15:04:05")
	entry := fmt.Sprintf("[%s] %s", timestamp, message)
	u.activityLines = append(u.activityLines, entry)
	if len(u.activityLines) > 20 {
		u.activityLines = u.activityLines[len(u.activityLines)-20:]
	}
	u.renderActivity()
}

func (u *ui) renderActivity() {
	if len(u.activityLines) == 0 {
		u.activity.SetText("No activity yet.")
		return
	}

	start := 0
	if len(u.activityLines) > activityRenderLimit {
		start = len(u.activityLines) - activityRenderLimit
	}

	visible := make([]string, 0, len(u.activityLines)-start)
	for i := len(u.activityLines) - 1; i >= start; i-- {
		visible = append(visible, u.activityLines[i])
	}

	var builder strings.Builder
	builder.WriteString("[gray]Latest first[-]\n")
	fmt.Fprintf(&builder, "[darkgray]%s[-]\n", uiSeparatorLine)
	builder.WriteString(strings.Join(visible, fmt.Sprintf("\n[darkgray]%s[-]\n", uiSeparatorLine)))
	if start > 0 {
		fmt.Fprintf(&builder, "\n[darkgray]%s[-]\n[gray]... %d older event(s)[-]", uiSeparatorLine, start)
	}
	u.activity.SetText(builder.String())
}

func (u *ui) writeStageWorkflow(builder *strings.Builder, operatorKey string, lookup model.LookupResult, lookupLoaded bool, scanState scanProgress, dnsttState dnsttProgress, scanActive bool, dnsttActive bool, stableCount uint64) {
	builder.WriteString("Step Progress\n")
	builder.WriteString(uiSeparatorLine)
	builder.WriteString("\n")

	loadCurrent := uint64(0)
	loadTotal := uint64(1)
	loadStatus := "waiting for targets"
	if lookupLoaded {
		loadCurrent = 1
		loadStatus = fmt.Sprintf("%s ready, %s", lookup.SourceLabel, u.selectedScanSummary(operatorKey))
	}
	writeWorkflowLine(builder, "1. Load Targets", loadCurrent, loadTotal, loadStatus)

	scanCurrent := uint64(0)
	scanTotal := uint64(1)
	scanStatus := "waiting to start"
	if scanActive {
		scanCurrent = scanState.Scanned
		scanTotal = maxProgressTotal(scanState.Total)
		scanStatus = fmt.Sprintf("running: reachable %s, recursive %s, stable %s",
			formatCount(scanState.Reachable),
			formatCount(scanState.Recursive),
			formatCount(stableCount),
		)
	} else if u.hasCompletedScan(operatorKey) {
		scanCurrent = scanState.Scanned
		scanTotal = maxProgressTotal(scanState.Total)
		scanStatus = fmt.Sprintf("done: %s DNS hosts, %s recursive, %s stable",
			formatCount(scanState.Reachable),
			formatCount(scanState.Recursive),
			formatCount(stableCount),
		)
	}
	writeWorkflowLine(builder, "2. DNS Scan", scanCurrent, scanTotal, scanStatus)

	dnsttCurrent := uint64(0)
	dnsttTotal := uint64(1)
	dnsttStatus := "locked until scan completes"
	if !u.hasCompletedScan(operatorKey) && !scanActive {
		dnsttStatus = "locked until scan completes"
	} else if dnsttActive {
		dnsttCurrent = dnsttState.Tested
		dnsttTotal = maxProgressTotal(dnsttState.Total)
		dnsttStatus = fmt.Sprintf("running: tunnel %s, e2e %s",
			formatCount(dnsttState.Tunnel),
			formatCount(dnsttState.E2E),
		)
	} else if u.hasCompletedDNSTT(operatorKey) {
		dnsttCurrent = dnsttState.Tested
		dnsttTotal = maxProgressTotal(dnsttState.Total)
		if result, ok := u.scanCache[operatorKey]; ok && result.DNSTTE2EEnabled {
			dnsttStatus = fmt.Sprintf("done: tunnel %s, e2e %s",
				formatCount(dnsttState.Tunnel),
				formatCount(dnsttState.E2E),
			)
		} else {
			dnsttStatus = fmt.Sprintf("done: tunnel %s passed", formatCount(dnsttState.Tunnel))
		}
	} else if u.hasDNSTTCandidates(operatorKey) {
		if u.dnsttE2ERequested() {
			dnsttStatus = "ready: open setup and start"
		} else {
			dnsttStatus = "ready: open setup"
		}
	} else {
		dnsttStatus = "no healthy recursive resolvers yet"
	}
	writeWorkflowLine(builder, "3. DNSTT E2E", dnsttCurrent, dnsttTotal, dnsttStatus)
	builder.WriteString("\n")
}

func writeDetailSectionHeader(builder *strings.Builder, title string) {
	builder.WriteString(title)
	builder.WriteString("\n")
	builder.WriteString(uiSeparatorLine)
	builder.WriteString("\n")
}

func writeWorkflowLine(builder *strings.Builder, label string, current, total uint64, status string) {
	if total == 0 {
		total = 1
	}
	if current > total {
		current = total
	}
	fmt.Fprintf(builder, "%-16s  %s %s  %s\n",
		label,
		meterBar(current, total, workflowBarWidth),
		percent(current, total),
		status,
	)
}

func maxProgressTotal(total uint64) uint64 {
	if total == 0 {
		return 1
	}
	return total
}

func selectedTargetPreview(entries []model.PrefixEntry, customTargets bool, limit int) string {
	if len(entries) == 0 {
		return "none"
	}
	if limit <= 0 {
		limit = 1
	}

	previewCount := len(entries)
	if previewCount > limit {
		previewCount = limit
	}
	parts := make([]string, 0, previewCount+1)
	for i := 0; i < previewCount; i++ {
		parts = append(parts, displayTargetEntry(entries[i], customTargets))
	}
	if len(entries) > previewCount {
		parts = append(parts, fmt.Sprintf("+%d more", len(entries)-previewCount))
	}
	return strings.Join(parts, ", ")
}

func firstSelectedPrefix(prefixes []string) string {
	if len(prefixes) == 0 {
		return ""
	}
	return prefixes[0]
}

func firstVisiblePrefix(entries []model.PrefixEntry, visibleIndices []int) string {
	if len(visibleIndices) == 0 {
		return ""
	}
	index := visibleIndices[0]
	if index < 0 || index >= len(entries) {
		return ""
	}
	return entries[index].Prefix
}

func displayOperatorASNs(operator model.Operator) string {
	if len(operator.ASNs) == 0 {
		return "manual targets"
	}
	return strings.Join(operator.ASNs, ", ")
}

func wrapFormValue(value string, width int) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	if width <= 0 {
		return []string{trimmed}
	}

	var lines []string
	for _, paragraph := range strings.Split(trimmed, "\n") {
		paragraph = strings.TrimSpace(paragraph)
		if paragraph == "" {
			lines = append(lines, "")
			continue
		}

		words := strings.Fields(paragraph)
		current := ""
		for _, word := range words {
			if current == "" {
				for len([]rune(word)) > width {
					runes := []rune(word)
					lines = append(lines, string(runes[:width]))
					word = string(runes[width:])
				}
				current = word
				continue
			}

			candidate := current + " " + word
			if len([]rune(candidate)) <= width {
				current = candidate
				continue
			}

			lines = append(lines, current)
			for len([]rune(word)) > width {
				runes := []rune(word)
				lines = append(lines, string(runes[:width]))
				word = string(runes[width:])
			}
			current = word
		}

		if current != "" {
			lines = append(lines, current)
		}
	}

	return lines
}

func formatCount(value uint64) string {
	if value < 1000 {
		return fmt.Sprintf("%d", value)
	}
	text := fmt.Sprintf("%d", value)
	parts := make([]string, 0, len(text)/3+1)
	for len(text) > 3 {
		parts = append([]string{text[len(text)-3:]}, parts...)
		text = text[:len(text)-3]
	}
	parts = append([]string{text}, parts...)
	return strings.Join(parts, ",")
}

func countStableResolvers(resolvers []model.Resolver) uint64 {
	var count uint64
	for _, resolver := range resolvers {
		if resolver.Stable {
			count++
		}
	}
	return count
}

func countDNSTTCandidates(resolvers []model.Resolver) uint64 {
	var count uint64
	for _, resolver := range resolvers {
		if resolver.RecursionAvailable && resolver.Stable {
			count++
		}
	}
	return count
}

func totalPrefixAddresses(entries []model.PrefixEntry) uint64 {
	var total uint64
	for _, entry := range entries {
		total += entry.TotalAddresses
	}
	return total
}

func filterPrefixEntryIndexes(entries []model.PrefixEntry, query string) []int {
	query = strings.ToLower(strings.TrimSpace(query))
	indexes := make([]int, 0, len(entries))
	for index, entry := range entries {
		if query != "" && !strings.Contains(strings.ToLower(entry.Prefix), query) {
			continue
		}
		indexes = append(indexes, index)
	}
	return indexes
}

func scanRangeLabel(entry model.PrefixEntry, imported bool, selected bool) string {
	label := fmt.Sprintf("%12s %-3s  %s", formatCount(entry.TotalAddresses), targetCountUnit(entry.TotalAddresses), displayTargetEntry(entry, imported))
	if selected {
		return fmt.Sprintf("[black:lightskyblue]%s[-:-:-]", label)
	}
	return label
}

func displayProbeURL(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return "-"
	}
	return text
}

func displayScanPort(value string) string {
	port := mustPort(value, 53)
	return strconv.Itoa(port)
}

func displayResultPort(value int) int {
	if value <= 0 {
		return 53
	}
	return value
}

func displayScanProtocol(value string) string {
	return mustProtocol(value, string(scanner.ProtocolUDP))
}

func displayTransport(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return "-"
	}
	return text
}

func (u *ui) dnsttClientPath() (string, bool) {
	path, err := dnstt.FindClientBinary()
	if err != nil {
		return "", false
	}
	return path, true
}

func (u *ui) dnsttClientFieldValue() string {
	if path, ok := u.dnsttClientPath(); ok {
		return filepath.Base(path)
	}
	if strings.TrimSpace(u.dnsttPubkey) == "" {
		return "optional"
	}
	return "missing - install for e2e"
}

func (u *ui) dnsttClientWarning() string {
	if strings.TrimSpace(u.dnsttPubkey) == "" {
		return ""
	}
	if _, ok := u.dnsttClientPath(); ok {
		return ""
	}
	return "Install with `go install www.bamsoftware.com/git/dnstt.git/dnstt-client@latest`, or place `dnstt-client` next to `range-scout`."
}

func (u *ui) dnsttE2ERequested() bool {
	return strings.TrimSpace(u.dnsttPubkey) != ""
}

func (u *ui) dnsttE2EStageLabel() string {
	if u.dnsttE2ERequested() {
		return "Ready with current Pubkey"
	}
	return "Optional when Pubkey is set"
}

func displayDNSTTDomain(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return "-"
	}
	return text
}

func displayDNSTTPubkey(value string) string {
	if strings.TrimSpace(value) == "" {
		return "tunnel-only"
	}
	return "set"
}

func displayDNSTTQuerySize(value string) string {
	text := strings.TrimSpace(value)
	if text == "" || text == "0" {
		return "default"
	}
	return text
}

func displayDNSTTTimeout(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return "3000"
	}
	return text
}

func displayDNSTTE2ETimeout(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return "20"
	}
	return text
}

func displayDNSTTE2EPort(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return "53 (resolver IP)"
	}
	return text + " (resolver IP)"
}

func dnsttStatusLabel(resolver model.Resolver) string {
	switch {
	case resolver.DNSTTE2EOK:
		return "e2e"
	case resolver.DNSTTTunnelOK:
		return "tunnel"
	case resolver.DNSTTChecked:
		return "failed"
	default:
		return "-"
	}
}

func showDNSTTError(resolver model.Resolver) bool {
	return resolver.DNSTTChecked && !resolver.DNSTTE2EOK && strings.TrimSpace(resolver.DNSTTError) != ""
}

func displayDNSTTError(value string) string {
	text := strings.TrimSpace(value)
	if len(text) <= 120 {
		return text
	}
	return text[:120] + "..."
}

func mergeResolver(resolvers []model.Resolver, updated model.Resolver) []model.Resolver {
	merged := slices.Clone(resolvers)
	for index, resolver := range merged {
		if resolver.IP == updated.IP {
			merged[index] = updated
			return merged
		}
	}
	return append(merged, updated)
}

func sortResolversForDisplay(resolvers []model.Resolver) []model.Resolver {
	sorted := slices.Clone(resolvers)
	slices.SortStableFunc(sorted, func(left, right model.Resolver) int {
		switch {
		case left.DNSTTE2EOK != right.DNSTTE2EOK:
			if left.DNSTTE2EOK {
				return -1
			}
			return 1
		case left.DNSTTTunnelOK != right.DNSTTTunnelOK:
			if left.DNSTTTunnelOK {
				return -1
			}
			return 1
		case left.Stable != right.Stable:
			if left.Stable {
				return -1
			}
			return 1
		case left.RecursionAvailable != right.RecursionAvailable:
			if left.RecursionAvailable {
				return -1
			}
			return 1
		case left.RecursionAdvertised != right.RecursionAdvertised:
			if left.RecursionAdvertised {
				return -1
			}
			return 1
		case left.LatencyMillis != right.LatencyMillis:
			if left.LatencyMillis < right.LatencyMillis {
				return -1
			}
			return 1
		case left.IP < right.IP:
			return -1
		case left.IP > right.IP:
			return 1
		default:
			return 0
		}
	})
	return sorted
}

func countImportLines(text string) int {
	count := 0
	for _, line := range strings.Split(text, "\n") {
		if normalizeImportPreviewLine(line) == "" {
			continue
		}
		count++
	}
	return count
}

func normalizeImportPreviewLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if hashIndex := strings.Index(line, "#"); hashIndex >= 0 {
		line = strings.TrimSpace(line[:hashIndex])
	}
	return line
}

func writeScanOptionGuide(builder *strings.Builder) {
	builder.WriteString("Commands - DNS Scan\n")
	builder.WriteString("  - Targets: CIDRs or file-imported / pasted single IPs selected for this scan. Use Pick Targets to change them.\n")
	builder.WriteString("  - Workers: number of concurrent DNS probes. Higher is faster but heavier.\n")
	builder.WriteString("  - Timeout: per-request timeout in milliseconds.\n")
	builder.WriteString("  - Host Limit: maximum number of hosts to scan. Leave empty or 0 for the full selection.\n")
	builder.WriteString("  - Port: DNS port to test. Default is 53.\n")
	builder.WriteString("  - Protocol: UDP, TCP, or BOTH. BOTH tries UDP first, then TCP.\n")
	builder.WriteString("  - Probe URLs: two hostnames used to confirm stable recursive resolution. Make sure each probe is accessible through your network.\n")
	builder.WriteString("  - Start Scan is unlocked after targets are loaded.\n")
	builder.WriteString("  - Test DNSTT unlocks only after a completed scan and opens a dedicated DNSTT setup screen.\n")
	builder.WriteString("  - The DNSTT stage checks only healthy recursive resolvers and uses the Pubkey, resolver IP, and E2E Port for the final SOCKS5 check.\n")
	builder.WriteString("  - DNSTT Client is looked up in PATH, current directory, or next to range-scout. It is required for e2e when Pubkey is set.\n")
	builder.WriteString("  - Export is available after the scan. After DNSTT runs, the DNSTT screen exports only DNSTT-passed resolvers.\n\n")
}

func percent(scanned, total uint64) string {
	if total == 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", float64(scanned)*100/float64(total))
}

func meterBar(scanned, total uint64, width int) string {
	if width <= 0 {
		return ""
	}
	if total == 0 {
		return "[" + strings.Repeat("-", width) + "]"
	}
	filled := int((scanned * uint64(width)) / total)
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", width-filled) + "]"
}

func defaultOutputPath(operatorKey, suffix string, format export.Format) string {
	return defaultOutputPathAt(operatorKey, suffix, format, time.Now())
}

func defaultOutputPathAt(operatorKey, suffix string, format export.Format, ts time.Time) string {
	if strings.TrimSpace(operatorKey) == "" {
		operatorKey = "custom"
	}
	return fmt.Sprintf(
		"exports/%s-%s_%s_%06d.%s",
		suffix,
		operatorKey,
		ts.Format("20060102_150405"),
		ts.Nanosecond()/1000,
		format.Extension(),
	)
}

func pairedOutputPath(basePath, operatorKey, suffix string, format export.Format, ts time.Time) string {
	dir := filepath.Dir(strings.TrimSpace(basePath))
	if dir == "." || dir == "" {
		return defaultOutputPathAt(operatorKey, suffix, format, ts)
	}
	return filepath.Join(dir, filepath.Base(defaultOutputPathAt(operatorKey, suffix, format, ts)))
}

func filterScanResult(result model.ScanResult, scope scanSaveScope) model.ScanResult {
	if scope == scanSaveDNSTTPassed {
		filtered := make([]model.Resolver, 0, len(result.Resolvers))
		for _, resolver := range result.Resolvers {
			if dnsttExportPassed(result, resolver) {
				filtered = append(filtered, resolver)
			}
		}
		result.Resolvers = filtered
		result.ReachableCount = uint64(len(filtered))
		result.RecursiveCount = uint64(len(filtered))
		return result
	}

	if scope != scanSaveRecursiveOnly {
		result.ReachableCount = uint64(len(result.Resolvers))
		recursiveCount := uint64(0)
		for _, resolver := range result.Resolvers {
			if resolver.RecursionAvailable {
				recursiveCount++
			}
		}
		result.RecursiveCount = recursiveCount
		return result
	}

	filtered := make([]model.Resolver, 0, len(result.Resolvers))
	for _, resolver := range result.Resolvers {
		if resolver.RecursionAvailable {
			filtered = append(filtered, resolver)
		}
	}
	result.Resolvers = filtered
	result.ReachableCount = uint64(len(filtered))
	result.RecursiveCount = uint64(len(filtered))
	return result
}

func buildScanFailureExport(result model.ScanResult, successfulResolvers []model.Resolver) (export.FailedHostResult, bool, error) {
	exportResult := export.FailedHostResult{
		Operator:       result.Operator,
		TotalTargets:   result.TotalTargets,
		ScannedTargets: result.ScannedTargets,
	}
	if result.TotalTargets == 0 || len(result.Prefixes) == 0 {
		return exportResult, false, nil
	}
	if result.ScannedTargets < result.TotalTargets {
		return exportResult, false, nil
	}

	successful := make(map[string]struct{}, len(successfulResolvers))
	for _, resolver := range successfulResolvers {
		successful[resolver.IP] = struct{}{}
	}

	failedHosts := make([]export.FailedHost, 0)
	_, err := prefixes.WalkHosts(result.Prefixes, result.HostLimit, func(addr netip.Addr, prefix string) bool {
		if _, ok := successful[addr.String()]; ok {
			return true
		}
		failedHosts = append(failedHosts, export.FailedHost{
			IP:     addr.String(),
			Prefix: prefix,
		})
		return true
	})
	if err != nil {
		return exportResult, false, err
	}

	exportResult.FailedHosts = failedHosts
	exportResult.FailedCount = uint64(len(failedHosts))
	return exportResult, true, nil
}

func dnsttExportPassed(result model.ScanResult, resolver model.Resolver) bool {
	if result.DNSTTE2EEnabled {
		return resolver.DNSTTE2EOK
	}
	return resolver.DNSTTTunnelOK
}

func writeClipboardText(text string) error {
	switch runtime.GOOS {
	case "darwin":
		return runClipboardCommand("pbcopy", nil, text)
	case "windows":
		return runClipboardCommand("cmd", []string{"/c", "clip"}, text)
	default:
		for _, candidate := range []struct {
			name string
			args []string
		}{
			{name: "wl-copy"},
			{name: "xclip", args: []string{"-selection", "clipboard"}},
			{name: "xsel", args: []string{"--clipboard", "--input"}},
		} {
			if _, err := exec.LookPath(candidate.name); err != nil {
				continue
			}
			return runClipboardCommand(candidate.name, candidate.args, text)
		}
		return fmt.Errorf("no clipboard command found (wl-copy, xclip, xsel)")
	}
}

func runClipboardCommand(name string, args []string, text string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s not found in PATH", name)
	}

	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(text)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	message := strings.TrimSpace(string(output))
	if message == "" {
		return err
	}
	return fmt.Errorf("%v: %s", err, message)
}

func mustInt(text string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func mustUint64(text string, fallback uint64) uint64 {
	value, err := strconv.ParseUint(strings.TrimSpace(text), 10, 64)
	if err != nil {
		return fallback
	}
	return value
}

func mustPort(text string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || value <= 0 || value > 65535 {
		return fallback
	}
	return value
}

func mustProtocol(text, fallback string) string {
	value, err := scanner.ParseProtocol(text)
	if err != nil {
		return fallback
	}
	return string(value)
}

func parseCustomTargets(operator model.Operator, sourceLabel, sourcePath, text string) (model.LookupResult, error) {
	entries, totalAddresses, totalScanHosts, warnings, err := prefixes.ParseTXTTargets(text)
	result := model.LookupResult{
		Operator:       operator,
		Entries:        entries,
		TotalAddresses: totalAddresses,
		TotalScanHosts: totalScanHosts,
		FetchedAt:      time.Now(),
		Warnings:       warnings,
		SourceLabel:    sourceLabel,
		SourcePath:     sourcePath,
	}
	return result, err
}

func (u *ui) selectedTargetSource(operatorKey string) targetSourceMode {
	if mode, ok := u.targetSources[operatorKey]; ok && mode != "" {
		return mode
	}
	if strings.TrimSpace(operatorKey) == "" || operatorKey == customOperatorKey {
		return targetSourcePaste
	}
	return targetSourceRIPE
}

func (u *ui) setSelectedTargetSource(operatorKey string, mode targetSourceMode) {
	if mode == "" {
		delete(u.targetSources, operatorKey)
		return
	}
	u.targetSources[operatorKey] = mode
}

func (u *ui) importPath(operatorKey string) string {
	return u.importPaths[operatorKey]
}

func (u *ui) setImportPath(operatorKey, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		delete(u.importPaths, operatorKey)
		return
	}
	u.importPaths[operatorKey] = trimmed
}

func (u *ui) pasteBuffer(operatorKey string) string {
	return u.pasteBuffers[operatorKey]
}

func (u *ui) setPasteBuffer(operatorKey, value string) {
	if strings.TrimSpace(value) == "" {
		delete(u.pasteBuffers, operatorKey)
		return
	}
	u.pasteBuffers[operatorKey] = value
}

func (u *ui) pasteStatus(operatorKey string) string {
	return u.pasteStatusFromText(u.pasteBuffer(operatorKey))
}

func (u *ui) pasteStatusFromText(text string) string {
	lines := countImportLines(text)
	switch lines {
	case 0:
		return "No pasted targets yet"
	case 1:
		return "1 line ready"
	default:
		return fmt.Sprintf("%d lines ready", lines)
	}
}

func (u *ui) targetExportPrefix(operatorKey string) string {
	return "cidr"
}

func (u *ui) scanExportPrefix(operatorKey string) string {
	if u.hasCompletedDNSTT(operatorKey) {
		return "dnstt-scan-success"
	}
	return "dns-scan-success"
}

func (u *ui) scanFailureExportPrefix(operatorKey string) string {
	return "dns-scan-failures"
}

func (u *ui) lookupUsesCustomTargets(operatorKey string) bool {
	lookup, ok := u.lookupCache[operatorKey]
	return ok && lookupUsesCustomTargets(lookup)
}

func (u *ui) lookupEntry(operatorKey, prefix string) (model.PrefixEntry, bool) {
	lookup, ok := u.lookupCache[operatorKey]
	if !ok {
		return model.PrefixEntry{}, false
	}
	for _, entry := range lookup.Entries {
		if entry.Prefix == prefix {
			return entry, true
		}
	}
	return model.PrefixEntry{}, false
}

func primaryLoadButtonLabel(mode targetSourceMode) string {
	if mode == targetSourceImportTXT {
		return "Import TXT"
	}
	if mode == targetSourcePaste {
		return "Paste Targets"
	}
	return "Load Targets"
}

func targetSourceOptions(hasOperator bool) []targetSourceMode {
	if hasOperator {
		return []targetSourceMode{targetSourceRIPE, targetSourceImportTXT, targetSourcePaste}
	}
	return []targetSourceMode{targetSourceImportTXT, targetSourcePaste}
}

func lookupUsesCustomTargets(result model.LookupResult) bool {
	if strings.TrimSpace(result.SourcePath) != "" {
		return true
	}
	switch result.SourceLabel {
	case string(targetSourceImportTXT), string(targetSourcePaste):
		return true
	default:
		return false
	}
}

func displayTargetEntry(entry model.PrefixEntry, imported bool) string {
	if !imported {
		return entry.Prefix
	}
	if addr, ok := singleIPFromPrefix(entry.Prefix); ok {
		return addr
	}
	return entry.Prefix
}

func singleIPFromPrefix(prefix string) (string, bool) {
	parsed, err := netip.ParsePrefix(prefix)
	if err != nil {
		return "", false
	}
	if !parsed.Addr().Is4() || parsed.Bits() != 32 {
		return "", false
	}
	return parsed.Addr().String(), true
}

func targetCountLabel(value uint64) string {
	return fmt.Sprintf("%s %s", formatCount(value), targetCountUnit(value))
}

func targetCountUnit(value uint64) string {
	if value == 1 {
		return "IP"
	}
	return "IPs"
}

func (u *ui) operatorName(key string) string {
	if key == customOperatorKey {
		return customOperatorName
	}
	for _, operator := range u.operators {
		if operator.Key == key {
			return operator.Name
		}
	}
	return key
}
