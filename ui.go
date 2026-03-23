package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unsafe"

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
type layoutMode string
type layoutMetrics struct {
	mode              layoutMode
	width             int
	height            int
	operatorWidth     int
	rightWidth        int
	activityWidth     int
	activityHeight    int
	footerHeight      int
	formNoteWidth     int
	formSidebarWidth  int
	detailsGuideWidth int
}

type scanSaveScope string
type targetSourceMode string

const (
	screenOperators screen = "operators"
	screenScanner   screen = "scanner"
	screenDNSTT     screen = "dnstt"

	layoutWide    layoutMode = "wide"
	layoutCompact layoutMode = "compact"

	scanSaveRecursiveOnly scanSaveScope = "compatible only"
	scanSaveAllDNSHosts   scanSaveScope = "all dns hosts"
	scanSaveDNSTTPassed   scanSaveScope = "dnstt passed only"

	targetSourceRIPE      targetSourceMode = "Automatic API Fetch"
	targetSourceImportTXT targetSourceMode = "Import TXT"
	targetSourcePaste     targetSourceMode = "Paste Targets"

	yesOption = "Yes"
	noOption  = "No"

	activityRenderLimit  = 6
	targetPreviewLimit   = 3
	workflowBarWidth     = 16
	formNoteWrapWidth    = 24
	formSidebarWrapWidth = 20
	uiSeparatorLine      = "────────────────────────"
	uiVersionLabel       = "v0.1.6-rc1"
	operatorPlaceholder  = "Paste or Import"
	customOperatorKey    = "custom"
	customOperatorName   = "Custom Targets"
)

var clipboardWriter = writeClipboardText
var clipboardReader = readClipboardText
var consoleScreenFactory = tcell.NewConsoleScreen
var preferredWindowsScreenFactory = createPreferredWindowsScreen

type scanProgress struct {
	Scanned    uint64
	Total      uint64
	Working    uint64
	Compatible uint64
	Qualified  uint64
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
	body         *tview.Flex
	contentPanel *tview.Flex
	rightColumn  *tview.Flex
	footerPanel  *tview.Flex
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
	scanPort            string
	scanProtocol        string
	scanRecursionURL    string
	scanProbeURL1       string
	scanProbeURL2       string
	dnsttDomain         string
	dnsttPubkey         string
	dnsttTimeoutMS      string
	dnsttE2ETimeoutS    string
	dnsttQuerySize      string
	dnsttScoreThreshold string
	dnsttE2EURL         string
	dnsttNearbyIPs      string
	configPath          string
	activityLines       []string
	lastStatusLine      string
	lockSelection       bool
	layout              layoutMode
	layoutState         layoutMetrics
}

func newUI() *ui {
	u := &ui{
		app:                 tview.NewApplication(),
		pages:               tview.NewPages(),
		header:              tview.NewTextView(),
		operatorList:        tview.NewList(),
		body:                tview.NewFlex(),
		contentPanel:        tview.NewFlex(),
		rightColumn:         tview.NewFlex().SetDirection(tview.FlexRow),
		footerPanel:         tview.NewFlex(),
		details:             tview.NewTextView(),
		commands:            tview.NewFlex().SetDirection(tview.FlexRow),
		form:                tview.NewForm(),
		buttonRows:          []*tview.Form{tview.NewForm(), tview.NewForm(), tview.NewForm()},
		activity:            tview.NewTextView(),
		status:              tview.NewTextView(),
		operators:           operators.All(),
		selected:            -1,
		mode:                screenOperators,
		client:              ripestat.NewClient(),
		lookupCache:         make(map[string]model.LookupResult),
		scanCache:           make(map[string]model.ScanResult),
		scanFormat:          export.FormatTXT.String(),
		scanSaveScope:       scanSaveRecursiveOnly,
		scanRanges:          make(map[string][]string),
		targetSources:       make(map[string]targetSourceMode),
		importPaths:         make(map[string]string),
		pasteBuffers:        make(map[string]string),
		scanWorkers:         "256",
		scanTimeoutMS:       "15000",
		scanPort:            "53",
		scanProtocol:        string(scanner.ProtocolUDP),
		scanRecursionURL:    "google.com",
		scanProbeURL1:       "github.com",
		scanProbeURL2:       "example.com",
		dnsttTimeoutMS:      "15000",
		dnsttE2ETimeoutS:    "20",
		dnsttQuerySize:      "",
		dnsttScoreThreshold: "2",
		dnsttE2EURL:         dnstt.DefaultE2ETestURL,
		dnsttNearbyIPs:      noOption,
		layout:              layoutWide,
		layoutState:         defaultLayoutMetrics(layoutWide),
	}
	configStatus := u.loadStartupConfig()

	u.configureViews()
	u.populateOperators()
	u.updateDefaultPaths()
	u.rebuildForm()
	u.addActivity("Ready")
	u.renderAll()
	if configStatus != "" {
		u.addActivity(configStatus)
		u.setStatus(configStatus)
	} else {
		u.setStatus("Ready. Select an operator for Automatic API Fetch, or use Import TXT / Paste Targets without one.")
	}

	main := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(u.header, 3, 0, false).
		AddItem(u.body, 0, 1, true).
		AddItem(u.status, 4, 0, false)

	u.applyLayout(layoutWide)
	u.pages.AddPage("main", main, true, true)
	u.app.SetRoot(u.pages, true)
	u.app.SetFocus(u.operatorList)
	u.app.SetInputCapture(u.handleKeys)
	u.app.EnableMouse(true)
	u.app.EnablePaste(true)
	u.app.SetBeforeDrawFunc(func(screen tcell.Screen) bool {
		u.refreshLayout(screen)
		return false
	})

	return u
}

func (u *ui) Run() error {
	screen := preferredScreenForRun(runtime.GOOS)
	if screen != nil {
		u.app.SetScreen(screen)
		u.applyScreenFeatures(screen)
	}

	return u.app.Run()
}

func (u *ui) applyScreenFeatures(screen tcell.Screen) {
	if screen == nil {
		return
	}
	// tview's SetScreen() initializes the screen immediately before Run(), which
	// means Run() skips its normal screen setup path. Reapply the app-level
	// features we expect on our preferred Windows screen.
	screen.EnableMouse()
	screen.EnablePaste()
}

func preferredScreenForRun(goos string) tcell.Screen {
	if goos != "windows" {
		return nil
	}
	screen, err := preferredWindowsScreenFactory()
	if err != nil {
		return nil
	}
	return screen
}

func createPreferredWindowsScreen() (tcell.Screen, error) {
	// Prefer the native Windows console backend when it can actually initialize.
	// If the probe fails, the caller falls back to tview/tcell's default backend.
	probe, err := consoleScreenFactory()
	if err != nil {
		return nil, err
	}
	if err := probe.Init(); err != nil {
		return nil, err
	}
	probe.Fini()
	return consoleScreenFactory()
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
	u.form.SetItemPadding(0)
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

func (u *ui) refreshLayout(screen tcell.Screen) {
	if screen == nil {
		return
	}
	width, height := screen.Size()
	u.applyLayoutMetrics(u.calculateLayoutMetrics(width, height))
}

func (u *ui) layoutModeForSize(width, height int) layoutMode {
	if width <= 0 || height <= 0 {
		return layoutWide
	}
	if width < 170 || height < 40 {
		return layoutCompact
	}
	return layoutWide
}

func (u *ui) applyLayout(mode layoutMode) {
	u.applyLayoutMetrics(defaultLayoutMetrics(mode))
}

func (u *ui) applyLayoutMetrics(metrics layoutMetrics) {
	if metrics.mode == "" {
		metrics = defaultLayoutMetrics(layoutWide)
	}
	if u.body == nil || u.contentPanel == nil || u.rightColumn == nil || u.footerPanel == nil {
		return
	}
	if u.layoutState == metrics && u.body.GetItemCount() > 0 {
		return
	}

	previousMetrics := u.layoutState

	u.body.Clear()
	u.contentPanel.Clear()
	u.rightColumn.Clear()
	u.footerPanel.Clear()

	switch metrics.mode {
	case layoutCompact:
		u.details.SetWrap(true)
		u.footerPanel.
			AddItem(u.details, 0, 1, false).
			AddItem(u.activity, metrics.activityWidth, 0, false)
		u.contentPanel.SetDirection(tview.FlexRow)
		u.contentPanel.
			AddItem(u.commands, 0, 1, false).
			AddItem(u.footerPanel, metrics.footerHeight, 0, false)
		u.body.
			AddItem(u.operatorList, metrics.operatorWidth, 0, true).
			AddItem(u.contentPanel, 0, 1, false)
	default:
		u.details.SetWrap(false)
		u.rightColumn.SetDirection(tview.FlexRow)
		u.rightColumn.
			AddItem(u.commands, 0, 1, false).
			AddItem(u.activity, metrics.activityHeight, 0, false)
		u.body.
			AddItem(u.operatorList, metrics.operatorWidth, 0, true).
			AddItem(u.details, 0, 1, false).
			AddItem(u.rightColumn, metrics.rightWidth, 0, false)
		metrics.mode = layoutWide
	}

	u.layout = metrics.mode
	u.layoutState = metrics
	if shouldRebuildFormForLayout(previousMetrics, metrics) {
		u.rebuildForm()
	}
	u.renderDetails()
	u.renderActivity()
}

func (u *ui) calculateLayoutMetrics(width, height int) layoutMetrics {
	mode := u.layoutModeForSize(width, height)
	if width <= 0 || height <= 0 {
		return defaultLayoutMetrics(mode)
	}

	bodyHeight := max(height-7, 12)
	metrics := layoutMetrics{
		mode:   mode,
		width:  width,
		height: height,
	}

	switch mode {
	case layoutCompact:
		metrics.operatorWidth = clampInt(width/7, 18, 24)
		contentWidth := max(width-metrics.operatorWidth-4, 48)
		metrics.activityWidth = clampInt(contentWidth/3, 24, 32)
		metrics.footerHeight = clampInt(bodyHeight/3, 9, 12)
		metrics.formNoteWidth = clampInt(contentWidth/5+18, 28, 42)
		metrics.formSidebarWidth = clampInt(contentWidth/4+8, 24, 36)
		detailsWidth := max(contentWidth-metrics.activityWidth-4, 36)
		metrics.detailsGuideWidth = clampGuideWrapWidth(detailsWidth - 3)
	default:
		metrics.operatorWidth = clampInt(width/6, 24, 30)
		metrics.rightWidth = clampInt(width/4, 42, 54)
		metrics.activityHeight = clampInt(bodyHeight/5, 7, 10)
		metrics.formNoteWidth = formNoteWrapWidth
		metrics.formSidebarWidth = formSidebarWrapWidth
		detailsWidth := max(width-metrics.operatorWidth-metrics.rightWidth-6, 48)
		metrics.detailsGuideWidth = clampGuideWrapWidth(detailsWidth - 3)
	}

	return metrics
}

func defaultLayoutMetrics(mode layoutMode) layoutMetrics {
	switch mode {
	case layoutCompact:
		return (&ui{}).calculateLayoutMetrics(160, 40)
	default:
		return (&ui{}).calculateLayoutMetrics(190, 45)
	}
}

func shouldRebuildFormForLayout(previous, current layoutMetrics) bool {
	return previous.mode != current.mode ||
		previous.formNoteWidth != current.formNoteWidth ||
		previous.formSidebarWidth != current.formSidebarWidth
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func clampGuideWrapWidth(width int) int {
	if width <= 0 {
		return 88
	}
	if width > 96 {
		return 96
	}
	if width < 48 {
		return 48
	}
	return width
}

func (u *ui) populateOperators() {
	u.operatorList.AddItem(operatorPlaceholder, "", 0, nil)
	for _, op := range u.operators {
		u.operatorList.AddItem(fmt.Sprintf("%s [%s]", op.Name, strings.Join(op.ASNs, ", ")), "", 0, nil)
	}
	u.restoreSelectedOperator()
}

func (u *ui) handleKeys(event *tcell.EventKey) *tcell.EventKey {
	if u.focusIsEditable() {
		if isClipboardPasteEvent(event) {
			if err := u.pasteClipboardIntoFocusedEditable(); err != nil {
				u.setStatus(fmt.Sprintf("Clipboard paste failed: %v", err))
				u.addActivity("Clipboard paste failed")
			}
			return nil
		}
		if event.Key() == tcell.KeyEsc {
			u.app.SetFocus(u.operatorList)
			return nil
		}
		return event
	}

	if u.pages.HasPage("range-picker") || u.pages.HasPage("paste-targets") || u.pages.HasPage("confirm-exit") {
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
	case *tview.InputField, *tview.DropDown, *tview.TextArea:
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
		case *tview.InputField, *tview.DropDown, *tview.TextArea:
			return true
		}
	}
	return false
}

func isClipboardPasteEvent(event *tcell.EventKey) bool {
	if event == nil {
		return false
	}
	if event.Key() == tcell.KeyCtrlV {
		return true
	}
	if event.Key() == tcell.KeyInsert && event.Modifiers()&tcell.ModShift != 0 {
		return true
	}
	if event.Key() == tcell.KeyRune && event.Modifiers()&tcell.ModCtrl != 0 {
		return event.Rune() == 'v' || event.Rune() == 'V'
	}
	return false
}

func configureInputFieldClipboard(field *tview.InputField) *tview.InputField {
	if textArea := inputFieldTextArea(field); textArea != nil {
		configureTextAreaClipboard(textArea)
	}
	return field
}

func configureTextAreaClipboard(textArea *tview.TextArea) *tview.TextArea {
	if textArea == nil {
		return nil
	}
	textArea.SetClipboard(func(text string) {
		_ = clipboardWriter(text)
	}, func() string {
		text, err := clipboardReader()
		if err != nil {
			return ""
		}
		return normalizeClipboardText(text)
	})
	return textArea
}

func inputFieldTextArea(field *tview.InputField) *tview.TextArea {
	if field == nil {
		return nil
	}
	value := reflect.ValueOf(field)
	if !value.IsValid() || value.IsNil() {
		return nil
	}
	textAreaField := value.Elem().FieldByName("textArea")
	if !textAreaField.IsValid() || textAreaField.IsNil() || !textAreaField.CanAddr() {
		return nil
	}
	textAreaValue := reflect.NewAt(textAreaField.Type(), unsafe.Pointer(textAreaField.UnsafeAddr())).Elem()
	textArea, _ := textAreaValue.Interface().(*tview.TextArea)
	return textArea
}

func (u *ui) pasteClipboardIntoFocusedEditable() error {
	target := u.focusedEditablePrimitive()
	if target == nil {
		return nil
	}

	text, err := clipboardReader()
	if err != nil {
		return err
	}
	text = normalizeClipboardText(text)

	handler := target.PasteHandler()
	if handler == nil {
		return nil
	}
	handler(text, func(p tview.Primitive) {
		u.app.SetFocus(p)
	})
	return nil
}

func (u *ui) focusedEditablePrimitive() tview.Primitive {
	switch primitive := u.app.GetFocus().(type) {
	case *tview.InputField, *tview.DropDown, *tview.TextArea:
		return primitive
	case *tview.Form:
		for index := 0; index < primitive.GetFormItemCount(); index++ {
			item := primitive.GetFormItem(index)
			if item == nil || !item.HasFocus() {
				continue
			}
			if editable, ok := item.(tview.Primitive); ok {
				return editable
			}
		}
	}
	return nil
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
		u.addButtonRow(2, buttonSpec{label: "Save Config", action: u.saveConfig})
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
		u.addButtonRow(2, buttonSpec{label: "Save Config", action: u.saveConfig})
	case screenScanner:
		if !hasOperator && !u.hasFetchedPrefixes(targetKey) && !u.hasCompletedScan(targetKey) && u.activeScanOperator != targetKey && u.activeDNSTTOperator != targetKey {
			u.form.SetTitle("Commands - DNS Scan")
			u.addButtonRow(2,
				buttonSpec{label: "Back", action: u.backToPrefixes},
				buttonSpec{label: "Save Config", action: u.saveConfig},
			)
			u.rebuildCommands()
			return
		}
		operatorKey := targetKey
		scanCompleted := u.hasCompletedScan(operatorKey)
		canRunDNSTT := scanCompleted && u.hasDNSTTCandidates(operatorKey)
		canExport := scanCompleted

		u.form.SetTitle("Commands - DNS Scan")
		u.ensureScanRangeSelection(operatorKey)
		u.form.AddFormItem(u.newSectionHeader("DNS Scan", "Configure and run"))
		u.form.AddFormItem(u.newReadOnlyInput("Targets", u.selectedScanSummary(operatorKey)))
		u.form.AddFormItem(u.newInput("Workers", u.scanWorkers, func(value string) { u.scanWorkers = value }))
		u.form.AddFormItem(u.newInput("Timeout", u.scanTimeoutMS, func(value string) { u.scanTimeoutMS = value }))
		u.form.AddFormItem(u.newInput("Port", u.scanPort, func(value string) { u.scanPort = value }))
		u.form.AddFormItem(u.newReadOnlyInput("Protocol", string(scanner.ProtocolUDP)))
		u.form.AddFormItem(u.newInput("DNSTT Domain", u.dnsttDomain, func(value string) { u.dnsttDomain = value }))
		u.form.AddFormItem(u.newInput("Query Size", u.dnsttQuerySize, func(value string) { u.dnsttQuerySize = value }))
		u.form.AddFormItem(u.newInput("Score Threshold", u.dnsttScoreThreshold, func(value string) { u.dnsttScoreThreshold = value }))
		u.form.AddFormItem(u.newSectionHeader("Next Step", "Open DNSTT setup after scan"))
		if scanCompleted {
			u.form.AddFormItem(u.newReadOnlyInput("DNSTT Setup", "Ready after completed scan"))
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
			buttonSpec{label: "Save Config", action: u.saveConfig},
		)
	case screenDNSTT:
		operatorKey := targetKey
		if !u.hasCompletedScan(operatorKey) && u.activeScanOperator != operatorKey {
			u.form.SetTitle("Commands - DNSTT E2E")
			u.addButtonRow(2,
				buttonSpec{label: "Back", action: u.backToScanner},
				buttonSpec{label: "Save Config", action: u.saveConfig},
			)
			u.rebuildCommands()
			return
		}
		dnsttCompleted := u.hasCompletedDNSTT(operatorKey)

		u.form.SetTitle("Commands - DNSTT E2E")
		u.form.AddFormItem(u.newInput("DNSTT Domain", u.dnsttDomain, func(value string) { u.dnsttDomain = value }))
		u.form.AddFormItem(u.newInput("DNSTT Pubkey", u.dnsttPubkey, func(value string) { u.dnsttPubkey = value }))
		u.form.AddFormItem(u.newInput("DNSTT Timeout", u.dnsttTimeoutMS, func(value string) { u.dnsttTimeoutMS = value }))
		u.form.AddFormItem(u.newInput("Query Size", u.dnsttQuerySize, func(value string) { u.dnsttQuerySize = value }))
		u.form.AddFormItem(u.newInput("Score Threshold", u.dnsttScoreThreshold, func(value string) { u.dnsttScoreThreshold = value }))
		u.form.AddFormItem(u.newYesNoDropDown("Test Nearby IPs", u.dnsttNearbyIPs, func(value string) { u.dnsttNearbyIPs = value }))
		u.form.AddFormItem(u.newInput("E2E Timeout", u.dnsttE2ETimeoutS, func(value string) { u.dnsttE2ETimeoutS = value }))
		u.form.AddFormItem(u.newInput("E2E URL", u.dnsttE2EURL, func(value string) { u.dnsttE2EURL = value }))

		u.form.AddFormItem(u.newSectionHeader("Export", ""))
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
			u.addWrappedReadOnlyInputWidth("Format", "Unlocked after DNSTT", u.formSidebarWrapWidth())
			u.addWrappedReadOnlyInputWidth("Save Scope", "Unlocked after DNSTT", u.formSidebarWrapWidth())
			u.addWrappedReadOnlyInputWidth("Path", "Unlocked after DNSTT", u.formSidebarWrapWidth())
		}

		u.addButtonRow(0, buttonSpec{label: "Start DNSTT", action: u.startDNSTTTest})
		if dnsttCompleted {
			u.addButtonRow(
				1,
				buttonSpec{label: "Export Passed", action: u.saveResolvers},
				buttonSpec{label: "Copy Passed", action: u.copyPassedResolvers},
			)
		}
		u.addButtonRow(2,
			buttonSpec{label: "Back", action: u.backToScanner},
			buttonSpec{label: "Save Config", action: u.saveConfig},
		)
	}
	u.rebuildCommands()
}

func (u *ui) newInput(label, value string, onChange func(string)) *tview.InputField {
	field := configureInputFieldClipboard(tview.NewInputField()).SetLabel(label + ": ").SetText(value)
	field.SetChangedFunc(onChange)
	return field
}

func (u *ui) addWrappedReadOnlyInput(label, value string) {
	u.addWrappedReadOnlyInputWidth(label, value, u.formNoteWrapWidth())
}

func (u *ui) addWrappedReadOnlyInputWidth(label, value string, width int) {
	lines := wrapFormValue(value, width)
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

func (u *ui) formNoteWrapWidth() int {
	if u.layoutState.formNoteWidth > 0 {
		return u.layoutState.formNoteWidth
	}
	return formNoteWrapWidth
}

func (u *ui) formSidebarWrapWidth() int {
	if u.layoutState.formSidebarWidth > 0 {
		return u.layoutState.formSidebarWidth
	}
	return formSidebarWrapWidth
}

func (u *ui) detailsGuideWrapWidth() int {
	if u.layoutState.detailsGuideWidth > 0 {
		return u.layoutState.detailsGuideWidth
	}
	return 88
}

func (u *ui) addWrappedSectionHeaderWidth(label, value string, width int) {
	lines := wrapFormValue(value, width)
	if len(lines) == 0 {
		lines = []string{""}
	}
	for index, line := range lines {
		if index == 0 {
			u.form.AddFormItem(u.newSectionHeader(label, line))
			continue
		}
		u.form.AddFormItem(u.newReadOnlyInput("", line))
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
	for index, row := range u.buttonRows {
		if row.GetButtonCount() > 0 {
			u.commands.AddItem(row, 3, 0, false)
			continue
		}
		if u.shouldReserveButtonRow(index) {
			// Keep command row heights stable so side panes do not jump when
			// actions unlock after load / scan / DNSTT transitions.
			u.commands.AddItem(nil, 3, 0, false)
		}
	}
}

func (u *ui) shouldReserveButtonRow(index int) bool {
	if u.busyRunning() {
		return index == 1
	}
	switch u.mode {
	case screenOperators:
		return index == 1
	case screenScanner, screenDNSTT:
		return index == 0 || index == 1
	default:
		return false
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

func (u *ui) newYesNoDropDown(label, selected string, onChange func(string)) *tview.DropDown {
	options := []string{yesOption, noOption}
	current := normalizeYesNoValue(selected)
	currentIndex := 0
	for index, option := range options {
		if option == current {
			currentIndex = index
			break
		}
	}
	dropdown := tview.NewDropDown().SetLabel(label+": ").SetOptions(options, nil)
	dropdown.SetCurrentOption(currentIndex)
	dropdown.SetSelectedFunc(func(text string, index int) {
		if text != "" {
			onChange(normalizeYesNoValue(text))
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
	line1 := fmt.Sprintf("[yellow]%s[-]  [cyan]%s[-]  [white]%s[-]", operatorName, modeLabel, uiVersionLabel)
	line2 := "p targets  f load  q exit"
	if u.mode == screenScanner && viewKey != "" {
		operatorKey := viewKey
		parts := []string{"p targets", "d dns", "g scan"}
		if u.hasCompletedScan(operatorKey) {
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
		u.setStatus("No compatible resolvers meet the current score threshold for DNSTT testing.")
		u.addActivity(fmt.Sprintf("DNSTT setup blocked for %s: no qualified resolvers", operator.Name))
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
	configureInputFieldClipboard(search)
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
		qualifiedCount := countQualifiedResolvers(resolvers, u.currentScoreThreshold())
		activeScanForCurrentOperator := u.activeScanOperator == operatorKey && u.scanCancel != nil
		activeDNSTTForCurrentOperator := u.activeDNSTTOperator == operatorKey && u.dnsttCancel != nil
		lookup, lookupLoaded := u.lookupCache[operatorKey]
		customTargets := lookupLoaded && lookupUsesCustomTargets(lookup)
		u.writeStageWorkflow(&builder, operatorKey, lookup, lookupLoaded, progress, dnsttState, activeScanForCurrentOperator, activeDNSTTForCurrentOperator, qualifiedCount)
		writeScanOptionGuide(&builder, u.detailsGuideWrapWidth())
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
			fmt.Fprintf(&builder, "Selected IPs: %s  Scan Hosts: %s\n", formatCount(totalPrefixAddresses(entries)), formatCount(totalPrefixScanHosts(entries)))
			fmt.Fprintf(&builder, "Target preview: %s\n", selectedTargetPreview(entries, customTargets, targetPreviewLimit))
			builder.WriteString("Use Pick Targets for the full list.\n")
		}
		fmt.Fprintf(&builder, "Protocol: %s  Port: %s\n", displayScanProtocol(u.scanProtocol), displayScanPort(u.scanPort))
		fmt.Fprintf(&builder, "Tunnel Domain: %s\n", displayDNSTTDomain(u.dnsttDomain))
		fmt.Fprintf(&builder, "Query Size: %s  Score Threshold: %d/6\n", displayDNSTTQuerySize(u.dnsttQuerySize), u.currentScoreThreshold())
		builder.WriteString("SlipNet-style scan scores each resolver on six tunnel compatibility probes.\n")
		if !activeScanForCurrentOperator {
			fmt.Fprintf(&builder, "Targets: %s  Scanned: %s  Working: %s  Compatible: %s  Qualified: %s  Progress: %s %s\n",
				formatCount(progress.Total),
				formatCount(progress.Scanned),
				formatCount(progress.Working),
				formatCount(progress.Compatible),
				formatCount(progress.Qualified),
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
			fmt.Fprintf(&builder, "Workers: %d  Timeout: %d ms  Targets: %d  Protocol: %s  Port: %d\n",
				result.Workers,
				result.TimeoutMillis,
				result.TotalTargets,
				displayScanProtocol(result.Protocol),
				displayResultPort(result.Port),
			)
			fmt.Fprintf(&builder, "Domain: %s  Query Size: %s  Threshold: %d/6\n",
				displayDNSTTDomain(result.TunnelDomain),
				displayResultQuerySize(result.QuerySize),
				displayResultScoreThreshold(result.ScoreThreshold),
			)
			fmt.Fprintf(&builder, "Export mode: %s\n", u.effectiveScanSaveScope(operator.Key))
			fmt.Fprintf(&builder, "Cached scan: %s working  %s compatible  %s qualified\n",
				greenCount(result.WorkingCount),
				greenCount(result.CompatibleCount),
				greenCount(countQualifiedResolvers(result.Resolvers, u.currentScoreThreshold())),
			)
			if result.TransparentProxyDetected {
				builder.WriteString("Warning: transparent DNS proxy was detected during the scan.\n")
			}
			if !result.DNSTTFinishedAt.IsZero() {
				fmt.Fprintf(&builder, "Last DNSTT: %s\n", result.DNSTTFinishedAt.Format("2006-01-02 15:04:05"))
				builder.WriteString("Next: Export saves scan successes and failures. Open Test DNSTT to export only DNSTT-passed resolvers.\n\n")
			} else {
				builder.WriteString("Last DNSTT: not run yet\n")
				builder.WriteString("Next: run Test DNSTT for tunnel validation, or Export to save scan results.\n\n")
			}
		} else if !activeScanForCurrentOperator {
			if u.hasCompletedDNSTT(operator.Key) {
				builder.WriteString("DNSTT finished for this operator.\n")
				builder.WriteString("Next: Export saves scan results, or open Test DNSTT to export passed resolvers.\n\n")
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
				fmt.Fprintf(&builder, "%02d  %-15s  %-4s  %d/6  %-34s  %5d ms  %-7s  %s\n",
					index+1,
					resolver.IP,
					displayTransport(resolver.Transport),
					resolver.TunnelScore,
					resolverTunnelDetails(resolver),
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
		qualifiedCount := countQualifiedResolvers(resolvers, u.currentScoreThreshold())
		activeScanForCurrentOperator := u.activeScanOperator == operatorKey && u.scanCancel != nil
		activeDNSTTForCurrentOperator := u.activeDNSTTOperator == operatorKey && u.dnsttCancel != nil
		lookup, lookupLoaded := u.lookupCache[operatorKey]
		u.writeStageWorkflow(&builder, operatorKey, lookup, lookupLoaded, progress, dnsttState, activeScanForCurrentOperator, activeDNSTTForCurrentOperator, qualifiedCount)
		writeDNSTTOptionGuide(&builder, u.detailsGuideWrapWidth())
		fmt.Fprintf(&builder, "Operator: %s\n", operator.Name)
		fmt.Fprintf(&builder, "ASNs: %s\n\n", displayOperatorASNs(operator))

		writeDetailSectionHeader(&builder, "DNS Scan")
		fmt.Fprintf(&builder, "Selected targets: %s\n", u.selectedScanSummary(operatorKey))
		fmt.Fprintf(&builder, "Protocol: %s  Port: %s\n", displayScanProtocol(string(scanner.ProtocolUDP)), displayScanPort(u.scanPort))
		fmt.Fprintf(&builder, "Domain: %s  Query Size: %s  Threshold: %d/6\n", displayDNSTTDomain(u.dnsttDomain), displayDNSTTQuerySize(u.dnsttQuerySize), u.currentScoreThreshold())
		fmt.Fprintf(&builder, "%s Qualified resolvers: %s\n\n", colorBadge("OK"), greenCount(qualifiedCount))

		writeDetailSectionHeader(&builder, "DNSTT Setup")
		fmt.Fprintf(&builder, "Domain: %s\n", displayDNSTTDomain(u.dnsttDomain))
		fmt.Fprintf(&builder, "Timeout: %s ms  Query Size: %s  Threshold: %d/6\n", displayDNSTTTimeout(u.dnsttTimeoutMS), displayDNSTTQuerySize(u.dnsttQuerySize), u.currentScoreThreshold())
		fmt.Fprintf(&builder, "Pubkey: %s\n", displayDNSTTPubkey(u.dnsttPubkey))
		fmt.Fprintf(&builder, "Test Nearby IPs: %s\n", normalizeYesNoValue(u.dnsttNearbyIPs))
		fmt.Fprintf(&builder, "E2E Timeout: %s s\n", displayDNSTTE2ETimeout(u.dnsttE2ETimeoutS))
		fmt.Fprintf(&builder, "E2E URL: %s\n", displayDNSTTE2EURL(u.dnsttE2EURL))
		fmt.Fprintf(&builder, "DNSTT Runtime: %s embedded\n", colorBadge("OK"))
		builder.WriteString("\n")

		writeDetailSectionHeader(&builder, "DNSTT Results")
		if activeDNSTTForCurrentOperator {
			fmt.Fprintf(&builder, "DNSTT running: tested %s/%s  tunnel %s  e2e %s\n\n",
				formatCount(dnsttState.Tested),
				formatCount(dnsttState.Total),
				greenCount(dnsttState.Tunnel),
				greenCount(dnsttState.E2E),
			)
		} else if u.activeDNSTTOperator != "" && u.activeDNSTTOperator != operator.Key {
			fmt.Fprintf(&builder, "Background DNSTT running for %s.\n\n", u.operatorName(u.activeDNSTTOperator))
		}
		fmt.Fprintf(&builder, "DNSTT candidates: %s  Checked: %s  Tunnel OK: %s  E2E OK: %s\n\n",
			formatCount(dnsttState.Total),
			formatCount(dnsttState.Tested),
			greenCount(dnsttState.Tunnel),
			greenCount(dnsttState.E2E),
		)

		writeDetailSectionHeader(&builder, "Export")
		if result, ok := u.scanCache[operatorKey]; ok && !result.DNSTTFinishedAt.IsZero() && !activeDNSTTForCurrentOperator {
			fmt.Fprintf(&builder, "Last DNSTT: %s\n", result.DNSTTFinishedAt.Format("2006-01-02 15:04:05"))
			builder.WriteString("Next: Export Passed saves DNSTT-passed resolvers and a paired failures file.\n\n")
		} else if !activeDNSTTForCurrentOperator {
			builder.WriteString("No completed DNSTT run cached for this operator.\n")
			builder.WriteString("Next: Start DNSTT to unlock Export Passed and the paired failures export.\n\n")
		}
		if len(resolvers) == 0 {
			builder.WriteString("No DNS services reached yet.\n")
		} else {
			builder.WriteString("DNS Hosts\n")
			for index, resolver := range resolvers {
				fmt.Fprintf(&builder, "%02d  %-15s  %-4s  %d/6  %-34s  %5d ms  %-7s  %s\n",
					index+1,
					resolver.IP,
					displayTransport(resolver.Transport),
					resolver.TunnelScore,
					resolverTunnelDetails(resolver),
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
			Scanned:    result.ScannedTargets,
			Total:      result.TotalTargets,
			Working:    result.WorkingCount,
			Compatible: result.CompatibleCount,
			Qualified:  countQualifiedResolvers(result.Resolvers, u.currentScoreThreshold()),
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
			Total:  dnsttCandidateCount(result, u.currentScoreThreshold()),
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
	configureTextAreaClipboard(textArea)
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

	cfg, err := u.scanConfig(selectedEntries)
	if err != nil {
		u.setStatus(err.Error())
		u.addActivity(fmt.Sprintf("Scan config invalid for %s", operator.Name))
		return
	}

	u.activeScanOperator = operator.Key
	u.liveProgress = scanProgress{Total: cfg.HostLimit}
	u.liveResolvers = nil
	u.scanProtocol = string(scanner.ProtocolUDP)
	ctx, cancel := context.WithCancel(context.Background())
	u.scanCancel = cancel
	u.setStatus(fmt.Sprintf("Scanning %s...", operator.Name))
	u.addActivity(fmt.Sprintf(
		"Scan started for %s on %s using UDP/%d with %d workers over %s targets against %s (threshold %d/6)",
		operator.Name,
		u.selectedScanSummary(operator.Key),
		cfg.Port,
		cfg.Workers,
		formatCount(u.liveProgress.Total),
		displayDNSTTDomain(cfg.Domain),
		cfg.ScoreThreshold,
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
						Scanned:    event.Scanned,
						Total:      event.Total,
						Working:    event.Working,
						Compatible: event.Compatible,
						Qualified:  event.Qualified,
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
					"Scan finished for %s: %s working, %s compatible, %s qualified. Use Export to save results.",
					op.Name,
					formatCount(result.WorkingCount),
					formatCount(result.CompatibleCount),
					formatCount(result.QualifiedCount),
				))
				u.addActivity(fmt.Sprintf(
					"Scan finished for %s: %s checked, %s working, %s compatible, %s qualified",
					op.Name,
					formatCount(result.ScannedTargets),
					formatCount(result.WorkingCount),
					formatCount(result.CompatibleCount),
					formatCount(result.QualifiedCount),
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
	cfg.BasePrefixes = scanPrefixStrings(result.Prefixes)
	e2ERequested := strings.TrimSpace(cfg.Pubkey) != ""

	candidates := countQualifiedResolvers(result.Resolvers, u.currentScoreThreshold())
	if candidates == 0 {
		u.setStatus("No compatible resolvers meet the current score threshold for DNSTT testing.")
		u.addActivity(fmt.Sprintf("DNSTT blocked for %s: no qualified resolvers", operator.Name))
		return
	}

	u.activeDNSTTOperator = operator.Key
	u.liveDNSTTProgress = dnsttProgress{Total: candidates}
	ctx, cancel := context.WithCancel(context.Background())
	u.dnsttCancel = cancel
	u.setStatus(fmt.Sprintf("Testing DNSTT for %s...", operator.Name))
	u.addActivity(fmt.Sprintf(
		"DNSTT started for %s on %s qualified resolvers using %s (threshold %d/6, nearby /24 %s)",
		operator.Name,
		formatCount(candidates),
		displayDNSTTDomain(cfg.Domain),
		cfg.ScoreThreshold,
		normalizeYesNoValue(u.dnsttNearbyIPs),
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
			finalResult.DNSTTCandidates = summary.Candidates
			finalResult.DNSTTChecked = summary.Checked
			finalResult.DNSTTTunnel = summary.TunnelOK
			finalResult.DNSTTE2E = summary.E2EOK
			finalResult.DNSTTTimeoutMS = int(config.Timeout.Milliseconds())
			finalResult.DNSTTE2ETimeS = int(config.E2ETimeout.Seconds())
			finalResult.DNSTTQuerySize = config.QuerySize
			finalResult.DNSTTE2EPort = 0
			finalResult.DNSTTE2EURL = config.E2EURL
			finalResult.DNSTTE2EEnabled = strings.TrimSpace(config.Pubkey) != ""
			finalResult.DNSTTE2ERequested = e2ERequested
			finalResult.DNSTTTestNearbyIPs = config.TestNearbyIPs
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
		hostLimit := totalPrefixScanHosts(selectedEntries)
		if progress.Total == 0 && len(resolvers) == 0 {
			u.setStatus("No scan results available yet.")
			u.addActivity("Resolver save skipped: no scan results")
			return
		}
		result = model.ScanResult{
			Operator:        operator,
			Prefixes:        slices.Clone(selectedEntries),
			Resolvers:       resolvers,
			TotalTargets:    progress.Total,
			ScannedTargets:  progress.Scanned,
			ReachableCount:  progress.Working,
			RecursiveCount:  progress.Qualified,
			WorkingCount:    progress.Working,
			CompatibleCount: progress.Compatible,
			QualifiedCount:  progress.Qualified,
			Workers:         mustInt(u.scanWorkers, 256),
			TimeoutMillis:   mustInt(u.scanTimeoutMS, 15000),
			HostLimit:       hostLimit,
			Port:            mustPort(u.scanPort, 53),
			Protocol:        string(scanner.ProtocolUDP),
			TunnelDomain:    strings.TrimSpace(u.dnsttDomain),
			QuerySize:       mustInt(u.dnsttQuerySize, 0),
			ScoreThreshold:  u.currentScoreThreshold(),
			StartedAt:       time.Now(),
			FinishedAt:      time.Now(),
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

	if u.mode == screenDNSTT {
		filtered := filterScanResult(result, saveScope)
		if len(filtered.Resolvers) == 0 {
			u.setStatus(fmt.Sprintf("No matching scan results for %s.", saveScope))
			u.addActivity(fmt.Sprintf("Resolver export skipped for %s: no %s", operator.Name, saveScope))
			return
		}
		if err := export.SaveResolvers(savePath, format, filtered); err != nil {
			u.setStatus(fmt.Sprintf("Save failed: %v", err))
			u.addActivity(fmt.Sprintf("Resolver save failed for %s", operator.Name))
			return
		}

		failureResult, failureReady := buildDNSTTFailureExport(result)
		statusLine := fmt.Sprintf("Saved resolvers to %s", savePath)
		activityLine := fmt.Sprintf(
			"Saved %s for %s using %s",
			formatCount(filtered.ReachableCount),
			operator.Name,
			saveScope,
		)
		if failureReady {
			failurePath := pairedOutputPath(savePath, operator.Key, u.dnsttFailureExportPrefix(operator.Key), format, time.Now())
			if err := export.SaveFailedHosts(failurePath, format, failureResult); err != nil {
				u.setStatus(fmt.Sprintf("Failure save failed: %v", err))
				u.addActivity(fmt.Sprintf("Failure export save failed for %s", operator.Name))
				return
			}
			statusLine = fmt.Sprintf("Saved passed resolvers to %s and failures to %s", savePath, failurePath)
			activityLine = fmt.Sprintf(
				"Saved %s DNSTT-passed resolvers and %s failures for %s",
				formatCount(filtered.ReachableCount),
				formatCount(failureResult.FailedCount),
				operator.Name,
			)
		}
		u.rebuildForm()
		u.renderAll()
		u.setStatus(statusLine)
		u.addActivity(activityLine)
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

func (u *ui) scanConfig(entries []model.PrefixEntry) (scanner.Config, error) {
	workers, err := strconv.Atoi(strings.TrimSpace(u.scanWorkers))
	if err != nil || workers <= 0 {
		return scanner.Config{}, fmt.Errorf("workers must be a positive integer")
	}
	timeoutMS, err := strconv.Atoi(strings.TrimSpace(u.scanTimeoutMS))
	if err != nil || timeoutMS <= 0 {
		return scanner.Config{}, fmt.Errorf("timeout must be a positive integer in milliseconds")
	}
	hostLimit := totalPrefixScanHosts(entries)
	if hostLimit == 0 {
		return scanner.Config{}, fmt.Errorf("selected targets do not contain any scannable IPv4 hosts")
	}
	portText := strings.TrimSpace(u.scanPort)
	port := 53
	if portText != "" {
		port, err = strconv.Atoi(portText)
		if err != nil || port <= 0 || port > 65535 {
			return scanner.Config{}, fmt.Errorf("port must be an integer between 1 and 65535")
		}
	}
	domain, err := scanner.NormalizeProbeDomain(u.dnsttDomain)
	if err != nil {
		return scanner.Config{}, fmt.Errorf("dnstt domain: %w", err)
	}
	querySize := mustInt(u.dnsttQuerySize, 0)
	if querySize < 0 {
		return scanner.Config{}, fmt.Errorf("query size must be zero or greater")
	}
	scoreThreshold, err := strconv.Atoi(strings.TrimSpace(u.dnsttScoreThreshold))
	if err != nil || scoreThreshold <= 0 || scoreThreshold > 6 {
		return scanner.Config{}, fmt.Errorf("score threshold must be an integer between 1 and 6")
	}

	return scanner.Config{
		Workers:        workers,
		Timeout:        time.Duration(timeoutMS) * time.Millisecond,
		HostLimit:      hostLimit,
		Port:           port,
		Protocol:       scanner.ProtocolUDP,
		Domain:         domain,
		QuerySize:      querySize,
		ScoreThreshold: scoreThreshold,
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
	scoreThreshold, err := strconv.Atoi(strings.TrimSpace(u.dnsttScoreThreshold))
	if err != nil || scoreThreshold <= 0 || scoreThreshold > 6 {
		return dnstt.Config{}, fmt.Errorf("score threshold must be an integer between 1 and 6")
	}

	e2eURL := strings.TrimSpace(u.dnsttE2EURL)
	if e2eURL == "" {
		e2eURL = dnstt.DefaultE2ETestURL
	}
	request, err := http.NewRequest(http.MethodGet, e2eURL, nil)
	if err != nil || request.URL == nil || request.URL.Host == "" {
		return dnstt.Config{}, fmt.Errorf("e2e url must be a valid http or https URL")
	}
	if request.URL.Scheme != "http" && request.URL.Scheme != "https" {
		return dnstt.Config{}, fmt.Errorf("e2e url must use http or https")
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
		Workers:        workers,
		Timeout:        time.Duration(timeoutMS) * time.Millisecond,
		E2ETimeout:     time.Duration(e2eTimeoutSeconds) * time.Second,
		Port:           targetPort,
		Domain:         strings.TrimSpace(u.dnsttDomain),
		Pubkey:         strings.TrimSpace(u.dnsttPubkey),
		QuerySize:      querySize,
		ScoreThreshold: scoreThreshold,
		E2EURL:         e2eURL,
		TestNearbyIPs:  u.dnsttNearbyIPsEnabled(),
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
	return countQualifiedResolvers(result.Resolvers, u.currentScoreThreshold()) > 0
}

func (u *ui) effectiveScanSaveScope(operatorKey string) scanSaveScope {
	if u.mode == screenDNSTT {
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
			"Scan %s: %s %s  scanned %s/%s  working %s  compatible %s  qualified %s",
			u.operatorName(u.activeScanOperator),
			meterBar(progress.Scanned, progress.Total, 16),
			percent(progress.Scanned, progress.Total),
			formatCount(progress.Scanned),
			formatCount(progress.Total),
			formatCount(progress.Working),
			formatCount(progress.Compatible),
			formatCount(countQualifiedResolvers(resolvers, u.currentScoreThreshold())),
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

func (u *ui) writeStageWorkflow(builder *strings.Builder, operatorKey string, lookup model.LookupResult, lookupLoaded bool, scanState scanProgress, dnsttState dnsttProgress, scanActive bool, dnsttActive bool, qualifiedCount uint64) {
	builder.WriteString("[lightskyblue::b]Step Progress[-:-:-]\n")
	builder.WriteString(uiSeparatorLine)
	builder.WriteString("\n")

	loadCurrent := uint64(0)
	loadTotal := uint64(1)
	loadStatus := workflowStatus("WAIT", "waiting for targets")
	if lookupLoaded {
		loadCurrent = 1
		loadStatus = fmt.Sprintf("%s %s ready, %s", colorBadge("OK"), lookup.SourceLabel, u.selectedScanSummary(operatorKey))
	}
	writeWorkflowLine(builder, "1. Load Targets", loadCurrent, loadTotal, loadStatus)

	scanCurrent := uint64(0)
	scanTotal := uint64(1)
	scanStatus := workflowStatus("WAIT", "waiting to start")
	if scanActive {
		scanCurrent = scanState.Scanned
		scanTotal = maxProgressTotal(scanState.Total)
		scanStatus = fmt.Sprintf("%s running: working %s, compatible %s, qualified %s",
			colorBadge("RUN"),
			greenCount(scanState.Working),
			greenCount(scanState.Compatible),
			greenCount(scanState.Qualified),
		)
	} else if u.hasCompletedScan(operatorKey) {
		scanCurrent = scanState.Scanned
		scanTotal = maxProgressTotal(scanState.Total)
		scanStatus = fmt.Sprintf("%s done: %s working, %s compatible, %s qualified",
			colorBadge("OK"),
			greenCount(scanState.Working),
			greenCount(scanState.Compatible),
			greenCount(qualifiedCount),
		)
	}
	writeWorkflowLine(builder, "2. DNS Scan", scanCurrent, scanTotal, scanStatus)

	dnsttCurrent := uint64(0)
	dnsttTotal := uint64(1)
	dnsttStatus := workflowStatus("WAIT", "locked until scan completes")
	if !u.hasCompletedScan(operatorKey) && !scanActive {
		dnsttStatus = workflowStatus("WAIT", "locked until scan completes")
	} else if dnsttActive {
		dnsttCurrent = dnsttState.Tested
		dnsttTotal = maxProgressTotal(dnsttState.Total)
		dnsttStatus = fmt.Sprintf("%s running: tunnel %s, e2e %s",
			colorBadge("RUN"),
			greenCount(dnsttState.Tunnel),
			greenCount(dnsttState.E2E),
		)
	} else if u.hasCompletedDNSTT(operatorKey) {
		dnsttCurrent = dnsttState.Tested
		dnsttTotal = maxProgressTotal(dnsttState.Total)
		if result, ok := u.scanCache[operatorKey]; ok && result.DNSTTE2ERequested && !result.DNSTTE2EEnabled {
			dnsttStatus = fmt.Sprintf("%s done: tunnel %s, e2e skipped",
				colorBadge("ERR"),
				greenCount(dnsttState.Tunnel),
			)
		} else if result, ok := u.scanCache[operatorKey]; ok && result.DNSTTE2EEnabled {
			dnsttStatus = fmt.Sprintf("%s done: tunnel %s, e2e %s",
				colorBadge("OK"),
				greenCount(dnsttState.Tunnel),
				greenCount(dnsttState.E2E),
			)
		} else {
			dnsttStatus = fmt.Sprintf("%s done: tunnel %s passed", colorBadge("OK"), greenCount(dnsttState.Tunnel))
		}
	} else if u.hasDNSTTCandidates(operatorKey) {
		if u.dnsttE2ERequested() {
			dnsttStatus = workflowStatus("WARN", "ready: open setup and start")
		} else {
			dnsttStatus = workflowStatus("WARN", "ready: open setup")
		}
	} else {
		dnsttStatus = workflowStatus("WARN", "no qualified resolvers yet")
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
	bar := meterBar(current, total, workflowBarWidth)
	percentText := percent(current, total)
	switch {
	case current >= total && total > 0:
		bar = "[green::b]" + bar + "[-:-:-]"
		percentText = "[green::b]" + percentText + "[-:-:-]"
	case current > 0:
		bar = "[yellow::b]" + bar + "[-:-:-]"
		percentText = "[yellow::b]" + percentText + "[-:-:-]"
	default:
		bar = "[darkgray]" + bar + "[-]"
		percentText = "[darkgray]" + percentText + "[-]"
	}
	fmt.Fprintf(builder, "%-16s  %s %s  %s\n",
		label,
		bar,
		percentText,
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

func countFullCompatibleResolvers(resolvers []model.Resolver) uint64 {
	var count uint64
	for _, resolver := range resolvers {
		if resolver.TunnelScore == 6 {
			count++
		}
	}
	return count
}

func countCompatibleResolvers(resolvers []model.Resolver) uint64 {
	var count uint64
	for _, resolver := range resolvers {
		if resolver.TunnelScore > 0 {
			count++
		}
	}
	return count
}

func countQualifiedResolvers(resolvers []model.Resolver, threshold int) uint64 {
	var count uint64
	for _, resolver := range resolvers {
		if resolver.TunnelScore >= threshold {
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

func totalPrefixScanHosts(entries []model.PrefixEntry) uint64 {
	var total uint64
	for _, entry := range entries {
		total += entry.ScanHosts
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

func (u *ui) dnsttE2ERequested() bool {
	return strings.TrimSpace(u.dnsttPubkey) != ""
}

func (u *ui) currentScoreThreshold() int {
	value, err := strconv.Atoi(strings.TrimSpace(u.dnsttScoreThreshold))
	if err != nil || value <= 0 {
		return 2
	}
	if value > 6 {
		return 6
	}
	return value
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

func displayResultQuerySize(value int) string {
	if value <= 0 {
		return "default"
	}
	return strconv.Itoa(value)
}

func displayResultScoreThreshold(value int) int {
	if value <= 0 {
		return 2
	}
	return value
}

func displayDNSTTTimeout(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return "15000"
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

func displayDNSTTE2EURL(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return dnstt.DefaultE2ETestURL
	}
	return text
}

func normalizeYesNoValue(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "true", "1", "on":
		return yesOption
	default:
		return noOption
	}
}

func (u *ui) dnsttNearbyIPsEnabled() bool {
	return normalizeYesNoValue(u.dnsttNearbyIPs) == yesOption
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

func resolverTunnelDetails(resolver model.Resolver) string {
	flag := func(ok bool, label string) string {
		if ok {
			return label + "✓"
		}
		return label + "✗"
	}
	edns := flag(resolver.TunnelEDNS0Support, "EDNS")
	if resolver.TunnelEDNS0Support && resolver.TunnelEDNSMaxPayload > 0 {
		edns += fmt.Sprintf("(%d)", resolver.TunnelEDNSMaxPayload)
	}
	return fmt.Sprintf("%s %s %s %s %s %s",
		flag(resolver.TunnelNSSupport, "NS"),
		flag(resolver.TunnelTXTSupport, "TXT"),
		flag(resolver.TunnelRandomSub, "RND"),
		flag(resolver.TunnelRealism, "DPI"),
		edns,
		flag(resolver.TunnelNXDOMAIN, "NXD"),
	)
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
		case left.TunnelScore != right.TunnelScore:
			if left.TunnelScore > right.TunnelScore {
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

func writeScanOptionGuide(builder *strings.Builder, width int) {
	builder.WriteString("[lightskyblue::b]Scan Guide[-:-:-]\n")
	builder.WriteString("[darkgray]")
	builder.WriteString(uiSeparatorLine)
	builder.WriteString("[-]\n")
	builder.WriteString("[gray]Field notes for the DNS scan form.[-]\n\n")
	writeWrappedGuideEntry(builder, width, "CFG", "Targets", "CIDRs or imported / pasted single IPs selected for this run. Use Pick Targets to change them. All scannable hosts in that selection are tested.")
	writeWrappedGuideEntry(builder, width, "CFG", "Workers", "Number of concurrent DNS probes. Higher is faster but heavier.")
	writeWrappedGuideEntry(builder, width, "CFG", "Timeout", "Per-request timeout in milliseconds.")
	writeWrappedGuideEntry(builder, width, "CFG", "Port", "DNS port to test. Default is `53`.")
	writeWrappedGuideEntry(builder, width, "CFG", "Protocol", "SlipNet-style scanning uses UDP DNS probes.")
	writeWrappedGuideEntry(builder, width, "CFG", "DNSTT Domain", "Tunnel domain used by the six SlipNet compatibility probes during the DNS scan.")
	writeWrappedGuideEntry(builder, width, "CFG", "Query Size", "Optional size budget for the tunnel-realism probe. Leave empty for the default full-capacity probe.")
	writeWrappedGuideEntry(builder, width, "CFG", "Score Threshold", "Minimum SlipNet compatibility score required before a resolver is considered qualified for DNSTT.")
	writeWrappedGuideEntry(builder, width, "ACT", "Start Scan", "Runs the DNS scan for the selected targets.")
	writeWrappedGuideEntry(builder, width, "ACT", "Test DNSTT", "Unlocks after a completed scan and opens the dedicated DNSTT setup screen.")
	writeWrappedGuideEntry(builder, width, "ACT", "Export", "Available after the scan. After DNSTT runs, the DNSTT screen exports only DNSTT-passed resolvers.")
	builder.WriteString("\n")
}

func writeDNSTTOptionGuide(builder *strings.Builder, width int) {
	builder.WriteString("[lightskyblue::b]DNSTT Guide[-:-:-]\n")
	builder.WriteString("[darkgray]")
	builder.WriteString(uiSeparatorLine)
	builder.WriteString("[-]\n")
	builder.WriteString("[gray]Field notes for the DNSTT setup form.[-]\n\n")
	writeWrappedGuideEntry(builder, width, "CFG", "DNSTT Domain", "Domain used for the tunnel checks. Only resolvers meeting the current score threshold are tested.")
	writeWrappedGuideEntry(builder, width, "CFG", "DNSTT Timeout", "Timeout in milliseconds for the tunnel precheck.")
	writeWrappedGuideEntry(builder, width, "OPT", "Query Size", "Optional maximum payload for the embedded DNSTT runtime. Leave empty unless you need smaller queries.")
	writeWrappedGuideEntry(builder, width, "CFG", "Score Threshold", "Minimum SlipNet compatibility score required before a resolver is eligible for DNSTT.")
	writeWrappedGuideEntry(builder, width, "CFG", "DNSTT Pubkey", "Leave empty for tunnel-only validation. Set it to enable full DNSTT E2E checks.")
	writeWrappedGuideEntry(builder, width, "CFG", "Test Nearby IPs", "When set to Yes, any successful original IPv4 resolver triggers one follow-up DNSTT pass for the rest of its /24 subnet. Nearby-discovered IPs do not expand again, and IPs already covered by the original scan ranges are skipped.")
	writeWrappedGuideEntry(builder, width, "CFG", "E2E Timeout", "Timeout in seconds for the embedded DNSTT runtime plus SOCKS5 end-to-end check.")
	writeWrappedGuideEntry(builder, width, "CFG", "E2E URL", "HTTP or HTTPS URL fetched through the tunnel after the SOCKS5 proxy starts. Default matches SlipNet's `generate_204` probe.")
	writeWrappedGuideEntry(builder, width, "ACT", "Start DNSTT", "Runs tunnel checks for qualified resolvers and, when Pubkey is set, the full E2E check too.")
	writeWrappedGuideEntry(builder, width, "ACT", "Export Passed", "Available after a completed DNSTT run. Saves passed resolvers to the main file and writes checked DNSTT failures to a paired failures file.")
	builder.WriteString("\n")
}

func writeWrappedGuideEntry(builder *strings.Builder, width int, badgeKind, label, text string) {
	badgeText := visibleBadge(badgeKind)
	labelText := label + ": "
	indent := strings.Repeat(" ", len([]rune(badgeText))+1+len([]rune(labelText)))
	bodyWidth := width - len([]rune(badgeText)) - 1 - len([]rune(labelText))
	if bodyWidth < 24 {
		bodyWidth = max(width-2, 24)
	}
	lines := wrapFormValue(text, bodyWidth)
	if len(lines) == 0 {
		return
	}

	fmt.Fprintf(builder, "%s [lightgoldenrodyellow]%s[-]: %s\n", colorBadge(badgeKind), label, lines[0])
	for _, line := range lines[1:] {
		fmt.Fprintf(builder, "%s%s\n", indent, line)
	}
}

func visibleBadge(kind string) string {
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "OK":
		return "(OK)"
	case "RUN":
		return "(RUN)"
	case "WAIT":
		return "(WAIT)"
	case "WARN":
		return "(WARN)"
	case "ERR":
		return "(ERR)"
	case "CFG":
		return "(CFG)"
	case "ACT":
		return "(ACT)"
	case "OPT":
		return "(OPT)"
	case "CHK":
		return "(CHK)"
	default:
		return "(" + strings.ToUpper(strings.TrimSpace(kind)) + ")"
	}
}

func colorBadge(kind string) string {
	text := visibleBadge(kind)
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "OK", "ACT":
		return "[green::b]" + text + "[-:-:-]"
	case "RUN", "WARN":
		return "[yellow::b]" + text + "[-:-:-]"
	case "ERR":
		return "[red::b]" + text + "[-:-:-]"
	case "CFG":
		return "[lightskyblue::b]" + text + "[-:-:-]"
	case "OPT":
		return "[darkgray]" + text + "[-]"
	case "CHK":
		return "[lightgoldenrodyellow::b]" + text + "[-:-:-]"
	default:
		return text
	}
}

func workflowStatus(kind, text string) string {
	return fmt.Sprintf("%s %s", colorBadge(kind), text)
}

func greenCount(value uint64) string {
	return "[green::b]" + formatCount(value) + "[-:-:-]"
}

func detailsGuideWrapWidth(view *tview.TextView) int {
	if view == nil {
		return 88
	}
	_, _, width, _ := view.GetInnerRect()
	if width <= 0 {
		return 88
	}
	wrapWidth := width - 3
	if wrapWidth > 96 {
		wrapWidth = 96
	}
	if wrapWidth < 48 {
		wrapWidth = 48
	}
	return wrapWidth
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
		result.WorkingCount = uint64(len(filtered))
		result.CompatibleCount = countCompatibleResolvers(filtered)
		result.QualifiedCount = countQualifiedResolvers(filtered, displayResultScoreThreshold(result.ScoreThreshold))
		result.ReachableCount = result.WorkingCount
		result.RecursiveCount = result.QualifiedCount
		return result
	}

	baseResolvers := baseScanResolvers(result.Resolvers)
	if scope != scanSaveRecursiveOnly {
		result.Resolvers = baseResolvers
		result.WorkingCount = uint64(len(result.Resolvers))
		result.CompatibleCount = countCompatibleResolvers(result.Resolvers)
		result.QualifiedCount = countQualifiedResolvers(result.Resolvers, displayResultScoreThreshold(result.ScoreThreshold))
		result.ReachableCount = result.WorkingCount
		result.RecursiveCount = result.QualifiedCount
		return result
	}

	filtered := make([]model.Resolver, 0, len(baseResolvers))
	for _, resolver := range baseResolvers {
		if resolver.TunnelScore > 0 {
			filtered = append(filtered, resolver)
		}
	}
	result.Resolvers = filtered
	result.WorkingCount = uint64(len(filtered))
	result.CompatibleCount = uint64(len(filtered))
	result.QualifiedCount = countQualifiedResolvers(filtered, displayResultScoreThreshold(result.ScoreThreshold))
	result.ReachableCount = result.WorkingCount
	result.RecursiveCount = result.QualifiedCount
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

func buildDNSTTFailureExport(result model.ScanResult) (export.FailedHostResult, bool) {
	exportResult := export.FailedHostResult{
		Operator:       result.Operator,
		TotalTargets:   dnsttCandidateCount(result, displayResultScoreThreshold(result.ScoreThreshold)),
		ScannedTargets: result.DNSTTChecked,
	}
	if result.DNSTTChecked == 0 {
		return exportResult, false
	}

	failedHosts := make([]export.FailedHost, 0)
	for _, resolver := range result.Resolvers {
		if !resolver.DNSTTChecked || dnsttExportPassed(result, resolver) {
			continue
		}
		failedHosts = append(failedHosts, export.FailedHost{
			IP:     resolver.IP,
			Prefix: resolver.Prefix,
		})
	}

	exportResult.FailedHosts = failedHosts
	exportResult.FailedCount = uint64(len(failedHosts))
	return exportResult, true
}

func dnsttExportPassed(result model.ScanResult, resolver model.Resolver) bool {
	if result.DNSTTE2ERequested {
		return resolver.DNSTTE2EOK
	}
	return resolver.DNSTTTunnelOK
}

func dnsttCandidateCount(result model.ScanResult, scoreThreshold int) uint64 {
	if result.DNSTTCandidates > 0 {
		return result.DNSTTCandidates
	}
	return countQualifiedResolvers(result.Resolvers, scoreThreshold)
}

func scanPrefixStrings(entries []model.PrefixEntry) []string {
	prefixes := make([]string, 0, len(entries))
	for _, entry := range entries {
		text := strings.TrimSpace(entry.Prefix)
		if text == "" {
			continue
		}
		prefixes = append(prefixes, text)
	}
	return prefixes
}

func baseScanResolvers(resolvers []model.Resolver) []model.Resolver {
	filtered := make([]model.Resolver, 0, len(resolvers))
	for _, resolver := range resolvers {
		if resolver.DNSTTNearby {
			continue
		}
		filtered = append(filtered, resolver)
	}
	return filtered
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

func readClipboardText() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return runClipboardReadCommand("pbpaste", nil)
	case "windows":
		for _, candidate := range []struct {
			name string
			args []string
		}{
			{name: "powershell.exe", args: []string{"-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"}},
			{name: "powershell", args: []string{"-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"}},
			{name: "pwsh.exe", args: []string{"-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"}},
			{name: "pwsh", args: []string{"-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"}},
		} {
			if _, err := exec.LookPath(candidate.name); err != nil {
				continue
			}
			return runClipboardReadCommand(candidate.name, candidate.args)
		}
		return "", fmt.Errorf("no clipboard command found (powershell, pwsh)")
	default:
		for _, candidate := range []struct {
			name string
			args []string
		}{
			{name: "wl-paste"},
			{name: "xclip", args: []string{"-selection", "clipboard", "-o"}},
			{name: "xsel", args: []string{"--clipboard", "--output"}},
		} {
			if _, err := exec.LookPath(candidate.name); err != nil {
				continue
			}
			return runClipboardReadCommand(candidate.name, candidate.args)
		}
		return "", fmt.Errorf("no clipboard command found (wl-paste, xclip, xsel)")
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

func runClipboardReadCommand(name string, args []string) (string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", fmt.Errorf("%s not found in PATH", name)
	}

	cmd := exec.Command(name, args...)
	output, err := cmd.Output()
	if err == nil {
		return normalizeClipboardText(string(output)), nil
	}

	var message string
	if exitErr, ok := err.(*exec.ExitError); ok {
		message = strings.TrimSpace(string(exitErr.Stderr))
	}
	if message == "" {
		return "", err
	}
	return "", fmt.Errorf("%v: %s", err, message)
}

func normalizeClipboardText(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return text
}

func mustInt(text string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || value <= 0 {
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
	if path := u.importPaths[operatorKey]; strings.TrimSpace(path) != "" {
		return path
	}
	if path := u.importPaths[defaultImportConfigKey]; strings.TrimSpace(path) != "" {
		return path
	}
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
	if u.mode == screenDNSTT {
		return "dnstt-scan-success"
	}
	return "dns-scan-success"
}

func (u *ui) scanFailureExportPrefix(operatorKey string) string {
	return "dns-scan-failures"
}

func (u *ui) dnsttFailureExportPrefix(operatorKey string) string {
	return "dnstt-scan-failures"
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
