package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"range-scout/internal/export"
	"range-scout/internal/model"
	"range-scout/internal/operators"
	"range-scout/internal/prefixes"
	"range-scout/internal/ripestat"
	"range-scout/internal/scanner"
)

type screen string

type scanSaveScope string

const (
	screenOperators screen = "operators"
	screenScanner   screen = "scanner"

	scanSaveRecursiveOnly scanSaveScope = "recursive only"
	scanSaveAllDNSHosts   scanSaveScope = "all dns hosts"
)

type scanProgress struct {
	Scanned   uint64
	Total     uint64
	Reachable uint64
	Recursive uint64
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

	activeScanOperator string
	liveProgress       scanProgress
	liveResolvers      []model.Resolver
	scanCancel         context.CancelFunc

	prefixFormat        string
	prefixPath          string
	scanFormat          string
	scanPath            string
	scanSaveScope       scanSaveScope
	scanRanges          map[string][]string
	prefixSuggestedPath string
	scanSuggestedPath   string
	scanWorkers         string
	scanTimeoutMS       string
	scanHostLimit       string
	scanPort            string
	scanProtocol        string
	scanProbeURL1       string
	scanProbeURL2       string
	activityLines       []string
	lastStatusLine      string
	lockSelection       bool
}

func newUI() *ui {
	u := &ui{
		app:           tview.NewApplication(),
		pages:         tview.NewPages(),
		header:        tview.NewTextView(),
		operatorList:  tview.NewList(),
		details:       tview.NewTextView(),
		commands:      tview.NewFlex().SetDirection(tview.FlexRow),
		form:          tview.NewForm(),
		buttonRows:    []*tview.Form{tview.NewForm(), tview.NewForm(), tview.NewForm()},
		activity:      tview.NewTextView(),
		status:        tview.NewTextView(),
		operators:     operators.All(),
		mode:          screenOperators,
		client:        ripestat.NewClient(),
		lookupCache:   make(map[string]model.LookupResult),
		scanCache:     make(map[string]model.ScanResult),
		prefixFormat:  export.FormatCSV.String(),
		scanFormat:    export.FormatTXT.String(),
		scanSaveScope: scanSaveRecursiveOnly,
		scanRanges:    make(map[string][]string),
		scanWorkers:   "256",
		scanTimeoutMS: "1200",
		scanHostLimit: "50000",
		scanPort:      "53",
		scanProtocol:  string(scanner.ProtocolUDP),
		scanProbeURL1: "https://github.com",
		scanProbeURL2: "https://example.com",
	}

	u.configureViews()
	u.populateOperators()
	u.updateDefaultPaths()
	u.rebuildForm()
	u.addActivity("Ready")
	u.renderAll()
	u.setStatus("Ready. Select an operator and press Enter to fetch prefixes.")

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
		AddItem(u.status, 2, 0, false)

	u.pages.AddPage("main", main, true, true)
	u.app.SetRoot(u.pages, true)
	u.app.SetFocus(u.operatorList)
	u.app.SetInputCapture(u.handleKeys)
	u.app.EnableMouse(true)

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
		if u.scanRunning() {
			u.restoreSelectedOperator()
			u.setStatus("Scan running. Stop it before changing operator.")
			return
		}
		u.selected = index
		u.updateDefaultPaths()
		u.rebuildForm()
		u.renderAll()
	})
	u.operatorList.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		if u.scanRunning() {
			u.setStatus("Scan running. Stop it before fetching or switching.")
			u.addActivity("Fetch blocked: scan active")
			u.restoreSelectedOperator()
			return
		}
		u.selected = index
		u.fetchPrefixes()
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
	u.activity.SetTitle("Activity")
	u.activity.SetWrap(true)

	u.status.
		SetDynamicColors(true).
		SetBorder(true).
		SetTitle("Status")
}

func (u *ui) populateOperators() {
	for _, op := range u.operators {
		u.operatorList.AddItem(fmt.Sprintf("%s [%s]", op.Name, strings.Join(op.ASNs, ", ")), "", 0, nil)
	}
}

func (u *ui) handleKeys(event *tcell.EventKey) *tcell.EventKey {
	if u.pages.HasPage("range-picker") {
		return event
	}

	if u.focusIsEditable() {
		if event.Key() == tcell.KeyEsc {
			u.app.SetFocus(u.operatorList)
			return nil
		}
		return event
	}

	if u.scanRunning() {
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
			u.stopScan()
			return nil
		case event.Rune() == 'p' || event.Rune() == 'd' || event.Rune() == 'f' || event.Rune() == 's' || event.Rune() == 'g':
			u.blockDuringScan("Another operation is blocked while a scan is running.")
			return nil
		}
		switch event.Key() {
		case tcell.KeyUp, tcell.KeyDown, tcell.KeyEnter, tcell.KeyPgUp, tcell.KeyPgDn, tcell.KeyHome, tcell.KeyEnd:
			if u.app.GetFocus() == u.operatorList {
				u.setStatus("Scan running. Stop it before changing operator.")
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
		u.openScanner()
		return nil
	case event.Rune() == 'f':
		u.fetchPrefixes()
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
	case event.Rune() == 'x' && u.mode == screenScanner:
		u.stopScan()
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
	switch u.app.GetFocus().(type) {
	case *tview.InputField, *tview.DropDown:
		return true
	default:
		return false
	}
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

func (u *ui) rebuildForm() {
	u.form.Clear(true)
	u.clearButtonRows()

	if u.scanRunning() {
		u.form.SetTitle("Commands - Scan Running")
		u.addButtonRow(0, buttonSpec{label: "Stop Scan", action: u.stopScan})
		u.rebuildCommands()
		return
	}

	switch u.mode {
	case screenOperators:
		u.form.SetTitle("Commands - Prefixes")
		u.form.AddFormItem(u.newFormatDropDown("Format", u.prefixFormat, func(value string) {
			u.prefixFormat = value
			u.updateDefaultPaths()
			u.rebuildForm()
			u.renderAll()
		}))
		u.form.AddFormItem(u.newInput("Path", u.prefixPath, func(value string) { u.prefixPath = value }))
		u.addButtonRow(0,
			buttonSpec{label: "Fetch", action: u.fetchPrefixes},
			buttonSpec{label: "Save", action: u.savePrefixes},
		)
		if u.hasFetchedPrefixes(u.selectedOperator().Key) {
			u.addButtonRow(1,
				buttonSpec{label: "Scan Setup", action: u.openScanner},
			)
		}
	case screenScanner:
		u.form.SetTitle("Commands - DNS Scan")
		u.ensureScanRangeSelection(u.selectedOperator().Key)
		u.form.AddFormItem(u.newReadOnlyInput("Ranges", u.selectedScanSummary(u.selectedOperator().Key)))
		u.form.AddFormItem(u.newInput("Workers", u.scanWorkers, func(value string) { u.scanWorkers = value }))
		u.form.AddFormItem(u.newInput("Timeout", u.scanTimeoutMS, func(value string) { u.scanTimeoutMS = value }))
		u.form.AddFormItem(u.newInput("Host Limit", u.scanHostLimit, func(value string) { u.scanHostLimit = value }))
		u.form.AddFormItem(u.newInput("Port", u.scanPort, func(value string) { u.scanPort = value }))
		u.form.AddFormItem(u.newScanProtocolDropDown("Protocol", u.scanProtocol, func(value string) { u.scanProtocol = value }))
		u.form.AddFormItem(u.newReadOnlyInput("Probe Note", "Make sure each probe is accessible through your network"))
		u.form.AddFormItem(u.newInput("Probe URL 1", u.scanProbeURL1, func(value string) { u.scanProbeURL1 = value }))
		u.form.AddFormItem(u.newInput("Probe URL 2", u.scanProbeURL2, func(value string) { u.scanProbeURL2 = value }))
		u.form.AddFormItem(u.newFormatDropDown("Format", u.scanFormat, func(value string) {
			u.scanFormat = value
			u.updateDefaultPaths()
			u.rebuildForm()
			u.renderAll()
		}))
		u.form.AddFormItem(u.newScanSaveScopeDropDown("Save Scope", u.scanSaveScope, func(value scanSaveScope) {
			u.scanSaveScope = value
			u.updateDefaultPaths()
			u.rebuildForm()
			u.renderAll()
		}))
		u.form.AddFormItem(u.newInput("Path", u.scanPath, func(value string) { u.scanPath = value }))
		u.addButtonRow(0,
			buttonSpec{label: "Pick Range", action: u.openRangePicker},
			buttonSpec{label: "Start Scan", action: u.startScan},
		)
		u.addButtonRow(1,
			buttonSpec{label: "Back", action: u.backToPrefixes},
			buttonSpec{label: "Export", action: u.saveResolvers},
		)
	}
	u.rebuildCommands()
}

func (u *ui) newInput(label, value string, onChange func(string)) *tview.InputField {
	field := tview.NewInputField().SetLabel(label + ": ").SetText(value)
	field.SetChangedFunc(onChange)
	return field
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
}

func (u *ui) renderHeader() {
	operator := u.selectedOperator()
	modeLabel := "Prefixes"
	if u.mode == screenScanner {
		modeLabel = "DNS Scan"
	}

	line1 := fmt.Sprintf("[yellow]%s[-]  [cyan]%s[-]", operator.Name, modeLabel)
	line2 := "p prefixes  d dns  f fetch  s save  g start  x stop  q exit"
	if u.scanRunning() {
		line2 = "scan active: stop or quit only"
	}
	u.header.SetText(line1 + "\n" + line2)
}

func (u *ui) openScanner() {
	operator := u.selectedOperator()
	if !u.hasFetchedPrefixes(operator.Key) {
		u.setStatus("Fetch prefixes before opening the scanner.")
		u.addActivity(fmt.Sprintf("Scan view blocked for %s: fetch prefixes first", operator.Name))
		return
	}
	u.mode = screenScanner
	u.updateDefaultPaths()
	u.rebuildForm()
	u.renderAll()
}

func (u *ui) backToPrefixes() {
	if u.scanRunning() {
		u.blockDuringScan("Back is blocked while a scan is running.")
		return
	}
	u.mode = screenOperators
	u.rebuildForm()
	u.renderAll()
}

func (u *ui) openRangePicker() {
	operator := u.selectedOperator()
	lookup, ok := u.lookupCache[operator.Key]
	if !ok || len(lookup.Entries) == 0 {
		u.setStatus("Fetch prefixes before choosing a scan range.")
		u.addActivity(fmt.Sprintf("Range picker blocked for %s: fetch prefixes first", operator.Name))
		return
	}

	u.ensureScanRangeSelection(operator.Key)
	selected := make(map[string]bool, len(u.scanRanges[operator.Key]))
	for _, prefix := range u.scanRanges[operator.Key] {
		selected[prefix] = true
	}

	search := tview.NewInputField().
		SetLabel("Filter: ").
		SetText("").
		SetPlaceholder("CIDR, slash, or IP fragment")
	search.SetPlaceholderTextColor(tcell.ColorGray)
	list := tview.NewList()
	list.ShowSecondaryText(false)
	list.SetBorder(true)
	list.SetTitle("Pick Scan Ranges")
	list.SetWrapAround(false)

	visibleIndices := make([]int, 0, len(lookup.Entries))
	currentIndex := 0
	refreshList := func(query string, keepPrefix string) {
		list.Clear()
		visibleIndices = visibleIndices[:0]
		currentIndex = 0
		for _, index := range filterPrefixEntryIndexes(lookup.Entries, query) {
			entry := lookup.Entries[index]
			list.AddItem(scanRangeLabel(entry, selected[entry.Prefix]), "", 0, nil)
			if entry.Prefix == keepPrefix {
				currentIndex = len(visibleIndices)
			}
			visibleIndices = append(visibleIndices, index)
		}
		if len(visibleIndices) == 0 {
			list.AddItem("No matching ranges", "", 0, nil)
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
			if len(selected) == 1 {
				u.setStatus("At least one range must stay selected.")
				return
			}
			delete(selected, entry.Prefix)
		} else {
			selected[entry.Prefix] = true
		}
		refreshList(search.GetText(), entry.Prefix)
	}
	refreshList("", u.selectedScanPrefixes(operator.Key)[0])

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
		if len(chosen) == 0 {
			chosen = append(chosen, lookup.Entries[0].Prefix)
		}
		u.scanRanges[operator.Key] = chosen
		u.addActivity(fmt.Sprintf("Selected %d ranges for %s", len(chosen), operator.Name))
		closePicker()
		u.rebuildForm()
		u.renderAll()
	}

	actions := tview.NewForm().
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
	frame.AddText("Filter examples: 94.182, /24, 109.230. Enter or Space toggles. Done applies.", false, tview.AlignCenter, tcell.ColorYellow)

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
	operator := u.selectedOperator()
	fmt.Fprintf(&builder, "Operator: %s\n", operator.Name)
	fmt.Fprintf(&builder, "ASNs: %s\n\n", strings.Join(operator.ASNs, ", "))

	switch u.mode {
	case screenOperators:
		u.details.SetTitle("Prefix Details")
		if result, ok := u.lookupCache[operator.Key]; ok {
			fmt.Fprintf(&builder, "Fetched: %s\n", result.FetchedAt.Format("2006-01-02 15:04:05"))
			fmt.Fprintf(&builder, "Source: %s\n", result.SourceLabel)
			fmt.Fprintf(&builder, "Prefixes: %s  Addresses: %s  Scan Hosts: %s\n\n",
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
		} else {
			builder.WriteString("No prefix data loaded yet.\n")
			builder.WriteString("Press Enter on the selected operator, use the Fetch button, or press 'f'.\n")
		}
	case screenScanner:
		u.details.SetTitle("DNS Scan Details")
		progress, resolvers := u.currentScanState(operator.Key)
		stableCount := countStableResolvers(resolvers)
		_, hasCachedResult := u.scanCache[operator.Key]
		fmt.Fprintf(&builder, "Selected ranges: %s\n", u.selectedScanSummary(operator.Key))
		if entries, err := u.selectedScanEntries(operator.Key); err == nil && len(entries) > 0 {
			fmt.Fprintf(&builder, "Selected IPs: %s\n", formatCount(totalPrefixAddresses(entries)))
			for _, entry := range entries {
				fmt.Fprintf(&builder, "  - %s (%s IPs)\n", entry.Prefix, formatCount(entry.TotalAddresses))
			}
		}
		fmt.Fprintf(&builder, "Protocol: %s  Port: %s\n", displayScanProtocol(u.scanProtocol), displayScanPort(u.scanPort))
		fmt.Fprintf(&builder, "Probe URLs: %s | %s\n", displayProbeURL(u.scanProbeURL1), displayProbeURL(u.scanProbeURL2))
		builder.WriteString("Note: make sure each probe is accessible through your network.\n")
		if !hasCachedResult && u.activeScanOperator != operator.Key {
			builder.WriteString("\n")
			writeScanOptionGuide(&builder)
		}
		fmt.Fprintf(&builder, "Targets: %s  Scanned: %s  Reachable: %s  Recursive: %s  Stable: %s  Progress: %s %s\n\n",
			formatCount(progress.Total),
			formatCount(progress.Scanned),
			formatCount(progress.Reachable),
			formatCount(progress.Recursive),
			formatCount(stableCount),
			meterBar(progress.Scanned, progress.Total, 20),
			percent(progress.Scanned, progress.Total),
		)
		if u.activeScanOperator != "" && u.activeScanOperator != operator.Key {
			fmt.Fprintf(&builder, "Background scan running for %s.\n\n", u.operatorName(u.activeScanOperator))
		}
		if result, ok := u.scanCache[operator.Key]; ok {
			fmt.Fprintf(&builder, "Last finished: %s\n", result.FinishedAt.Format("2006-01-02 15:04:05"))
			fmt.Fprintf(&builder, "Workers: %d  Timeout: %d ms  Host Limit: %d  Protocol: %s  Port: %d\n",
				result.Workers,
				result.TimeoutMillis,
				result.HostLimit,
				displayScanProtocol(result.Protocol),
				displayResultPort(result.Port),
			)
			fmt.Fprintf(&builder, "Export mode: %s\n", u.scanSaveScope)
			fmt.Fprintf(&builder, "Cached reachability: %s DNS hosts  %s recursive  %s stable\n\n",
				formatCount(result.ReachableCount),
				formatCount(result.RecursiveCount),
				formatCount(countStableResolvers(result.Resolvers)),
			)
		} else {
			fmt.Fprintf(&builder, "Export mode: %s\n\n", u.scanSaveScope)
			builder.WriteString("No completed scan cached for this operator.\n\n")
		}
		if len(resolvers) == 0 {
			builder.WriteString("No DNS services reached yet.\n")
			builder.WriteString("Fetch prefixes, then start a scan with the form or press 'g'.\n")
		} else {
			builder.WriteString("DNS Hosts\n")
			for index, resolver := range resolvers {
				status := "dns-only"
				if resolver.Stable {
					status = "stable"
				} else if resolver.RecursionAvailable {
					status = "recursive"
				}
				fmt.Fprintf(&builder, "%02d  %-15s  %-4s  %-9s  RA=%-5t  %-8s  %5d ms  %s\n",
					index+1,
					resolver.IP,
					displayTransport(resolver.Transport),
					status,
					resolver.RecursionAdvertised,
					resolver.ResponseCode,
					resolver.LatencyMillis,
					resolver.Prefix,
				)
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

func (u *ui) fetchPrefixes() {
	if u.scanRunning() {
		u.blockDuringScan("Fetch blocked while a scan is running.")
		return
	}
	operator := u.selectedOperator()
	u.setStatus(fmt.Sprintf("Fetching prefixes for %s...", operator.Name))
	u.addActivity(fmt.Sprintf("Fetch started for %s", operator.Name))
	u.rebuildForm()
	u.renderAll()

	go func(op model.Operator) {
		result, err := u.client.LookupOperator(context.Background(), op)
		u.app.QueueUpdateDraw(func() {
			if len(result.Entries) > 0 {
				u.lookupCache[op.Key] = result
				u.ensureScanRangeSelection(op.Key)
			}
			if err != nil && len(result.Entries) == 0 {
				u.setStatus(fmt.Sprintf("Lookup failed for %s: %v", op.Name, err))
				u.addActivity(fmt.Sprintf("Fetch failed for %s", op.Name))
			} else if err != nil {
				u.setStatus(fmt.Sprintf("Loaded prefixes for %s with warnings. Use Save to export them.", op.Name))
				u.addActivity(fmt.Sprintf("Fetched %s prefixes for %s with warnings", formatCount(uint64(len(result.Entries))), op.Name))
			} else {
				u.setStatus(fmt.Sprintf("Loaded %s prefixes for %s. Use Save to export them.", formatCount(uint64(len(result.Entries))), op.Name))
				u.addActivity(fmt.Sprintf("Fetched %s prefixes for %s", formatCount(uint64(len(result.Entries))), op.Name))
			}
			u.rebuildForm()
			u.renderAll()
		})
	}(operator)
}

func (u *ui) savePrefixes() {
	if u.scanRunning() {
		u.blockDuringScan("Prefix save blocked while a scan is running.")
		return
	}
	operator := u.selectedOperator()
	savePath := u.preparePrefixSaveTarget(operator)
	u.rebuildForm()
	u.renderAll()
	result, ok := u.lookupCache[operator.Key]
	if !ok || len(result.Entries) == 0 {
		u.setStatus("No prefixes available yet.")
		u.addActivity("Prefix save skipped: nothing loaded")
		return
	}

	format, err := export.ParseFormat(u.prefixFormat)
	if err != nil {
		u.setStatus(err.Error())
		u.addActivity("Prefix save failed: invalid export format")
		return
	}
	if err := export.SavePrefixes(savePath, format, result); err != nil {
		u.setStatus(fmt.Sprintf("Save failed: %v", err))
		u.addActivity(fmt.Sprintf("Prefix save failed for %s", operator.Name))
		return
	}
	u.rebuildForm()
	u.renderAll()
	u.setStatus(fmt.Sprintf("Saved prefixes to %s", savePath))
	u.addActivity(fmt.Sprintf("Saved %s prefixes for %s", formatCount(uint64(len(result.Entries))), operator.Name))
}

func (u *ui) startScan() {
	operator := u.selectedOperator()
	selectedEntries, err := u.selectedScanEntries(operator.Key)
	if err != nil {
		u.setStatus(err.Error())
		u.addActivity(fmt.Sprintf("Scan blocked for %s: %v", operator.Name, err))
		return
	}
	if len(selectedEntries) == 0 {
		u.setStatus("Fetch prefixes first before starting a scan.")
		u.addActivity(fmt.Sprintf("Scan blocked for %s: fetch prefixes first", operator.Name))
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
			u.rebuildForm()
			u.renderAll()
		})
	}(operator, selectedEntries, cfg)
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

func (u *ui) saveResolvers() {
	if u.scanRunning() {
		u.blockDuringScan("Resolver export blocked while a scan is running.")
		return
	}
	operator := u.selectedOperator()
	savePath := u.prepareScanSaveTarget(operator)
	u.rebuildForm()
	u.renderAll()
	result, ok := u.scanCache[operator.Key]
	if !ok || len(result.Resolvers) == 0 {
		progress, resolvers := u.currentScanState(operator.Key)
		if len(resolvers) == 0 {
			u.setStatus("No resolver results available yet.")
			u.addActivity("Resolver save skipped: nothing to save")
			return
		}
		result = model.ScanResult{
			Operator:       operator,
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
	}
	result = filterScanResult(result, u.scanSaveScope)
	if len(result.Resolvers) == 0 {
		u.setStatus(fmt.Sprintf("No matching scan results for %s.", u.scanSaveScope))
		u.addActivity(fmt.Sprintf("Resolver export skipped for %s: no %s", operator.Name, u.scanSaveScope))
		return
	}

	format, err := export.ParseFormat(u.scanFormat)
	if err != nil {
		u.setStatus(err.Error())
		u.addActivity("Resolver save failed: invalid export format")
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
		u.scanSaveScope,
	))
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

func (u *ui) updateDefaultPaths() {
	operator := u.selectedOperator()
	prefixFormat, err := export.ParseFormat(u.prefixFormat)
	if err == nil {
		suggested := defaultOutputPath(operator.Key, "prefixes", prefixFormat)
		if strings.TrimSpace(u.prefixPath) == "" || u.prefixPath == u.prefixSuggestedPath {
			u.prefixPath = suggested
		}
		u.prefixSuggestedPath = suggested
	}
	scanFormat, err := export.ParseFormat(u.scanFormat)
	if err == nil {
		suggested := defaultOutputPath(operator.Key, scanSaveSuffix(u.scanSaveScope), scanFormat)
		if strings.TrimSpace(u.scanPath) == "" || u.scanPath == u.scanSuggestedPath {
			u.scanPath = suggested
		}
		u.scanSuggestedPath = suggested
	}
}

func (u *ui) preparePrefixSaveTarget(operator model.Operator) string {
	if strings.TrimSpace(u.prefixPath) == "" || u.prefixPath == u.prefixSuggestedPath {
		format, err := export.ParseFormat(u.prefixFormat)
		if err == nil {
			u.prefixPath = defaultOutputPath(operator.Key, "prefixes", format)
			u.prefixSuggestedPath = u.prefixPath
		}
	}
	return strings.TrimSpace(u.prefixPath)
}

func (u *ui) prepareScanSaveTarget(operator model.Operator) string {
	if strings.TrimSpace(u.scanPath) == "" || u.scanPath == u.scanSuggestedPath {
		format, err := export.ParseFormat(u.scanFormat)
		if err == nil {
			u.scanPath = defaultOutputPath(operator.Key, scanSaveSuffix(u.scanSaveScope), format)
			u.scanSuggestedPath = u.scanPath
		}
	}
	return strings.TrimSpace(u.scanPath)
}

func (u *ui) hasFetchedPrefixes(operatorKey string) bool {
	result, ok := u.lookupCache[operatorKey]
	return ok && len(result.Entries) > 0
}

func (u *ui) ensureScanRangeSelection(operatorKey string) {
	lookup, ok := u.lookupCache[operatorKey]
	if !ok || len(lookup.Entries) == 0 {
		delete(u.scanRanges, operatorKey)
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
	if len(filtered) == 0 {
		filtered = append(filtered, lookup.Entries[0].Prefix)
	}
	u.scanRanges[operatorKey] = filtered
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
		return "-"
	case 1:
		return selected[0]
	default:
		return fmt.Sprintf("%d ranges selected", len(selected))
	}
}

func (u *ui) selectedScanEntries(operatorKey string) ([]model.PrefixEntry, error) {
	lookup, ok := u.lookupCache[operatorKey]
	if !ok || len(lookup.Entries) == 0 {
		return nil, fmt.Errorf("fetch prefixes first before starting a scan")
	}
	u.ensureScanRangeSelection(operatorKey)
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
		return nil, fmt.Errorf("selected scan ranges are no longer available")
	}
	return entries, nil
}

func (u *ui) scanRunning() bool {
	return u.scanCancel != nil
}

func (u *ui) restoreSelectedOperator() {
	if len(u.operators) == 0 {
		return
	}
	u.lockSelection = true
	u.operatorList.SetCurrentItem(u.selected)
	u.lockSelection = false
}

func (u *ui) blockDuringScan(message string) {
	u.setStatus(message)
	u.addActivity("Operation blocked: scan active")
}

func (u *ui) confirmExit() {
	message := "Close the application?"
	if u.scanCancel != nil {
		message = "A scan is running. Exit and stop it?"
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
				u.app.Stop()
			}
		})
	u.pages.AddPage("confirm-exit", modal, true, true)
}

func (u *ui) setStatus(message string) {
	u.lastStatusLine = message
	modeLabel := "prefix mode"
	if u.mode == screenScanner {
		modeLabel = "dns mode"
	}
	help := "Enter fetches from the list. Tab cycles focus. Mouse works on the list and form."
	u.status.SetText(fmt.Sprintf("%s (%s)\n%s", message, modeLabel, help))
}

func (u *ui) addActivity(message string) {
	timestamp := time.Now().Format("15:04:05")
	entry := fmt.Sprintf("[%s] %s", timestamp, message)
	u.activityLines = append(u.activityLines, entry)
	if len(u.activityLines) > 12 {
		u.activityLines = u.activityLines[len(u.activityLines)-12:]
	}
	u.renderActivity()
}

func (u *ui) renderActivity() {
	if len(u.activityLines) == 0 {
		u.activity.SetText("No activity yet.")
		return
	}
	u.activity.SetText(strings.Join(u.activityLines, "\n"))
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

func scanRangeLabel(entry model.PrefixEntry, selected bool) string {
	label := fmt.Sprintf("%12s IPs  %s", formatCount(entry.TotalAddresses), entry.Prefix)
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

func writeScanOptionGuide(builder *strings.Builder) {
	builder.WriteString("Commands - DNS Scan\n")
	builder.WriteString("  - Ranges: CIDRs selected for this scan. Use Pick Range to change them.\n")
	builder.WriteString("  - Workers: number of concurrent DNS probes. Higher is faster but heavier.\n")
	builder.WriteString("  - Timeout: per-request timeout in milliseconds.\n")
	builder.WriteString("  - Host Limit: maximum number of hosts to scan. Leave empty or 0 for the full selection.\n")
	builder.WriteString("  - Port: DNS port to test. Default is 53.\n")
	builder.WriteString("  - Protocol: UDP, TCP, or BOTH. BOTH tries UDP first, then TCP.\n")
	builder.WriteString("  - Probe URLs: two hostnames used to confirm stable recursive resolution. Make sure each probe is accessible through your network.\n")
	builder.WriteString("  - Format / Save Scope / Path: export settings used when you press Export.\n")
	builder.WriteString("  - Start Scan runs the scan. Export saves the latest results.\n\n")
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
	return fmt.Sprintf(
		"exports/%s_%s_%s_%06d.%s",
		operatorKey,
		suffix,
		ts.Format("20060102_150405"),
		ts.Nanosecond()/1000,
		format.Extension(),
	)
}

func filterScanResult(result model.ScanResult, scope scanSaveScope) model.ScanResult {
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

func scanSaveSuffix(scope scanSaveScope) string {
	if scope == scanSaveAllDNSHosts {
		return "dns_hosts"
	}
	return "recursive_resolvers"
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

func (u *ui) operatorName(key string) string {
	for _, operator := range u.operators {
		if operator.Key == key {
			return operator.Name
		}
	}
	return key
}
