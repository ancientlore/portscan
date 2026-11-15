package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/x/term"
)

var (
	titleBadgeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#6C5CE7")).
			Padding(0, 1)

	hostStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00D2D3"))

	metaStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A4B0BE"))

	openStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#2ED573"))

	openFilteredStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FFA502"))

	closedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#747D8C"))

	filteredStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ECCC68"))

	errorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF4757"))

	serviceStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#70A1FF"))

	bannerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#DFE4EA"))

	headerCellStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#A29BFE")).
			Padding(0, 1)

	cellStyle = lipgloss.NewStyle().
			Padding(0, 1)

	borderStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#57606F"))

	hintStyle = lipgloss.NewStyle().
			Italic(true).
			Foreground(lipgloss.Color("#57606F"))
)

// ScanSummary aggregates counts by port status and tracks scan timing.
type ScanSummary struct {
	Host          string        `json:"host"`
	ResolvedIP    string        `json:"resolved_ip"`
	Protocol      string        `json:"protocol"`
	TotalPorts    int           `json:"total_ports"`
	ScannedPorts  int           `json:"scanned_ports"`
	Open          int           `json:"open"`
	OpenFiltered  int           `json:"open_filtered"`
	Closed        int           `json:"closed"`
	Filtered      int           `json:"filtered"`
	Errors        int           `json:"errors"`
	ResourceLimit bool          `json:"resource_limit_reached,omitempty"`
	Canceled      bool          `json:"canceled,omitempty"`
	StartedAt     time.Time     `json:"started_at"`
	Duration      time.Duration `json:"-"`
	DurationMs    int64         `json:"duration_ms"`
}

func (s *ScanSummary) Record(res ScanResult) {
	s.ScannedPorts++
	switch res.Status {
	case StatusOpen:
		s.Open++
	case StatusOpenFiltered:
		s.OpenFiltered++
	case StatusClosed:
		s.Closed++
	case StatusFiltered:
		s.Filtered++
	case StatusResourceExhausted:
		s.Errors++
		s.ResourceLimit = true
	case StatusCanceled:
		s.Canceled = true
	default:
		s.Errors++
	}
}

// JSONResult is the serializable representation of a single port scan result.
type JSONResult struct {
	Port      int        `json:"port"`
	Protocol  string     `json:"protocol"`
	Status    PortStatus `json:"status"`
	Service   string     `json:"service,omitempty"`
	LatencyMs float64    `json:"latency_ms"`
	Banner    string     `json:"banner,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// JSONReport is the top-level JSON output structure for -json.
type JSONReport struct {
	Summary ScanSummary  `json:"summary"`
	Results []JSONResult `json:"results"`
}

// shouldDisplayResult determines whether a result should be included in the output rows.
func shouldDisplayResult(res ScanResult, verbose bool, udp bool) bool {
	if verbose {
		return res.Status != StatusCanceled
	}
	if res.Open() {
		return true
	}
	if udp && res.Status == StatusOpenFiltered {
		return true
	}
	return false
}

// insertSortedResult inserts a ScanResult into a slice sorted ascending by port number.
func insertSortedResult(slice []ScanResult, res ScanResult) []ScanResult {
	idx := sort.Search(len(slice), func(i int) bool {
		return slice[i].Port >= res.Port
	})
	slice = append(slice, ScanResult{})
	copy(slice[idx+1:], slice[idx:])
	slice[idx] = res
	return slice
}

// isStdoutTTY reports whether standard output is attached to an interactive terminal.
func isStdoutTTY() bool {
	return term.IsTerminal(os.Stdout.Fd())
}

// --- Bubble Tea Inline TUI Model ---

type scanResultMsg ScanResult
type scanDoneMsg struct{}
type tickMsg time.Time

type tuiModel struct {
	ctx        context.Context
	cancel     context.CancelFunc
	cfg        ScanConfig
	resultsCh  <-chan ScanResult
	summary    ScanSummary
	displayed  []ScanResult
	verbose    bool
	udp        bool
	spinner    spinner.Model
	progress   progress.Model
	termWidth  int
	termHeight int
	quitting   bool
}

func newTUIModel(ctx context.Context, cancel context.CancelFunc, cfg ScanConfig, totalPorts int, verbose bool, resultsCh <-chan ScanResult) tuiModel {
	sp := spinner.New(
		spinner.WithSpinner(spinner.MiniDot),
		spinner.WithStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("#6C5CE7"))),
	)
	prog := progress.New(
		progress.WithDefaultBlend(),
		progress.WithWidth(40),
	)

	w, h, err := term.GetSize(os.Stdout.Fd())
	if err != nil || w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	if w > 60 {
		barW := w - 36
		if barW > 60 {
			barW = 60
		}
		prog.SetWidth(barW)
	}

	return tuiModel{
		ctx:       ctx,
		cancel:    cancel,
		cfg:       cfg,
		resultsCh: resultsCh,
		summary: ScanSummary{
			Host:       cfg.HostHeader,
			ResolvedIP: cfg.TargetAddr,
			Protocol:   cfg.Protocol,
			TotalPorts: totalPorts,
			StartedAt:  time.Now(),
		},
		verbose:    verbose,
		udp:        cfg.Protocol == "udp",
		spinner:    sp,
		progress:   prog,
		termWidth:  w,
		termHeight: h,
	}
}

func waitForNextResult(ch <-chan ScanResult) tea.Cmd {
	return func() tea.Msg {
		res, ok := <-ch
		if !ok {
			return scanDoneMsg{}
		}
		return scanResultMsg(res)
	}
}

func tickEvery() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		waitForNextResult(m.resultsCh),
		tickEvery(),
	)
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.termWidth = msg.Width
		m.termHeight = msg.Height
		barW := msg.Width - 36
		if barW < 20 {
			barW = 20
		}
		if barW > 60 {
			barW = 60
		}
		m.progress.SetWidth(barW)
		return m, nil

	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.summary.Canceled = true
			m.quitting = true
			m.cancel()
			return m, tea.Quit
		}

	case spinner.TickMsg:
		if m.quitting {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case progress.FrameMsg:
		var cmd tea.Cmd
		m.progress, cmd = m.progress.Update(msg)
		return m, cmd

	case tickMsg:
		if m.quitting {
			return m, nil
		}
		return m, tickEvery()

	case scanResultMsg:
		res := ScanResult(msg)
		m.summary.Record(res)
		if shouldDisplayResult(res, m.verbose, m.udp) {
			m.displayed = insertSortedResult(m.displayed, res)
		}
		var pct float64
		if m.summary.TotalPorts > 0 {
			pct = float64(m.summary.ScannedPorts) / float64(m.summary.TotalPorts)
		}
		progCmd := m.progress.SetPercent(pct)
		return m, tea.Batch(progCmd, waitForNextResult(m.resultsCh))

	case scanDoneMsg:
		if m.ctx.Err() != nil {
			m.summary.Canceled = true
		}
		m.summary.Duration = time.Since(m.summary.StartedAt)
		m.summary.DurationMs = m.summary.Duration.Milliseconds()
		m.quitting = true
		return m, tea.Quit
	}

	return m, nil
}

func (m tuiModel) View() tea.View {
	// When quitting, clear the transient inline progress view so main() can print
	// the full unclipped sorted table and summary into terminal scrollback.
	if m.quitting {
		return tea.NewView("")
	}

	var b strings.Builder

	b.WriteString(renderHeaderLine(m.summary, m.cfg))
	b.WriteByte('\n')

	elapsed := time.Since(m.summary.StartedAt).Round(100 * time.Millisecond)
	var rate float64
	if sec := time.Since(m.summary.StartedAt).Seconds(); sec > 0 {
		rate = float64(m.summary.ScannedPorts) / sec
	}

	pct := 0.0
	if m.summary.TotalPorts > 0 {
		pct = float64(m.summary.ScannedPorts) / float64(m.summary.TotalPorts)
	}

	b.WriteString(fmt.Sprintf("%s %s  %s\n",
		m.spinner.View(),
		m.progress.ViewAs(pct),
		metaStyle.Render(fmt.Sprintf("%d/%d (%0.0f/s • %s)",
			m.summary.ScannedPorts, m.summary.TotalPorts, rate, elapsed)),
	))

	b.WriteString(renderStatusCounters(m.summary))
	b.WriteByte('\n')

	if len(m.displayed) > 0 {
		maxRows := 10
		if m.termHeight > 14 {
			maxRows = m.termHeight - 10
			if maxRows > 16 {
				maxRows = 16
			}
		}
		preview := m.displayed
		overflow := 0
		if len(preview) > maxRows {
			overflow = len(preview) - maxRows
			preview = preview[:maxRows]
		}
		b.WriteString(renderResultsTable(preview, m.cfg.GrabBanner, m.verbose))
		b.WriteByte('\n')
		if overflow > 0 {
			b.WriteString(metaStyle.Render(fmt.Sprintf("  … and %d more ports (full table shown on completion)", overflow)))
			b.WriteByte('\n')
		}
	}

	b.WriteString(hintStyle.Render("Press q or Ctrl+C to stop scan early"))
	return tea.NewView(b.String())
}

// --- Rendering Helpers for TUI & Scrollback Output ---

func renderHeaderLine(sum ScanSummary, cfg ScanConfig) string {
	hostDisp := sum.Host
	if sum.ResolvedIP != "" && sum.ResolvedIP != sum.Host {
		hostDisp = fmt.Sprintf("%s (%s)", sum.Host, sum.ResolvedIP)
	}
	return fmt.Sprintf("%s %s %s",
		titleBadgeStyle.Render("PORTSCAN"),
		hostStyle.Render(hostDisp),
		metaStyle.Render(fmt.Sprintf("• %d %s ports • %d workers • timeout %s",
			sum.TotalPorts, strings.ToUpper(sum.Protocol), cfg.Workers, cfg.Timeout)),
	)
}

func renderStatusCounters(sum ScanSummary) string {
	parts := []string{
		openStyle.Render(fmt.Sprintf("● Open: %d", sum.Open)),
	}
	if sum.OpenFiltered > 0 || sum.Protocol == "udp" {
		parts = append(parts, openFilteredStyle.Render(fmt.Sprintf("◐ Open|Filtered: %d", sum.OpenFiltered)))
	}
	parts = append(parts,
		closedStyle.Render(fmt.Sprintf("○ Closed: %d", sum.Closed)),
		filteredStyle.Render(fmt.Sprintf("◌ Filtered: %d", sum.Filtered)),
	)
	if sum.Errors > 0 {
		parts = append(parts, errorStyle.Render(fmt.Sprintf("✖ Errors: %d", sum.Errors)))
	}
	return strings.Join(parts, metaStyle.Render("  │  "))
}

func formatStatusCell(status PortStatus) string {
	switch status {
	case StatusOpen:
		return openStyle.Render("OPEN")
	case StatusOpenFiltered:
		return openFilteredStyle.Render("OPEN|FILTERED")
	case StatusClosed:
		return closedStyle.Render("CLOSED")
	case StatusFiltered:
		return filteredStyle.Render("FILTERED")
	case StatusResourceExhausted:
		return errorStyle.Render("FD_LIMIT")
	default:
		return errorStyle.Render(strings.ToUpper(string(status)))
	}
}

func renderResultsTable(results []ScanResult, showBannerCol bool, verbose bool) string {
	headers := []string{"PORT", "PROTO", "STATE", "SERVICE", "LATENCY"}
	hasDetails := showBannerCol || verbose
	if !hasDetails {
		for _, r := range results {
			if r.Banner != "" {
				hasDetails = true
				break
			}
		}
	}
	if hasDetails {
		headers = append(headers, "BANNER / DETAILS")
	}

	rows := make([][]string, 0, len(results))
	for _, r := range results {
		svc := r.Service
		if svc == "" {
			svc = "-"
		}
		row := []string{
			strconv.Itoa(r.Port),
			strings.ToUpper(r.Protocol),
			formatStatusCell(r.Status),
			serviceStyle.Render(svc),
			r.Latency.Round(10 * time.Microsecond).String(),
		}
		if hasDetails {
			detail := r.Banner
			if detail == "" && !r.Open() && r.Err != nil {
				detail = r.Err.Error()
			}
			if detail != "" {
				detail = bannerStyle.Render(detail)
			}
			row = append(row, detail)
		}
		rows = append(rows, row)
	}

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(borderStyle).
		Headers(headers...).
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return headerCellStyle
			}
			return cellStyle
		})

	return t.Render()
}

func printFinalScrollbackReport(w io.Writer, sum ScanSummary, cfg ScanConfig, displayed []ScanResult, verbose bool) {
	fmt.Fprintln(w, renderHeaderLine(sum, cfg))

	if len(displayed) > 0 {
		fmt.Fprintln(w, renderResultsTable(displayed, cfg.GrabBanner, verbose))
	} else {
		fmt.Fprintln(w, metaStyle.Render("  No open ports found."))
	}

	fmt.Fprintln(w, renderStatusCounters(sum))

	var rate float64
	if sec := sum.Duration.Seconds(); sec > 0 {
		rate = float64(sum.ScannedPorts) / sec
	}
	statusNote := "completed"
	if sum.Canceled {
		statusNote = "canceled early"
	}
	fmt.Fprintln(w, metaStyle.Render(fmt.Sprintf(
		"Scan %s: %d/%d ports in %s (%.0f ports/s)",
		statusNote, sum.ScannedPorts, sum.TotalPorts, sum.Duration.Round(time.Millisecond), rate,
	)))

	if sum.ResourceLimit {
		fmt.Fprintln(w, errorStyle.Render("Warning: OS file descriptor limit reached during scan; lower -threads or raise ulimit -n"))
	}
}

// runInteractiveTUI runs the inline Bubble Tea v2 interface and prints the final report to scrollback.
func runInteractiveTUI(ctx context.Context, cancel context.CancelFunc, cfg ScanConfig, totalPorts int, verbose bool, resultsCh <-chan ScanResult) error {
	m := newTUIModel(ctx, cancel, cfg, totalPorts, verbose, resultsCh)
	p := tea.NewProgram(m)
	finalModel, err := p.Run()
	if err != nil {
		return err
	}
	fm, ok := finalModel.(tuiModel)
	if !ok {
		return nil
	}
	if fm.summary.Duration == 0 {
		fm.summary.Duration = time.Since(fm.summary.StartedAt)
		fm.summary.DurationMs = fm.summary.Duration.Milliseconds()
	}
	printFinalScrollbackReport(os.Stdout, fm.summary, cfg, fm.displayed, verbose)
	return nil
}

// collectScanHeadless consumes resultsCh without Bubble Tea and returns the sorted results and summary.
func collectScanHeadless(cfg ScanConfig, totalPorts int, verbose bool, resultsCh <-chan ScanResult) (ScanSummary, []ScanResult) {
	sum := ScanSummary{
		Host:       cfg.HostHeader,
		ResolvedIP: cfg.TargetAddr,
		Protocol:   cfg.Protocol,
		TotalPorts: totalPorts,
		StartedAt:  time.Now(),
	}
	udp := cfg.Protocol == "udp"
	var displayed []ScanResult
	for res := range resultsCh {
		sum.Record(res)
		if shouldDisplayResult(res, verbose, udp) {
			displayed = insertSortedResult(displayed, res)
		}
	}
	sum.Duration = time.Since(sum.StartedAt)
	sum.DurationMs = sum.Duration.Milliseconds()
	return sum, displayed
}

func writeJSONReport(w io.Writer, sum ScanSummary, results []ScanResult) error {
	out := JSONReport{
		Summary: sum,
		Results: make([]JSONResult, 0, len(results)),
	}
	for _, r := range results {
		jr := JSONResult{
			Port:      r.Port,
			Protocol:  r.Protocol,
			Status:    r.Status,
			Service:   r.Service,
			LatencyMs: float64(r.Latency.Microseconds()) / 1000.0,
			Banner:    r.Banner,
		}
		if !r.Open() && r.Err != nil {
			jr.Error = r.Err.Error()
		}
		out.Results = append(out.Results, jr)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeCSVReport(w io.Writer, results []ScanResult) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"port", "protocol", "status", "service", "latency_ms", "banner", "error"}); err != nil {
		return err
	}
	for _, r := range results {
		errStr := ""
		if !r.Open() && r.Err != nil {
			errStr = r.Err.Error()
		}
		row := []string{
			strconv.Itoa(r.Port),
			r.Protocol,
			string(r.Status),
			r.Service,
			fmt.Sprintf("%.3f", float64(r.Latency.Microseconds())/1000.0),
			r.Banner,
			errStr,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
