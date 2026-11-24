package output

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	lintLocationPattern = regexp.MustCompile(`^on (.+) line ([0-9]+)`)
	lintSourcePattern   = regexp.MustCompile(`^[0-9]+:`)
)

type lintFinding struct {
	title       string
	rule        string
	location    string
	description []string
}

func parseLintFindings(raw, severity string) []lintFinding {
	var findings []lintFinding
	var current *lintFinding
	for _, line := range strings.Split(cleanLintOutput(raw), "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "warning:") || strings.HasPrefix(lower, "error:") {
			current = nil
			if !strings.HasPrefix(lower, severity+":") {
				continue
			}
			title := strings.TrimSpace(line[len(severity)+1:])
			rule := ""
			if start := strings.LastIndex(title, " ("); start >= 0 && strings.HasSuffix(title, ")") {
				rule = title[start+2 : len(title)-1]
				title = title[:start]
			}
			findings = append(findings, lintFinding{title: title, rule: rule})
			current = &findings[len(findings)-1]
			continue
		}
		if current == nil || line == "" {
			continue
		}
		if match := lintLocationPattern.FindStringSubmatch(line); match != nil {
			current.location = match[1] + ":" + match[2]
			continue
		}
		if lintSourcePattern.MatchString(line) {
			continue
		}
		current.description = append(current.description, line)
	}
	return findings
}

// PrintLintWarningSummary renders individual findings using the scan card layout.
func PrintLintWarningSummary(messages []TofuMessage) {
	printLintSummary(messages, "warning", "WARNING", BoldYellow, Yellow)
}

// PrintLintErrorSummary keeps warnings out of error cards and preserves
// initialization failures that do not use lint's structured diagnostics.
func PrintLintErrorSummary(messages []TofuMessage) {
	var initErrors, lintErrors []TofuMessage
	for _, message := range messages {
		if message.Step == "lint" {
			lintErrors = append(lintErrors, message)
		} else {
			initErrors = append(initErrors, message)
		}
	}
	PrintErrorSummary(initErrors)
	printLintSummary(lintErrors, "error", "ERROR", BoldRed, Red)
}

func printLintSummary(messages []TofuMessage, severity, badge, badgeColor, borderColor string) {
	// Only combine messages with identical locations as well as diagnostics.
	var groups []*errorGroup
	seen := make(map[string]*errorGroup)
	for _, message := range messages {
		raw := cleanLintOutput(message.Output)
		if raw == "" && severity == "error" {
			raw = message.Output
		}
		key := message.Step + "\x00" + raw
		if group, ok := seen[key]; ok {
			group.paths = append(group.paths, message.RelPath)
		} else {
			group := &errorGroup{step: message.Step, paths: []string{message.RelPath}, raw: raw}
			seen[key] = group
			groups = append(groups, group)
		}
	}
	printed := false
	for _, group := range groups {
		findings := parseLintFindings(group.raw, severity)
		if severity == "error" && len(findings) == 0 {
			findings = []lintFinding{{title: "OpenTofu " + group.step + " failed", description: []string{group.raw}}}
		}
		for _, finding := range findings {
			if printed {
				fmt.Println()
			}
			printed = true
			card := NewCard(borderColor)
			card.Open(Badge(badge, badgeColor), Title(finding.title))
			for _, path := range group.paths {
				location := path
				if finding.location != "" {
					location = filepath.ToSlash(filepath.Join(path, finding.location))
				}
				card.Line(fmt.Sprintf("%s %s", File, Colorize(location, Gray)))
			}
			if finding.rule != "" {
				card.Line(fmt.Sprintf("%s %s", Tag, Colorize(finding.rule, Gray)))
			}
			if len(finding.description) > 0 {
				card.Blank()
				card.Paragraph(strings.Join(finding.description, " "), Dim)
			}
			card.Close()
		}
	}
}
