package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// SkipDirectives holds parsed skip comments from source files.
type SkipDirectives struct {
	// resourceLevel maps file path → resource name → CIS control → reason.
	resourceLevel map[string]map[string]map[string]string
	globalLevel   map[string]globalSkip
}

type globalSkip struct {
	reason string
	file   string
	line   int
	info   os.FileInfo
}

// ParseSkipDirectives scans the given files for tofu-scan skip comments.
//
// Resource skip comments must be placed inside the resource block they apply to:
//
//	resource "google_container_cluster" "primary" {
//	  # tofu-scan skip: CIS 5.6.4 - Not applicable to this project
//	  name = "test"
//	}
//
// Global skip comments must be at the top level and apply to the entire scan:
//
//	# tofu-scan skip-global: CIS 1.17 - Managed at the organization level
func ParseSkipDirectives(files []string) (*SkipDirectives, error) {
	sd := &SkipDirectives{
		resourceLevel: make(map[string]map[string]map[string]string),
		globalLevel:   make(map[string]globalSkip),
	}
	seen := make(map[string]bool)
	var errs []error
	for _, file := range files {
		if seen[file] || file == "" {
			continue
		}
		seen[file] = true
		resLvl, err := parseFileSkips(file, sd.globalLevel)
		if err != nil {
			errs = append(errs, err)
		}
		if len(resLvl) > 0 {
			sd.resourceLevel[file] = resLvl
		}
	}
	return sd, errors.Join(errs...)
}

// Filter partitions violations into kept and skipped based on skip directives.
func (sd *SkipDirectives) Filter(violations []Violation) (kept, skipped []Violation) {
	for _, v := range violations {
		if reason, ok := sd.skipReason(v); ok {
			v.SkipReason = reason
			skipped = append(skipped, v)
		} else {
			kept = append(kept, v)
		}
	}
	return kept, skipped
}

func (sd *SkipDirectives) skipReason(v Violation) (string, bool) {
	if v.Resource == "global" {
		skip, ok := sd.globalLevel[v.CISControl]
		return skip.reason, ok
	}
	if resSkips, ok := sd.resourceLevel[v.File]; ok {
		if skips, ok := resSkips[v.Resource]; ok {
			if reason, ok := skips[v.CISControl]; ok {
				return reason, true
			}
		}
	}
	return "", false
}

// parseFileSkips scans a single file for resource and global skip comments.
func parseFileSkips(file string, globalLevel map[string]globalSkip) (map[string]map[string]string, error) {
	resourceLevel := make(map[string]map[string]string)

	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("read skip directives in %s: %w", file, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat skip directives in %s: %w", file, err)
	}
	source, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read skip directives in %s: %w", file, err)
	}

	start := hcl.Pos{Line: 1, Column: 1}
	parsed, diags := hclsyntax.ParseConfig(source, file, start)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse skip directives in %s: %s", file, diags.Error())
	}
	tokens, diags := hclsyntax.LexConfig(source, file, start)
	if diags.HasErrors() {
		return nil, fmt.Errorf("lex skip directives in %s: %s", file, diags.Error())
	}

	var errs []error
	body := parsed.Body.(*hclsyntax.Body)
	for _, token := range tokens {
		if token.Type != hclsyntax.TokenComment || !isDirectiveComment(string(token.Bytes), "tofu-scan skip-global:") {
			continue
		}
		lineStart := bytes.LastIndexByte(source[:token.Range.Start.Byte], '\n') + 1
		if strings.TrimSpace(string(source[lineStart:token.Range.Start.Byte])) != "" {
			errs = append(errs, fmt.Errorf("%s:%d: skip-global directive must be on its own line at the top level", file, token.Range.Start.Line))
			continue
		}
		insideBlock := false
		for _, block := range body.Blocks {
			if token.Range.Start.Byte >= block.Range().Start.Byte && token.Range.Start.Byte < block.Range().End.Byte {
				insideBlock = true
				break
			}
		}
		for _, attr := range body.Attributes {
			if token.Range.Start.Byte >= attr.Range().Start.Byte && token.Range.Start.Byte < attr.Range().End.Byte {
				insideBlock = true
				break
			}
		}
		if insideBlock {
			errs = append(errs, fmt.Errorf("%s:%d: skip-global directive must be at the top level", file, token.Range.Start.Line))
			continue
		}
		control, reason := parseDirectiveComment(string(token.Bytes), "tofu-scan skip-global:")
		if control == "" || reason == "" {
			errs = append(errs, fmt.Errorf("%s:%d: skip-global directive requires a CIS control and a non-empty reason: # tofu-scan skip-global: CIS <control> - <reason>", file, token.Range.Start.Line))
			continue
		}
		if previous, ok := globalLevel[control]; ok {
			if previous.line == token.Range.Start.Line && previous.reason == reason && os.SameFile(previous.info, info) {
				continue
			}
			errs = append(errs, fmt.Errorf("%s:%d: duplicate skip-global directive for CIS %s (already declared at %s:%d)", file, token.Range.Start.Line, control, previous.file, previous.line))
			continue
		}
		globalLevel[control] = globalSkip{reason: reason, file: file, line: token.Range.Start.Line, info: info}
	}
	tokenIndex := 0
	for _, block := range body.Blocks {
		if block.Type != "resource" || len(block.Labels) != 2 {
			continue
		}
		resource := block.Labels[0] + "." + block.Labels[1]
		for tokenIndex < len(tokens) && tokens[tokenIndex].Range.Start.Byte < block.CloseBraceRange.Start.Byte {
			token := tokens[tokenIndex]
			tokenIndex++
			if token.Type != hclsyntax.TokenComment || token.Range.Start.Byte <= block.OpenBraceRange.Start.Byte {
				continue
			}
			lineStart := bytes.LastIndexByte(source[:token.Range.Start.Byte], '\n') + 1
			if strings.TrimSpace(string(source[lineStart:token.Range.Start.Byte])) != "" || !isSkipComment(string(token.Bytes)) {
				continue
			}
			control, reason := parseSkipComment(string(token.Bytes))
			if control == "" || reason == "" {
				errs = append(errs, fmt.Errorf("%s:%d: skip directive requires a CIS control and a non-empty reason: # tofu-scan skip: CIS <control> - <reason>", file, token.Range.Start.Line))
				continue
			}
			if resourceLevel[resource] == nil {
				resourceLevel[resource] = make(map[string]string)
			}
			resourceLevel[resource][control] = reason
		}
	}

	return resourceLevel, errors.Join(errs...)
}

func isSkipComment(line string) bool {
	return isDirectiveComment(line, "tofu-scan skip:")
}

func isDirectiveComment(line, prefix string) bool {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#") {
		return false
	}
	line = strings.TrimSpace(line[1:])
	return len(line) >= len(prefix) && strings.EqualFold(line[:len(prefix)], prefix)
}

// parseSkipComment extracts a CIS control and reason from a skip
// comment. Returns empty strings if the line is not a skip comment.
//
// Format: # tofu-scan skip: CIS <control> - <reason>
func parseSkipComment(line string) (control, reason string) {
	return parseDirectiveComment(line, "tofu-scan skip:")
}

func parseDirectiveComment(line, prefix string) (control, reason string) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "#") {
		return "", ""
	}
	after := strings.TrimSpace(trimmed[1:])

	if len(after) < len(prefix) || !strings.EqualFold(after[:len(prefix)], prefix) {
		return "", ""
	}
	rest := strings.TrimSpace(after[len(prefix):])

	// Expect "CIS" keyword followed by whitespace.
	if len(rest) < 4 || !strings.EqualFold(rest[:3], "CIS") || (rest[3] != ' ' && rest[3] != '\t') {
		return "", ""
	}
	rest = strings.TrimSpace(rest[3:])

	// Extract control number (first non-whitespace token).
	parts := strings.SplitN(rest, " ", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", ""
	}
	control = parts[0]

	// Extract reason after "-".
	if len(parts) > 1 {
		remainder := strings.TrimSpace(parts[1])
		if strings.HasPrefix(remainder, "- ") {
			reason = strings.TrimSpace(remainder[2:])
		} else if strings.HasPrefix(remainder, "-") {
			reason = strings.TrimSpace(remainder[1:])
		}
	}

	return control, reason
}
