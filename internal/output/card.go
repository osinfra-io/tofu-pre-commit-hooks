package output

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// Card draws a styled terminal card with box-drawing borders.
//
//	╭─ [BADGE] Title
//	│  content line
//	│
//	│  more content
//	╰─
type Card struct {
	color string
	width int
}

// NewCard creates a Card with the given border color.
func NewCard(borderColor string) *Card {
	// Reserve the sidebar and room for pre-commit's output indentation.
	return &Card{color: borderColor, width: max(1, TermWidth()-7)}
}

// Open prints the card header line.
func (c *Card) Open(badge, title string) {
	fmt.Printf("%s %s %s\n", c.border("╭─"), badge, title)
}

// Line prints a content line within the card.
func (c *Card) Line(text string) {
	for _, line := range strings.Split(text, "\n") {
		prefix := ""
		if visible := ansi.Strip(line); strings.HasPrefix(visible, "│") {
			prefixWidth := 1
			if strings.HasPrefix(visible, "│ ") {
				prefixWidth++
			}
			// Keep OpenTofu's nested diagnostic border on continuations too.
			prefix = ansi.Cut(line, 0, prefixWidth)
			line = ansi.Cut(line, prefixWidth, ansi.StringWidth(line))
		}
		start := 0
		width := max(1, c.width-ansi.StringWidth(prefix))
		for _, wrapped := range strings.Split(ansi.Hardwrap(line, width, true), "\n") {
			end := start + ansi.StringWidth(wrapped)
			// Reapply the original styles after the sidebar resets its color.
			content := ansi.Cut(line, start, end)
			fmt.Printf("%s  %s%s\n", c.border("│"), prefix, content)
			start = end
		}
	}
}

// Paragraph wraps descriptive text at word boundaries within the card.
func (c *Card) Paragraph(text, color string) {
	for _, line := range WrapText(text, min(76, c.width)) {
		c.Line(Colorize(line, color))
	}
}

// Blank prints an empty separator line within the card.
func (c *Card) Blank() {
	fmt.Println(c.border("│"))
}

// Close prints the card footer line.
func (c *Card) Close() {
	fmt.Println(c.border("╰─"))
}

func (c *Card) border(s string) string {
	return fmt.Sprintf("%s%s%s", c.color, s, Reset)
}

// Badge returns a colored badge string like [ERROR] or [WARNING].
func Badge(text, color string) string {
	return fmt.Sprintf("%s[%s]%s", color, text, Reset)
}

// Title returns a bold white title string.
func Title(text string) string {
	return fmt.Sprintf("%s%s%s", BoldWhite, text, Reset)
}

// WrapText wraps text at word boundaries for the given width.
func WrapText(text string, width int) []string {
	words := strings.Fields(text)
	var lines []string
	var current strings.Builder

	for _, word := range words {
		if current.Len() > 0 && current.Len()+1+len(word) > width {
			lines = append(lines, current.String())
			current.Reset()
		}
		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(word)
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}
