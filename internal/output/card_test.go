package output

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestCard(t *testing.T) {
	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	c := NewCard(Red)
	c.Open(Badge("ERROR", BoldRed), Title("Something failed"))
	c.Line(File + " test.tofu:42")
	c.Blank()
	c.Line(Dim + "description line" + Reset)
	c.Close()

	_ = w.Close()
	outBytes, _ := io.ReadAll(r)
	out := string(outBytes)

	if !strings.Contains(out, "╭─") {
		t.Error("Expected card open border")
	}
	if !strings.Contains(out, "╰─") {
		t.Error("Expected card close border")
	}
	if !strings.Contains(out, "[ERROR]") {
		t.Error("Expected ERROR badge")
	}
	if !strings.Contains(out, "Something failed") {
		t.Error("Expected title text")
	}
	if !strings.Contains(out, "test.tofu:42") {
		t.Error("Expected file reference line")
	}
	if !strings.Contains(out, "description line") {
		t.Error("Expected description line")
	}
}

func TestBadge(t *testing.T) {
	b := Badge("HIGH", BoldRed)
	if !strings.Contains(b, "[HIGH]") {
		t.Errorf("Badge() = %q, expected [HIGH]", b)
	}
}

func TestTitle_Output(t *testing.T) {
	tt := Title("My Title")
	if !strings.Contains(tt, "My Title") {
		t.Errorf("Title() = %q, expected My Title", tt)
	}
}

func TestWrapText(t *testing.T) {
	text := "This is a long sentence that should be wrapped at the word boundary"
	lines := WrapText(text, 30)
	for _, line := range lines {
		if len(line) > 30 {
			t.Errorf("Line exceeds width: %q (%d chars)", line, len(line))
		}
	}
	joined := strings.Join(lines, " ")
	if joined != text {
		t.Errorf("WrapText lost content: got %q, want %q", joined, text)
	}
}

func TestCardLineWrapsWithinSidebar(t *testing.T) {
	for _, tc := range []struct {
		name       string
		text       string
		underlined bool
		prefix     string
	}{
		{
			name:   "source from validation diagnostic",
			text:   `│ 43: workspace_valid = can(regex("^us-east[14]-[a-f]-${local.stage}-(sandbox|non-production|production)$", terraform.workspace))`,
			prefix: "│ ",
		},
		{name: "colored nested border", text: "\x1b[31m│\x1b[0m " + strings.Repeat("source ", 20), prefix: "│ "},
		{name: "long path", text: strings.Repeat("directory/", 15) + "main.tofu:43"},
		{name: "active ANSI style", text: "\x1b[4m" + strings.Repeat("value ", 20) + "\x1b[0m", underlined: true},
		{name: "wide graphemes", text: strings.Repeat("界📄👩‍💻e\u0301", 15)},
		{name: "existing newlines", text: strings.Repeat("first ", 20) + "\n" + strings.Repeat("second ", 20)},
		{name: "empty", text: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			oldStdout := os.Stdout
			os.Stdout = w
			defer func() { os.Stdout = oldStdout }()
			card := NewCard(Red)
			card.width = 31
			card.Line(tc.text)
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			captured, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			var content strings.Builder
			for i, line := range strings.Split(strings.TrimSuffix(string(captured), "\n"), "\n") {
				visible := ansi.Strip(line)
				if !strings.HasPrefix(visible, "│  "+tc.prefix) {
					t.Errorf("continuation lost its sidebar: %q", line)
				}
				if ansi.StringWidth(visible) > card.width+3 {
					t.Errorf("line overflowed its sidebar: %q", visible)
				}
				if tc.underlined && !strings.Contains(line, "\x1b[4m") {
					t.Errorf("continuation lost its underline: %q", line)
				}
				part := strings.TrimPrefix(visible, "│  ")
				if i > 0 && tc.prefix != "" {
					part = strings.TrimPrefix(part, tc.prefix)
				}
				content.WriteString(part)
			}
			want := strings.ReplaceAll(ansi.Strip(tc.text), "\n", "")
			if content.String() != want {
				t.Errorf("wrapping changed diagnostic text:\ngot:  %q\nwant: %q", content.String(), want)
			}
		})
	}
}
