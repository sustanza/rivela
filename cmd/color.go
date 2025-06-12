package cmd

const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
)

func colorize(s, color string) string {
	if !flagColor {
		return s
	}
	return color + s + ansiReset
}
