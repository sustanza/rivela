package main

import (
	"os"
	"os/exec"
	"testing"
)

func TestMainFunc(t *testing.T) {
	if os.Getenv("RIVELA_MAIN_TEST") == "1" {
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainFunc")
	cmd.Env = append(os.Environ(), "RIVELA_MAIN_TEST=1")
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected exit status")
	}
}
