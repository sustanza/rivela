package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/spf13/cobra"
)

// TestExecute_Error verifies that Execute exits when the command returns an error.
func TestExecute_Error(t *testing.T) {
	if os.Getenv("RIVELA_EXECUTE_ERROR") == "1" {
		orig := rootCmd
		rootCmd = &cobra.Command{RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("boom")
		}}
		defer func() { rootCmd = orig }()
		Execute()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestExecute_Error")
	cmd.Env = append(os.Environ(), "RIVELA_EXECUTE_ERROR=1")
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected exit status")
	}
}

// TestGetCommandPointer ensures GetCommand exposes RivelaCmd.
func TestGetCommandPointer(t *testing.T) {
	if GetCommand() != RivelaCmd {
		t.Fatalf("expected RivelaCmd")
	}
}
