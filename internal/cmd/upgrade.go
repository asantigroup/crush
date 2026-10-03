package cmd

import (
	"fmt"

	"github.com/charmbracelet/crush/internal/update"
	"github.com/charmbracelet/crush/internal/version"
	"github.com/spf13/cobra"
)

var upgradeCmd = &cobra.Command{
	Use:     "upgrade",
	Aliases: []string{"self-update"},
	Short:   "Upgrade Crush to the latest release",
	Long: `Upgrade Crush to the latest release.

Downloads the latest release archive from GitHub, verifies its checksum,
and replaces the running binary in place. Restart Crush afterwards to run
the new version. Only supported on Linux.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		ctx := cmd.Context()
		info, err := update.Upgrade(ctx, version.Version, update.Default)
		if err != nil {
			return err
		}

		switch {
		case info.IsDevelopment():
			fmt.Printf("This is a development build; self-update is disabled. The latest version is v%s.\n", info.Latest)
		case info.Upgraded:
			fmt.Printf("Crush upgraded to v%s in place. Restart to apply.\n", info.Latest)
		default:
			fmt.Printf("Crush is up to date (v%s).\n", info.Current)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(upgradeCmd)
}
