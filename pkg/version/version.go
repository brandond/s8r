package version

import "strings"

var (
	Program      = "s8r"
	ProgramUpper = strings.ToUpper(Program)
	GitVersion   = "dev"
	GitCommit    = "HEAD"
	Products     = []string{"k3s", "rke2"}
)
