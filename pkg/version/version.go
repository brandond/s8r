package version

import "strings"

var (
	Program      = "s8r"
	ProgramUpper = strings.ToUpper(Program)
	GitVersion   = "dev"
	GitCommit    = "HEAD"
)
