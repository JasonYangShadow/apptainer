package unpacker

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/apptainer/apptainer/internal/pkg/util/bin"
	"github.com/apptainer/apptainer/internal/pkg/util/env"
)

const (
	password = "12345\n"
)

type Gocryptfs struct {
	gocryptfsPath string
	squshfs       *Squashfs
}

func NewGocryptfs() *Gocryptfs {
	g := &Gocryptfs{}
	g.gocryptfsPath, _ = bin.FindBin("gocryptfs")
	g.squshfs = NewSquashfs()
	return g
}

func (g *Gocryptfs) HasGocryptfs() bool {
	return g.gocryptfsPath != ""
}

func (g *Gocryptfs) init() error {
	initConf := filepath.Join(env.DefaultGocryptfsCipherPath(), "gocryptfs.conf")
	// make sure the the folder is not initialized
	if _, err := os.Stat(initConf); err != nil && os.IsNotExist(err) {
		cmd := exec.Command(g.gocryptfsPath, "-init", "-deterministic-names", "-plaintextnames", env.DefaultGocryptfsCipherPath())
		cmd.Stdin = strings.NewReader(password)
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	return nil
}
