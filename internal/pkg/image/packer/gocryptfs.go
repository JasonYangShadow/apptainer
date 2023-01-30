package packer

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/apptainer/apptainer/internal/pkg/util/bin"
	"github.com/apptainer/apptainer/internal/pkg/util/env"
	"github.com/apptainer/apptainer/pkg/sylog"
)

const (
	password = "12345\n"
)

type Gocryptfs struct {
	gocryptfsPath string
	Squashfs
}

func NewGocryptfs() *Gocryptfs {
	g := &Gocryptfs{}
	g.gocryptfsPath, _ = bin.FindBin("gocryptfs")
	return g
}

func (g *Gocryptfs) HasGocryptfs() bool {
	return g.gocryptfsPath != ""
}

func (g *Gocryptfs) init() error {
	if !g.HasGocryptfs() {
		return errors.New("could not locate gocryptfs external binary")
	}

	initConf := filepath.Join(env.DefaultGocryptfsCipherPath(), "gocryptfs.conf")
	// make sure the the folder is not initialized
	if _, err := os.Stat(initConf); err != nil && os.IsNotExist(err) {
		err := os.Mkdir(env.DefaultGocryptfsCipherPath(), 0o700)
		if err != nil {
			return err
		}

		err = os.Mkdir(env.DefaultGocryptfsPlainPath(), 0o750)
		if err != nil {
			return err
		}

		cmd := exec.Command(g.gocryptfsPath, "-init", "-deterministic-names", "-plaintextnames", env.DefaultGocryptfsCipherPath())
		cmd.Stdin = strings.NewReader(password + password)
		if err := cmd.Run(); err != nil {
			return err
		}

		cmd = exec.Command(g.gocryptfsPath, env.DefaultGocryptfsCipherPath(), env.DefaultGocryptfsPlainPath())
		cmd.Stdin = strings.NewReader(password)
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	return nil
}

func (g *Gocryptfs) Create(src []string, dest string, opts []string) error {
	sylog.Debugf("gocryptfs create is called, start initialization, %s, %s", env.DefaultGocryptfsCipherPath(), env.DefaultGocryptfsPlainPath())
	err := g.init()
	if err != nil {
		return err
	}

	// change the dest path
	filename := filepath.Base(dest)
	newDest := filepath.Join(env.DefaultGocryptfsPlainPath(), filename)
	encrytedDest := filepath.Join(env.DefaultGocryptfsCipherPath(), filename)

	sylog.Debugf("gocryptfs start creating squashfs archive, src: %s, dest: %s", src, newDest)
	err = g.Squashfs.Create(src, newDest, opts)
	if err != nil {
		return err
	}

	// we need to replace the squashed archive with encrypted one
	sylog.Debugf("gocryptfs returns and rename the target, src: %s, dest: %s", encrytedDest, dest)
	if _, err := os.Stat(encrytedDest); err != nil && os.IsNotExist(err) {
		return fmt.Errorf("could not find encrypted squash file: %s", encrytedDest)
	}
	return os.Rename(encrytedDest, dest)
}
