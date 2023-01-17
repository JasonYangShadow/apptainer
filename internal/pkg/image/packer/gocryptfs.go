package packer

import (
	"errors"
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
	gocryptfsPath  string
	fusermountPath string
	Squashfs
}

func NewGocryptfs() *Gocryptfs {
	g := &Gocryptfs{}
	g.gocryptfsPath, _ = bin.FindBin("gocryptfs")
	g.fusermountPath, _ = bin.FindBin("fusermount")
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
	}

	return nil
}

func (g *Gocryptfs) Create(src []string, dest string, opts []string) error {
	sylog.Debugf("gocryptfs create is called, start initialization, %s, %s", env.DefaultGocryptfsCipherPath(), env.DefaultGocryptfsPlainPath())
	err := g.init()
	if err != nil {
		return err
	}

	sylog.Debugf("gocryptfs starts encrypting plain path")
	cmd := exec.Command(g.gocryptfsPath, env.DefaultGocryptfsCipherPath(), env.DefaultGocryptfsPlainPath())
	cmd.Stdin = strings.NewReader(password)
	if err := cmd.Run(); err != nil {
		return err
	}
	defer func() {
		err := exec.Command(g.fusermountPath, "-u", env.DefaultGocryptfsPlainPath()).Run()
		if err != nil {
			sylog.Fatalf("could not unmount the gocryptfs plain folder: %s using fusermount, err: %s", env.DefaultGocryptfsPlainPath(), err.Error())
		}
	}()

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
	return os.Rename(encrytedDest, dest)
}
