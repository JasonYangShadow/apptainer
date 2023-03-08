package packer

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/apptainer/apptainer/internal/pkg/util/bin"
	"github.com/apptainer/apptainer/pkg/sylog"
)

type Gocryptfs struct {
	*Squashfs
	GocryptfsPath string
	Pass          string
}

type cryptInfo struct {
	CipherDir, PlainDir, Pass, ConfPath string
}

func NewGocryptfs() *Gocryptfs {
	g := &Gocryptfs{
		Squashfs: NewSquashfs(),
	}
	g.GocryptfsPath, _ = bin.FindBin("gocryptfs")
	return g
}

func (g *Gocryptfs) HasGocryptfs() bool {
	return g.GocryptfsPath != ""
}

func (g *Gocryptfs) init() (*cryptInfo, func(string, string) error, error) {
	if !g.HasGocryptfs() {
		return nil, nil, fmt.Errorf("could not use gocryptfs, gocryptfs not found")
	}
	tmpDir, err := os.MkdirTemp(os.TempDir(), "gocryptfs-")
	if err != nil {
		return nil, nil, err
	}
	cipherDir := filepath.Join(tmpDir, "cipher")
	plainDir := filepath.Join(tmpDir, "plain")
	cleanFn := func(target, dir string) error {
		err := syscall.Unmount(target, 0)
		if err != nil && err.(syscall.Errno) != syscall.EINVAL {
			if err.(syscall.Errno) == syscall.EBUSY {
				err = syscall.Unmount(target, syscall.MNT_DETACH)
				if err != nil {
					sylog.Fatalf("could not do lazy unmount on the mount point: %s, err: %v", target, err)
				}
			}
		}
		return os.RemoveAll(dir)
	}

	err = os.Mkdir(cipherDir, 0o700)
	if err != nil {
		return nil, cleanFn, err
	}
	err = os.Mkdir(plainDir, 0o700)
	if err != nil {
		return nil, cleanFn, err
	}

	buf := make([]byte, 32)
	_, err = rand.Read(buf)
	if err != nil {
		return nil, cleanFn, err
	}
	pass := fmt.Sprintf("%s\n", base64.URLEncoding.EncodeToString(buf))
	sylog.Debugf("start initializing gocryptfs, cipher: %s, plain: %s", cipherDir, plainDir)
	cmd := exec.Command(g.GocryptfsPath, "-init", "-deterministic-names", "-plaintextnames", cipherDir)
	cmd.Stdin = strings.NewReader(pass + pass)
	if err := cmd.Run(); err != nil {
		return nil, cleanFn, err
	}

	confPath := filepath.Join(cipherDir, "gocryptfs.conf")
	if _, err := os.Stat(confPath); err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, cleanFn, fmt.Errorf("gocryptfs initialization failed, gocryptfs.conf does not exist")
	}

	cmd = exec.Command(g.GocryptfsPath, cipherDir, plainDir)
	cmd.Stdin = strings.NewReader(pass)
	if err := cmd.Run(); err != nil {
		return nil, cleanFn, err
	}

	return &cryptInfo{
		CipherDir: cipherDir,
		PlainDir:  plainDir,
		Pass:      pass,
		ConfPath:  confPath,
	}, cleanFn, nil
}

func (g *Gocryptfs) create(files []string, dest string, opts []string) error {
	cryptInfo, cleanFn, err := g.init()
	if err != nil {
		return err
	}
	defer cleanFn(cryptInfo.PlainDir, filepath.Dir(cryptInfo.PlainDir))
	g.Pass = cryptInfo.Pass

	fileName := filepath.Base(dest)
	newDest := filepath.Join(cryptInfo.PlainDir, fileName)
	err = g.Squashfs.Create(files, newDest, opts)
	if err != nil {
		return err
	}
	info, err := os.Stat(newDest)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("squashfuse does not generate the squash img")
	}
	if info.Size() == 0 {
		return fmt.Errorf("the size of generated file: %s is 0", newDest)
	}

	encryptFile := filepath.Join(cryptInfo.CipherDir, fileName)
	info, err = os.Stat(encryptFile)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("gocryptfs does not generate the encrypted squash img")
	}
	if info.Size() == 0 {
		return fmt.Errorf("the size of generated file: %s is 0", encryptFile)
	}

	err = g.Squashfs.Create([]string{encryptFile, cryptInfo.ConfPath}, dest, opts)
	if err != nil {
		return err
	}

	return nil
}

func (g *Gocryptfs) Create(src []string, dest string, opts []string) error {
	return g.create(src, dest, opts)
}
