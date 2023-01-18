package unpacker

import (
	"errors"
	"fmt"
	"io"
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
	*Squashfs
}

func NewGocryptfs() *Gocryptfs {
	g := &Gocryptfs{}
	g.gocryptfsPath, _ = bin.FindBin("gocryptfs")
	g.Squashfs = NewSquashfs()
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

		err = os.Mkdir(env.DefaultGocryptfsPlainPath(), 0o700)
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

func (g *Gocryptfs) extract(files []string, reader io.Reader, dest string) error {
	sylog.Debugf("gocryptfs starts decrpyting plain path")
	err := g.init()
	if err != nil {
		return err
	}
	sylog.Debugf("gocryptfs starts creating necessary tmp file...")
	tmp, err := os.CreateTemp(env.DefaultGocryptfsCipherPath(), "archive-")
	if err != nil {
		return fmt.Errorf("failed to create staging file: %s", err)
	}
	filename := tmp.Name()
	defer os.Remove(filename)

	if _, err := io.Copy(tmp, reader); err != nil {
		return fmt.Errorf("failed to copy content in staging file: %s", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close staging file: %s", err)
	}

	newfile := filepath.Join(env.DefaultGocryptfsPlainPath(), filepath.Base(filename))
	sylog.Debugf("gocryptfs searches decrypted new file: %s", newfile)
	decryptedfile, err := os.Open(newfile)
	if err != nil {
		return fmt.Errorf("could not find decrypted squashfs archive file: %s", newfile)
	}

	sylog.Debugf("calling unsquashfs extraction method, decryptedfile: %s, dest: %s", decryptedfile, dest)
	return g.Squashfs.extract(files, decryptedfile, dest)
}

func (g *Gocryptfs) ExtractAll(reader io.Reader, dest string) error {
	return g.extract(nil, reader, dest)
}

func (g *Gocryptfs) DecryptOffset(source string, offset, size uint64) (string, error) {
	sylog.Debugf("gocryptfs starts decrpyting plain path")
	err := g.init()
	if err != nil {
		return "", err
	}

	tmp, err := os.CreateTemp(env.DefaultGocryptfsCipherPath(), "decrypted-")
	if err != nil {
		return "", fmt.Errorf("failed to create staging file: %s", err)
	}
	filename := tmp.Name()
	// defer os.Remove(filename)

	sylog.Debugf("gocryptfs starts open the source file: %s", source)
	file, err := os.Open(source)
	if err != nil {
		return "", fmt.Errorf("could not open the source file: %s", source)
	}
	defer file.Close()
	// here we have risks to lose data during convert
	_, err = file.Seek(int64(offset), 0)
	if err != nil {
		return "", fmt.Errorf("could not seek the offset of source file, err: %s", err.Error())
	}
	if _, err := io.CopyN(tmp, file, int64(size)); err != nil {
		return "", fmt.Errorf("failed to copy content from source file: %s, with err: %s", source, err.Error())
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("failed to close staging file: %s", err)
	}

	newfile := filepath.Join(env.DefaultGocryptfsPlainPath(), filepath.Base(filename))
	if _, err := os.Stat(newfile); err != nil && os.IsNotExist(err) {
		return "", fmt.Errorf("could not use gocryptfs to decrypt source file: %s", source)
	}

	sylog.Debugf("gocryptfs successfully returns decrypted newfile path: %s", newfile)
	return newfile, nil
}
