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

	"github.com/apptainer/apptainer/internal/pkg/image/driver"
	"github.com/apptainer/apptainer/internal/pkg/util/bin"
	"github.com/apptainer/apptainer/pkg/sylog"
)

type Gocryptfs struct {
	*Squashfs
	gocryptfsPath  string
	fusermountPath string
	Pass           string
}

type cryptInfo struct {
	cipherDir, plainDir, pass, confPath, parentDir string
	pid                                            int
}

var defaultCleanFnGenerator = func(target string, pid int) func(bool) {
	return func(kill bool) {
		// if using syscall.Unmount, it'll show permission denied error
		cmd := exec.Command("fusermount", "-u", target)
		if err := cmd.Run(); err != nil {
			sylog.Errorf("could not unmount the mount point: %s, err: %v", target, err)
			if kill {
				// find the real gocryptfs pid
				realPid, err := driver.GetGocryptfsPid(fmt.Sprintf("-notifypid=%d", pid))
				if err != nil {
					sylog.Errorf("find gocryptfs pid encounters error: %v", err)
				} else {
					err = driver.KillProcess(realPid)
					if err != nil {
						sylog.Errorf("could not kill process, pid: %d, err: %v", pid, err)
					}
				}

			}
		}
	}
}

func newCryptInfo() *cryptInfo {
	return &cryptInfo{
		cipherDir: "",
		plainDir:  "",
		pass:      "",
		confPath:  "",
		parentDir: "",
		pid:       -1,
	}
}

func NewGocryptfs() *Gocryptfs {
	g := &Gocryptfs{
		Squashfs: NewSquashfs(),
	}
	g.gocryptfsPath, _ = bin.FindBin("gocryptfs")
	g.fusermountPath, _ = bin.FindBin("fusermount")
	return g
}

func (g *Gocryptfs) HasGocryptfs() bool {
	return g.gocryptfsPath != "" && g.fusermountPath != ""
}

func (g *Gocryptfs) init() (cryptInfo *cryptInfo, err error) {
	if !g.HasGocryptfs() {
		return nil, fmt.Errorf("either gocryptfs or fusermount does not exist")
	}

	cryptInfo = newCryptInfo()
	parentDir, err := os.MkdirTemp(os.TempDir(), "gocryptfs-")
	if err != nil {
		return
	}
	cryptInfo.parentDir = parentDir
	cipherDir := filepath.Join(parentDir, "cipher")
	plainDir := filepath.Join(parentDir, "plain")

	err = os.Mkdir(cipherDir, 0o700)
	if err != nil {
		return
	}
	cryptInfo.cipherDir = cipherDir
	err = os.Mkdir(plainDir, 0o700)
	if err != nil {
		return
	}
	cryptInfo.plainDir = plainDir

	buf := make([]byte, 32)
	_, err = rand.Read(buf)
	if err != nil {
		return
	}

	pass := fmt.Sprintf("%s\n", base64.URLEncoding.EncodeToString(buf))
	sylog.Debugf("start initializing gocryptfs, cipher: %s, plain: %s", cipherDir, plainDir)
	cmd := exec.Command(g.gocryptfsPath, "-init", "-deterministic-names", "-plaintextnames", cipherDir)
	cmd.Stdin = strings.NewReader(pass + pass)
	if err = cmd.Run(); err != nil {
		return
	}
	cryptInfo.pass = pass
	cryptInfo.confPath = filepath.Join(cipherDir, "gocryptfs.conf")

	cmd = exec.Command(g.gocryptfsPath, cipherDir, plainDir)
	cmd.Stdin = strings.NewReader(pass)
	if err = cmd.Run(); err != nil {
		return
	}
	cryptInfo.pid = cmd.Process.Pid

	return
}

func (g *Gocryptfs) create(files []string, dest string, opts []string) error {
	cryptInfo, err := g.init()
	if err != nil {
		if cryptInfo != nil && cryptInfo.parentDir != "" {
			// need to clean up the tmp created folder
			os.RemoveAll(cryptInfo.parentDir)
		}
		return err
	}

	// check whether gocryptfs is mounted and ready
	errCh := make(chan error, 1)
	defer close(errCh)
	go driver.CheckMountInfo(cryptInfo.plainDir, errCh)

	err = <-errCh
	if err != nil {
		return err
	}

	// the gocryptfs is ready, create the clean func
	defer func() {
		if cryptInfo != nil {
			if cryptInfo.plainDir != "" && cryptInfo.pid > 0 {
				defaultCleanFnGenerator(cryptInfo.plainDir, cryptInfo.pid)(true)
			}

			if cryptInfo.parentDir != "" {
				os.RemoveAll(cryptInfo.parentDir)
			}
		}
	}()

	g.Pass = cryptInfo.pass
	fileName := filepath.Base(dest)
	newDest := filepath.Join(cryptInfo.plainDir, fileName)
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

	encryptFile := filepath.Join(cryptInfo.cipherDir, fileName)
	info, err = os.Stat(encryptFile)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("gocryptfs does not generate the encrypted squash img")
	}
	if info.Size() == 0 {
		return fmt.Errorf("the size of generated file: %s is 0", encryptFile)
	}

	err = g.Squashfs.Create([]string{encryptFile, cryptInfo.confPath}, dest, opts)
	if err != nil {
		return err
	}

	return nil
}

func (g *Gocryptfs) Create(src []string, dest string, opts []string) error {
	return g.create(src, dest, opts)
}
