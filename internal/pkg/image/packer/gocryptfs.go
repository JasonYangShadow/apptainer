package packer

import (
	"fmt"
	"os"

	"github.com/apptainer/apptainer/pkg/sylog"
	gocryptfs "github.com/rfjakob/gocryptfs/v2/pkg"
)

type Gocryptfs struct {
	Squashfs
	Conf []byte
}

func NewGocryptfs() *Gocryptfs {
	return &Gocryptfs{}
}

func (g *Gocryptfs) Create(src []string, dest string, opts []string) error {
	sylog.Debugf("gocryptfs start creating squashfs archive, src: %s, dest: %s", src, dest)
	squashfile, err := os.CreateTemp(os.TempDir(), "mksquashfs-")
	if err != nil {
		return err
	}
	defer os.Remove(squashfile.Name())

	err = g.Squashfs.Create(src, squashfile.Name(), opts)
	if err != nil {
		return err
	}

	file, conf, unmount, err := gocryptfs.Encrypt(squashfile)
	defer unmount()
	if err != nil {
		return err
	}

	if encryptFile, ok := file.(*os.File); ok {
		encryptFile.Close()
		sylog.Debugf("gocryptfs returns and rename the target, src: %s, dest: %s", encryptFile.Name(), dest)
		g.Conf = make([]byte, len(conf))
		copy(g.Conf, conf)
		return os.Rename(encryptFile.Name(), dest)
	}
	return fmt.Errorf("gocryptfs generated file is not File type")
}
