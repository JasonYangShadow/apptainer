package unpacker

import (
	"fmt"
	"os"

	"github.com/apptainer/apptainer/pkg/sylog"
	gocryptfs "github.com/rfjakob/gocryptfs/v2/pkg"
)

type Gocryptfs struct{}

func NewGocryptfs() *Gocryptfs {
	return &Gocryptfs{}
}

func (g *Gocryptfs) Decrypt(source string, offset, size uint64, conf []byte) (string, error) {
	sylog.Infof("gocryptfs starts decrypting plain path")
	src, err := os.Open(source)
	if err != nil {
		return "", err
	}
	file, unmount, err := gocryptfs.Decrypt(src, int64(offset), int64(size), conf)
	if err != nil {
		return "", err
	}
	defer unmount()

	if decryptFile, ok := file.(*os.File); ok {
		decryptFile.Close()
		sylog.Infof("returns new decrypted file: %s", decryptFile.Name())
		return decryptFile.Name(), nil
	}

	return "", fmt.Errorf("gocryptfs decrypted file type is not File type")
}
