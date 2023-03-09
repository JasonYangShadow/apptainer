package driver

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/apptainer/apptainer/internal/pkg/util/bin"
	"github.com/apptainer/apptainer/pkg/image"
	"github.com/apptainer/apptainer/pkg/sylog"
	"github.com/apptainer/apptainer/pkg/util/apptainerconf"
	"github.com/apptainer/apptainer/pkg/util/capabilities"
	mountPkg "github.com/moby/sys/mountinfo"
)

const (
	gocryptfsDriverName = "gocryptfsDriver"
	SQUASHFS            = iota
	GOCRYPTFS
)

type gocryptfsDriver struct {
	gocryptfsFeature
	cmdPrefix []string
}

type gocryptfsFeature struct {
	*decryptInfo
	cleanFn        func() error
	gocryptfsPath  string
	squashfusePath string
	mountInfos     []mountInfo
}

type mountInfo struct {
	pid       int
	srcPath   string
	dstPath   string
	mountType int
}

type decryptInfo struct {
	cipherDir, plainDir, pass, confPath string
}

var sysAttr = &syscall.SysProcAttr{
	AmbientCaps: []uintptr{
		uintptr(capabilities.Map["CAP_SYS_ADMIN"].Value),
		// Needed for nsenter
		//  https://stackoverflow.com/a/69724124/10457761
		uintptr(capabilities.Map["CAP_SYS_PTRACE"].Value),
	},
}

var defaultCleanFnGenerator = func(target string, pid int, mountType int) func(bool) {
	return func(kill bool) {
		err := syscall.Unmount(target, 0)
		if err != nil && err.(syscall.Errno) != syscall.EINVAL {
			if err.(syscall.Errno) == syscall.EBUSY {
				err = syscall.Unmount(target, syscall.MNT_DETACH)
				if err != nil {
					sylog.Errorf("could not do lazy unmount on the mount point: %s, err: %v", target, err)
					if kill {
						if mountType == GOCRYPTFS {
							// find the real gocryptfs pid
							p, err := GetGocryptfsPid(fmt.Sprintf("-notifypid=%d", pid))
							if err != nil {
								sylog.Errorf("find gocryptfs pid encounters error: %v", err)
							} else {
								pid = p
							}
						}

						err = KillProcess(pid)
						if err != nil {
							sylog.Errorf("could not kill process, pid: %d, err: %v", pid, err)
						}
					}
				}
			}
			if err != nil {
				sylog.Errorf("cleanFn has err: %v", err)
			}
		}
	}
}

func (g *gocryptfsFeature) init(binName string, purpose string, desiredFeatures image.DriverFeature) {
	if binName != "gocryptfs" {
		sylog.Debugf("binName: %s is not 'gocryptfs', return directly", binName)
		if desiredFeatures != 0 {
			sylog.Infof("binName: %s is not 'gocryptfs', will not be able to %v", binName, purpose)
		}
		return
	}

	gocryptfsPath, err := bin.FindBin(binName)
	if err != nil {
		sylog.Debugf("%v mounting not enabled because: %v", binName, err)
		if desiredFeatures != 0 {
			sylog.Infof("gocryptfs not found, will not be able to %v", purpose)
		}
	}
	g.gocryptfsPath = gocryptfsPath

	squashfusePath, err := bin.FindBin("squashfuse_ll")
	if err != nil {
		squashfusePath, err = bin.FindBin("squashfuse")
		if err != nil {
			sylog.Debugf("%v mounting not enabled because: %v", binName, err)
			if desiredFeatures != 0 {
				sylog.Infof("squashfuse_ll and squashfuse not found, will not be able to %v", purpose)
			}
		}
	}
	g.squashfusePath = squashfusePath
}

func (g *gocryptfsFeature) create() error {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "gocryptfs-")
	if err != nil {
		return err
	}
	g.decryptInfo = &decryptInfo{
		cipherDir: filepath.Join(tmpDir, "cipher"),
		plainDir:  filepath.Join(tmpDir, "plain"),
		pass:      "",
		confPath:  filepath.Join(filepath.Join(tmpDir, "cipher"), "gocryptfs.conf"),
	}
	g.cleanFn = func() error {
		return os.RemoveAll(tmpDir)
	}

	err = os.Mkdir(g.decryptInfo.cipherDir, 0o700)
	if err != nil {
		return err
	}
	err = os.Mkdir(g.decryptInfo.plainDir, 0o700)
	if err != nil {
		return err
	}

	g.mountInfos = make([]mountInfo, 0)
	return nil
}

func (g *gocryptfsFeature) Mount(params *image.MountParams, mfunc image.MountFunc, cmdPrefix []string) error {
	// step 1. initialize the gocryptfs
	if g.gocryptfsPath == "" {
		return fmt.Errorf("gocryptfs is required")
	}
	if g.squashfusePath == "" {
		return fmt.Errorf("squashfuse | squashfuse_ll is required")
	}

	err := g.create()
	if err != nil {
		return err
	}

	g.decryptInfo.pass = string(params.Key)

	ch := make(chan error, 1)

	// step 2. directly mount the sif with data partition offset to cipher folder

	oldDest := params.Target
	var extraFiles []*os.File
	if path.Dir(params.Source) == "/proc/self/fd" {
		extraFiles = make([]*os.File, 1)
		targetFd, _ := strconv.Atoi(path.Base(params.Source))
		extraFiles[0] = os.NewFile(uintptr(targetFd), params.Source)
	}
	cmd, err := g.cmdStart(cmdPrefix, sysAttr, nil, extraFiles, g.squashfusePath, "-f", "-o", fmt.Sprintf("uid=%v,gid=%v,offset=%v", os.Getuid(), os.Getgid(), params.Offset), params.Source, g.decryptInfo.cipherDir)
	if err != nil {
		return err
	}

	go CheckMountInfo(g.decryptInfo.cipherDir, ch)

	err = <-ch
	if err != nil {
		return err
	}

	// verify mounted files
	files, err := os.ReadDir(g.decryptInfo.cipherDir)
	if err != nil || len(files) == 0 {
		return fmt.Errorf("previous squashfuse mount failed, because there are no files in %s", g.decryptInfo.cipherDir)
	}

	var targetfile string
	for _, file := range files {
		info, err := file.Info()
		if err != nil {
			return err
		}
		sylog.Debugf("file name: %s, file size: %d\n", info.Name(), info.Size())
		if info.Size() == 0 {
			return fmt.Errorf("%s file size should not be 0", file.Name())
		}
		if strings.HasPrefix(file.Name(), "squashfs-") {
			targetfile = file.Name()
			break
		}
	}

	if targetfile == "" {
		return fmt.Errorf("could not locate the squashfuse created file, previous step might fail")
	}

	g.mountInfos = append(g.mountInfos, mountInfo{
		pid:       cmd.Process.Pid,
		srcPath:   params.Source,
		dstPath:   g.decryptInfo.cipherDir,
		mountType: SQUASHFS,
	})

	// step 3. trigger gocryptfs fuse mount
	cmd, err = g.cmdStart(cmdPrefix, sysAttr, strings.NewReader(fmt.Sprintf("%s\n", g.pass)), nil, g.gocryptfsPath, g.decryptInfo.cipherDir, g.decryptInfo.plainDir)
	if err != nil {
		return err
	}

	go CheckMountInfo(g.decryptInfo.plainDir, ch)
	err = <-ch
	if err != nil {
		return err
	}

	g.mountInfos = append(g.mountInfos, mountInfo{
		pid:       cmd.Process.Pid,
		srcPath:   g.decryptInfo.cipherDir,
		dstPath:   g.decryptInfo.plainDir,
		mountType: GOCRYPTFS,
	})

	// step 4. mount the plain squash image
	source := fmt.Sprintf("%s/%s", g.decryptInfo.plainDir, targetfile)
	cmd, err = g.cmdStart(cmdPrefix, sysAttr, nil, nil, g.squashfusePath, "-f", "-o", fmt.Sprintf("uid=%v,gid=%v,offset=0", os.Getuid(), os.Getgid()), source, oldDest)
	if err != nil {
		return err
	}

	go CheckMountInfo(oldDest, ch)
	err = <-ch
	if err != nil {
		return err
	}

	g.mountInfos = append(g.mountInfos, mountInfo{
		pid:       cmd.Process.Pid,
		srcPath:   source,
		dstPath:   oldDest,
		mountType: SQUASHFS,
	})

	for _, mountInfo := range g.mountInfos {
		sylog.Debugf("mount %s -> %s, pid: %d", mountInfo.srcPath, mountInfo.dstPath, mountInfo.pid)
	}

	return nil
}

func (g *gocryptfsFeature) cmdStart(cmdPrefix []string, sysAttr *syscall.SysProcAttr, stdin io.Reader, extraFiles []*os.File, args ...string) (cmd *exec.Cmd, err error) {
	sylog.Debugf("cmd starts, cmd prefix: %s, args: %s", cmdPrefix, args)
	if args[0], err = exec.LookPath(args[0]); err == nil {
		var cmdArgs []string
		cmdArgs = append(cmdArgs, cmdPrefix...)
		cmdArgs = append(cmdArgs, args...)
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if stdin != nil {
			cmd.Stdin = stdin
		}
		if sysAttr != nil {
			cmd.SysProcAttr = sysAttr
		}
		if len(extraFiles) > 0 {
			cmd.ExtraFiles = extraFiles
		}
		if err := cmd.Start(); err != nil {
			return cmd, err
		}
		return cmd, nil
	}
	return nil, fmt.Errorf("%s could not be located", args[0])
}

func (g *gocryptfsFeature) stop(target string, kill bool) error {
	// not mounted using squashfuse or gocryptfs
	if len(g.mountInfos) == 0 {
		return nil
	}

	// normal case
	if len(g.mountInfos) == 3 {
		// not our target
		if g.mountInfos[2].dstPath != target {
			return nil
		}
	}

	sylog.Debugf("gocryptfsFeature stop is called, target: %s, kill: %t, mountInfos: %v", target, kill, g.mountInfos)
	defer g.cleanFn()
	// we need to unmount mount points by reverse order
	for i := len(g.mountInfos) - 1; i >= 0; i-- {
		defaultCleanFnGenerator(g.mountInfos[i].dstPath, g.mountInfos[i].pid, g.mountInfos[i].mountType)(kill)
	}

	return nil
}

func (d *gocryptfsDriver) Features() image.DriverFeature {
	var features image.DriverFeature
	if d.gocryptfsFeature.gocryptfsPath != "" && d.gocryptfsFeature.squashfusePath != "" {
		features |= image.ImageFeature
	}

	return features
}

func (d *gocryptfsDriver) Mount(params *image.MountParams, mfunc image.MountFunc) error {
	if params.Filesystem != "gocryptfs" {
		return fmt.Errorf("filesystem type should be 'gocryptfs'")
	}
	g := &d.gocryptfsFeature
	return g.Mount(params, mfunc, d.cmdPrefix)
}

func (d *gocryptfsDriver) Start(params *image.DriverParams, containerPid int) error {
	if containerPid != 0 {
		// Running in hybrid setuid-fakeroot mode
		// Need any subcommand to first enter the container's
		//  user namespace
		nsenter, err := bin.FindBin("nsenter")
		if err != nil {
			return fmt.Errorf("failed to find nsenter: %v", err)
		}
		d.cmdPrefix = []string{
			nsenter,
			fmt.Sprintf("--user=/proc/%d/ns/user", containerPid),
			"-F",
		}
	}
	return nil
}

func (d *gocryptfsDriver) Stop(target string) error {
	if err := d.gocryptfsFeature.stop(target, true); err != nil {
		return err
	}
	return nil
}

func (d *gocryptfsDriver) GetDriverName() string {
	return gocryptfsDriverName
}

func CheckMountInfo(path string, ch chan error) {
	iter := 0
	for {
		ok, err := mountPkg.Mounted(path)
		if ok {
			ch <- nil
			break
		}
		if err != nil {
			ch <- err
			break
		}
		time.Sleep(1 * time.Second)
		iter++
		if iter >= 10 {
			ch <- fmt.Errorf("timeout to check mount info for target path: %s, timeout limit: %d s", path, iter)
			break
		}
	}
}

func GetGocryptfsPid(substr string) (int, error) {
	d, err := os.Open("/proc")
	if err != nil {
		return -1, err
	}
	defer d.Close()
	for {
		names, err := d.Readdirnames(10)
		if err == io.EOF {
			break
		}
		if err != nil {
			return -1, err
		}

		for _, name := range names {
			// We only care if the name starts with a numeric
			if name[0] < '0' || name[0] > '9' {
				continue
			}

			// From this point forward, any errors we just ignore, because
			// it might simply be that the process doesn't exist anymore.
			pid, err := strconv.ParseInt(name, 10, 0)
			if err != nil {
				continue
			}

			content, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
			if err != nil {
				return -1, err
			}
			if strings.Contains(string(content), substr) {
				return int(pid), nil
			}
		}
	}

	return -1, fmt.Errorf("could not find any process containing the substr: %s", substr)
}

func KillProcess(pid int) error {
	err := syscall.Kill(pid, syscall.SIGTERM)
	if err != nil {
		// child process not exit
		if err.(syscall.Errno) == syscall.ECHILD {
			return nil
		}
		return fmt.Errorf("send SIGTERM signal to process: %d encounters error: %v", pid, err)
	}

	var ws syscall.WaitStatus
	wpid, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, nil)
	if err != nil {
		// child process not exit
		if err.(syscall.Errno) == syscall.ECHILD {
			return nil
		}
		return fmt.Errorf("could not retrieve the process status for pid: %d, err: %v", pid, err)
	}

	if wpid != 0 {
		return fmt.Errorf("process pid: %d exited with status: %v", pid, ws.ExitStatus())
	}
	return nil
}

func InitGocryptfsDriver(register bool, fileconf *apptainerconf.File, desiredFeatures image.DriverFeature) error {
	var gocryptfsFeature gocryptfsFeature
	gocryptfsFeature.init("gocryptfs", "use gocryptfs", desiredFeatures&image.ImageFeature)
	fileconf.ImageDriver = gocryptfsDriverName
	if register {
		sylog.Debugf("register image driver: %s in suid mode", fileconf.ImageDriver)
		return image.RegisterDriver(gocryptfsDriverName, &gocryptfsDriver{gocryptfsFeature, []string{}})
	}

	return nil
}
