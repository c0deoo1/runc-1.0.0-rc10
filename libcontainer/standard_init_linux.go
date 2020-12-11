// +build linux

package libcontainer

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall" //only for Exec

	"github.com/opencontainers/runc/libcontainer/apparmor"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/keys"
	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/selinux/go-selinux/label"
	"github.com/pkg/errors"

	"golang.org/x/sys/unix"
)

type linuxStandardInit struct {
	pipe          *os.File //用于父子进程通信
	consoleSocket *os.File //用于虚拟终端
	parentPid     int      //父进程PID
	fifoFd        int
	config        *initConfig //父进程传递过来的配置信息
}

func (l *linuxStandardInit) getSessionRingParams() (string, uint32, uint32) {
	var newperms uint32

	if l.config.Config.Namespaces.Contains(configs.NEWUSER) {
		// With user ns we need 'other' search permissions.
		newperms = 0x8
	} else {
		// Without user ns we need 'UID' search permissions.
		newperms = 0x80000
	}

	// Create a unique per session container name that we can join in setns;
	// However, other containers can also join it.
	return fmt.Sprintf("_ses.%s", l.config.ContainerId), 0xffffffff, newperms
}

func (l *linuxStandardInit) Init() error {
	//GORoutine锁定一个线程
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !l.config.Config.NoNewKeyring {
		if err := label.SetKeyLabel(l.config.ProcessLabel); err != nil {
			return err
		}
		defer label.SetKeyLabel("")
		ringname, keepperms, newperms := l.getSessionRingParams()

		// Do not inherit the parent's session keyring.
		if sessKeyId, err := keys.JoinSessionKeyring(ringname); err != nil {
			// If keyrings aren't supported then it is likely we are on an
			// older kernel (or inside an LXC container). While we could bail,
			// the security feature we are using here is best-effort (it only
			// really provides marginal protection since VFS credentials are
			// the only significant protection of keyrings).
			//
			// TODO(cyphar): Log this so people know what's going on, once we
			//               have proper logging in 'runc init'.
			if errors.Cause(err) != unix.ENOSYS {
				return errors.Wrap(err, "join session keyring")
			}
		} else {
			// Make session keyring searcheable. If we've gotten this far we
			// bail on any error -- we don't want to have a keyring with bad
			// permissions.
			if err := keys.ModKeyringPerm(sessKeyId, keepperms, newperms); err != nil {
				return errors.Wrap(err, "mod keyring permissions")
			}
		}
	}

	//初始化网络接口，RUNC目前只支持创建loopback接口
	if err := setupNetwork(l.config); err != nil {
		return err
	}
	//初始化路由配置
	if err := setupRoute(l.config.Config); err != nil {
		return err
	}

	label.Init()
	//初始化文件系统，进行相关的挂载操作
	if err := prepareRootfs(l.pipe, l.config); err != nil {
		return err
	}
	// Set up the console. This has to be done *before* we finalize the rootfs,
	// but *after* we've given the user the chance to set up all of the mounts
	// they wanted.
	if l.config.CreateConsole {
		if err := setupConsole(l.consoleSocket, l.config, true); err != nil {
			return err
		}
		if err := system.Setctty(); err != nil {
			return errors.Wrap(err, "setctty")
		}
	}

	// Finish the rootfs setup.
	if l.config.Config.Namespaces.Contains(configs.NEWNS) {
		if err := finalizeRootfs(l.config.Config); err != nil {
			return err
		}
	}

	if hostname := l.config.Config.Hostname; hostname != "" {
		if err := unix.Sethostname([]byte(hostname)); err != nil {
			return errors.Wrap(err, "sethostname")
		}
	}
	if err := apparmor.ApplyProfile(l.config.AppArmorProfile); err != nil {
		return errors.Wrap(err, "apply apparmor profile")
	}

	for key, value := range l.config.Config.Sysctl {
		if err := writeSystemProperty(key, value); err != nil {
			return errors.Wrapf(err, "write sysctl key %s", key)
		}
	}
	for _, path := range l.config.Config.ReadonlyPaths {
		if err := readonlyPath(path); err != nil {
			return errors.Wrapf(err, "readonly path %s", path)
		}
	}
	for _, path := range l.config.Config.MaskPaths {
		if err := maskPath(path, l.config.Config.MountLabel); err != nil {
			return errors.Wrapf(err, "mask path %s", path)
		}
	}
	pdeath, err := system.GetParentDeathSignal()
	if err != nil {
		return errors.Wrap(err, "get pdeath signal")
	}
	if l.config.NoNewPrivileges {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return errors.Wrap(err, "set nonewprivileges")
		}
	}
	// Tell our parent that we're ready to Execv. This must be done before the
	// Seccomp rules have been applied, because we need to be able to read and
	// write to a socket.
	// 通知父进程子进程初始化完成，发送procReady，等待procRun信号
	if err := syncParentReady(l.pipe); err != nil {
		return errors.Wrap(err, "sync ready")
	}
	if err := label.SetProcessLabel(l.config.ProcessLabel); err != nil {
		return errors.Wrap(err, "set process label")
	}
	defer label.SetProcessLabel("")
	// Without NoNewPrivileges seccomp is a privileged operation, so we need to
	// do this before dropping capabilities; otherwise do it as late as possible
	// just before execve so as few syscalls take place after it as possible.
	if l.config.Config.Seccomp != nil && !l.config.NoNewPrivileges {
		if err := seccomp.InitSeccomp(l.config.Config.Seccomp); err != nil {
			return err
		}
	}
	if err := finalizeNamespace(l.config); err != nil {
		return err
	}
	// finalizeNamespace can change user/group which clears the parent death
	// signal, so we restore it here.
	if err := pdeath.Restore(); err != nil {
		return errors.Wrap(err, "restore pdeath signal")
	}
	// Compare the parent from the initial start of the init process and make
	// sure that it did not change.  if the parent changes that means it died
	// and we were reparented to something else so we should just kill ourself
	// and not cause problems for someone else.
	if unix.Getppid() != l.parentPid {
		return unix.Kill(unix.Getpid(), unix.SIGKILL)
	}
	// Check for the arg before waiting to make sure it exists and it is
	// returned as a create time error.
	name, err := exec.LookPath(l.config.Args[0])
	if err != nil {
		return err
	}
	// Close the pipe to signal that we have completed our init.
	l.pipe.Close()
	// Wait for the FIFO to be opened on the other side before exec-ing the
	// user process. We open it through /proc/self/fd/$fd, because the fd that
	// was given to us was an O_PATH fd to the fifo itself. Linux allows us to
	// re-open an O_PATH fd through /proc.
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", l.fifoFd), unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return newSystemErrorWithCause(err, "open exec fifo")
	}
	// 阻塞模式，只有读取端调用了Read才会返回
	// 通过这种方式可以先Create容器，之后再Start
	//       If a process attempts to read from an empty pipe, then read(2) will
	//       block until data is available.  If a process attempts to write to a
	//       full pipe (see below), then write(2) blocks until sufficient data has
	//       been read from the pipe to allow the write to complete.  Nonblocking
	//       I/O is possible by using the fcntl(2) F_SETFL operation to enable the
	//       O_NONBLOCK open file status flag.
	// TODO 抓下堆栈验证一下确实是阻塞在这里？
	if _, err := unix.Write(fd, []byte("0")); err != nil {
		return newSystemErrorWithCause(err, "write 0 exec fifo")
	}
	// Close the O_PATH fifofd fd before exec because the kernel resets
	// dumpable in the wrong order. This has been fixed in newer kernels, but
	// we keep this to ensure CVE-2016-9962 doesn't re-emerge on older kernels.
	// N.B. the core issue itself (passing dirfds to the host filesystem) has
	// since been resolved.
	// https://github.com/torvalds/linux/blob/v4.9/fs/exec.c#L1290-L1318
	unix.Close(l.fifoFd)
	// Set seccomp as close to execve as possible, so as few syscalls take
	// place afterward (reducing the amount of syscalls that users need to
	// enable in their seccomp profiles).
	if l.config.Config.Seccomp != nil && l.config.NoNewPrivileges {
		if err := seccomp.InitSeccomp(l.config.Config.Seccomp); err != nil {
			return newSystemErrorWithCause(err, "init seccomp")
		}
	}
	//这里执行用户配置的进程，此时进程的命名空间都已经初始化好了
	if err := syscall.Exec(name, l.config.Args[0:], os.Environ()); err != nil {
		return newSystemErrorWithCause(err, "exec user process")
	}
	return nil
}
