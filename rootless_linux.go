// +build linux

package main

import (
	"os"

	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/urfave/cli"
)

//rootless的机制需要研究一下
func shouldUseRootlessCgroupManager(context *cli.Context) (bool, error) {
	if context != nil {
		b, err := parseBoolOrAuto(context.GlobalString("rootless"))
		if err != nil {
			return false, err
		}
		// nil b stands for "auto detect"
		if b != nil {
			return *b, nil
		}

		if context.GlobalBool("systemd-cgroup") {
			return false, nil
		}
	}
	if os.Geteuid() != 0 {
		return true, nil
	}
	if !system.RunningInUserNS() {
		// euid == 0 , in the initial ns (i.e. the real root)
		return false, nil
	}
	// euid = 0, in a userns.
	// As we are unaware of cgroups path, we can't determine whether we have the full
	// access to the cgroups path.
	// Either way, we can safely decide to use the rootless cgroups manager.
	return true, nil
}

func shouldHonorXDGRuntimeDir() bool {
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		return false
	}
	// Geteuid 获取有效的用户识别码
	// 有效的用户识别码用来决定进程执行的权限, 借由此改变此值, 进程可以获得额外的权限.
	// 倘若执行文件的setID 位已被设置, 该文件执行时, 其进程的euid值便会设成该文件所有者的uid.
	// 例如, 执行文件/usr/bin/passwd 的权限为-r-s--x--x, 其s 位即为setID(SUID)位
	// 而当任何用户在执行passwd 时其有效的用户识别码会被设成passwd 所有者的uid 值, 即root 的uid 值(0).
	if os.Geteuid() != 0 {
		return true
	}
	// 通过/proc/self/uid_map的映射来粗略检测是否在User NS中
	if !system.RunningInUserNS() {
		// euid == 0 , in the initial ns (i.e. the real root)
		// in this case, we should use /run/runc and ignore
		// $XDG_RUNTIME_DIR (e.g. /run/user/0) for backward
		// compatibility.
		return false
	}
	// euid = 0, in a userns.
	u, ok := os.LookupEnv("USER")
	return !ok || u != "root"
}
