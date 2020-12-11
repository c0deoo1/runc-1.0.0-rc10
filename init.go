package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/logs"

	// 这里导入了nsenter这个包，这个包中的init函数会调用nsexec()
	// C 语言却可以通过 gcc 的 扩展 __attribute__((constructor)) 来实现程序启动前执行特定代码
	// 注意这里放在init中，此时Go runtime还没有启动多个线程，所以目前仅仅只有一个线程
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
		//获取到父进程传递过来的参数
		level := os.Getenv("_LIBCONTAINER_LOGLEVEL")
		logLevel, err := logrus.ParseLevel(level)
		if err != nil {
			panic(fmt.Sprintf("libcontainer: failed to parse log level: %q: %v", level, err))
		}

		err = logs.ConfigureLogging(logs.Config{
			//获取到父进程传递过来的日志管道
			LogPipeFd: os.Getenv("_LIBCONTAINER_LOGPIPE"),
			LogFormat: "json",
			LogLevel:  logLevel,
		})
		if err != nil {
			panic(fmt.Sprintf("libcontainer: failed to configure logging: %v", err))
		}
		//这一行日志实际上会输出到父进程的管道当中
		logrus.Debug("child process in init()")
	}
}

var initCommand = cli.Command{
	Name:  "init",
	Usage: `initialize the namespaces and launch the process (do not call it outside of runc)`,
	Action: func(context *cli.Context) error {
		factory, _ := libcontainer.New("")
		// runc create 会创建一个进程来执行runc init
		// runc init的 作用就是通过一系列的初始化来容器进程的namespace等资源
		// 执行的过程中，会多次与runc start之间通过管道来交互，比如传递配置文件、同步初始化进度等等
		// 最终初始化完成之后，runc init进程会等待执行用户指定的初始化进程
		if err := factory.StartInitialization(); err != nil {
			// as the error is sent back to the parent there is no need to log
			// or write it to stderr because the parent process will handle this
			os.Exit(1)
		}
		panic("libcontainer: container init failed to exec")
	},
}
