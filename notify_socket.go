// +build linux

package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type notifySocket struct {
	socket     *net.UnixConn
	host       string
	socketPath string
}

func newNotifySocket(context *cli.Context, notifySocketHost string, id string) *notifySocket {
	if notifySocketHost == "" {
		return nil
	}

	root := filepath.Join(context.GlobalString("root"), id)
	path := filepath.Join(root, "notify.sock")
	logrus.Infof("notifySocketHost：%v,socketPath:%v\n", notifySocketHost, path)

	notifySocket := &notifySocket{
		socket:     nil,
		host:       notifySocketHost,
		socketPath: path,
	}

	return notifySocket
}

func (s *notifySocket) Close() error {
	return s.socket.Close()
}

// If systemd is supporting sd_notify protocol, this function will add support
// for sd_notify protocol from within the container.
func (s *notifySocket) setupSpec(context *cli.Context, spec *specs.Spec) {
	// 这里我的理解是，给容器挂载一个host目录，root/id/notify.sock目录
	// 如果容器内的进程使用了sd_notify协议，则最终消息会转发到root/id/notify.sock套接字
	// TODO 需要将相关的透传给host上的套接字？待实践确认
	mount := specs.Mount{Destination: s.host, Source: s.socketPath, Options: []string{"bind"}}
	spec.Mounts = append(spec.Mounts, mount)
	spec.Process.Env = append(spec.Process.Env, fmt.Sprintf("NOTIFY_SOCKET=%s", s.host))
}

func (s *notifySocket) setupSocket() error {
	addr := net.UnixAddr{
		Name: s.socketPath,
		Net:  "unixgram",
	}

	socket, err := net.ListenUnixgram("unixgram", &addr)
	if err != nil {
		return err
	}

	err = os.Chmod(s.socketPath, 0777)
	if err != nil {
		socket.Close()
		return err
	}

	s.socket = socket
	return nil
}

// pid1 must be set only with -d, as it is used to set the new process as the main process
// for the service in systemd
func (s *notifySocket) run(pid1 int) {
	buf := make([]byte, 512)
	notifySocketHostAddr := net.UnixAddr{Name: s.host, Net: "unixgram"}
	// 这个client用于将sd_notify信息传递给host
	client, err := net.DialUnix("unixgram", nil, &notifySocketHostAddr)
	if err != nil {
		logrus.Error(err)
		return
	}
	for {
		// 接收来自容器中下发的sd_notify消息
		r, err := s.socket.Read(buf)
		if err != nil {
			break
		}
		var out bytes.Buffer
		for _, line := range bytes.Split(buf[0:r], []byte{'\n'}) {
			if bytes.HasPrefix(line, []byte("READY=")) {
				logrus.Infof("notifySocket Got:%v,pid1:%v\n", string(line), pid1)
				_, err = out.Write(line)
				if err != nil {
					return
				}

				_, err = out.Write([]byte{'\n'})
				if err != nil {
					return
				}

				_, err = client.Write(out.Bytes())
				if err != nil {
					return
				}

				// now we can inform systemd to use pid1 as the pid to monitor
				if pid1 > 0 {
					// 将容器内部的pid也发出去，方便systemd监控
					// 这里后续需要研究一下systemd的工作流程！
					newPid := fmt.Sprintf("MAINPID=%d\n", pid1)
					client.Write([]byte(newPid))
				}
				return
			}
		}
	}
}
