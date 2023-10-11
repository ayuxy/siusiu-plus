package exec

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

func Docker(name string, args []string) {
	params := append([]string{"run", "--rm", "-it", "--network", "host", name}, args...)
	CmdExec("docker", params...)
}

func CmdExec(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGQUIT)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func(ctx context.Context) {
	LOOP:
		for {
			select {
			case <-ctx.Done():
				break LOOP
			case <-c:
				cmd.Process.Release()
				cmd.Process.Kill()
				break LOOP
			}
		}
	}(ctx)
	if err := cmd.Run(); err != nil {
		logrus.Error("cmd.Run failed,err:", err)
		return
	}
}
