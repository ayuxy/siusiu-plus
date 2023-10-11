package main

import (
	"log"
	"os"

	"github.com/ayuxy/siusiu-plus/controllers"
	"github.com/ayuxy/siusiu-plus/routers"
	"github.com/abiosoft/ishell"
	"github.com/abiosoft/readline"
)

func main() {
	//1.初始化shell
	shell := ishell.NewWithConfig(&readline.Config{
		Prompt: controllers.GetShellPrompt(),
	})
	//2.初始化路由
	if err := routers.Init(shell); err != nil {
		log.Println("routers.Init failed,err:", err)
		return
	}
	// 当第一个参数为exec时，非交互模式
	if len(os.Args) > 1 && os.Args[1] == "exec" {
		shell.Process(os.Args[2:]...)
	} else {
		//交互模式
		shell.Run()
	}
}
