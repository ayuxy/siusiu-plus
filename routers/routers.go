package routers

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	
	"github.com/ayuxy/ishell-plus/controllers"
	"github.com/ayuxy/ishell-plus/pkg/exec"
	"github.com/abiosoft/ishell"
)

type Command struct {
	*ishell.Cmd
	Tags     []string
	TagHelps map[string]string
}

func contains(slice []string, str string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, str) {
			return true
		}
	}
	return false
}

var TagHelps = map[string]string{ // 定义标签的描述信息
	"recon":    "信息收集",
	"vulnscan": "漏洞扫描",
}

func Init(shell *ishell.Shell) error {

	// dirsearch 目录扫描工具
	dirsearchCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 1,
			Name:  "dirsearch",
			Help:  "信息收集 | 目录扫描 | dirsearch v0.4.3",
			Func: func(c *ishell.Context) {
				// 执行命令的代码
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)	
					return
				}
				//为docker容器挂上代理--env
				//params := append([]string{"run", "--rm", "-it", "--network", "host","-v", currentDir+":/tools/","--env","http_proxy=http://192.168.0.103:7890","-w","/tools/","ayuxy/tools-dirsearch"}, c.Args...)
				params := append([]string{"run", "--rm", "-it", "--network", "host","-v", currentDir+":/tools/", "-w","/tools/","ayuxy/tools-dirsearch"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"recon"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}

	//httpx是一种快速且多功能的HTTP工具包
	httpxCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 2,
			Name:  "httpx",
			Help:  "信息收集 | 快速且多功能的HTTP工具包",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				//params := append([]string{"run", "--rm", "-it", "--network", "host", "-v", currentDir + ":/tools/", "-w", "/tools/", "ayuxy/tools-httpx"}, c.Args...)
				//使用 -i 的话主要是管道符用 比如：./CyberX exec morefind -d -f $input_file -o morefind_result.txt | ./CyberX exec httpx -o domain_result.txt，-it的话会报错
				//但是 -i 不用管道符的时候，使用可能会出现一些问题
				params := append([]string{"run", "--rm", "-i", "--network", "host", "-v", currentDir + ":/tools/", "-w", "/tools/", "ayuxy/tools-httpx"}, c.Args...)				
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"recon"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}


	//urlfinder
	urlfinderCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 3,
			Name:  "urlfinder",
			Help:  "信息收集 | 快速查找隐藏在页面或js中的敏感或未授权api接口",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				params := append([]string{"run", "--rm", "-it", "--network", "host", "-v", currentDir + ":/tools/", "-w", "/tools/", "ayuxy/tools-urlfinder"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"recon"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}


	//ipinfosearch SRC漏洞挖掘信息收集工具
	ipinfosearchCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 4,
			Name:  "ipinfosearch",
			Help:  "信息收集 | SRC资产信息收集 | 域名和ip反查、权重及ipc备案查询",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				params := append([]string{"run", "--rm", "-it", "-v", currentDir + ":/tools/", "ayuxy/tools-ipinfosearch"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"recon"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}

	//domain_search_ip 
	domain_search_ipCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 5,
			Name:  "domain_search_ip",
			Help:  "信息收集 | 域名查询ip",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				params := append([]string{"run", "--rm", "-it", "-v", currentDir + ":/tools/", "ayuxy/tools-domain_search_ip"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"recon"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}

	// oneforall
	oneforallCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 6,
			Name:  "oneforall",
			Help:  "信息收集 | 子域名收集",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				params := append([]string{"run", "--rm", "-it", "-v", currentDir + ":/OneForAll/results", "-w", "/OneForAll/results", "ayuxy/tools-oneforall"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"recon"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}

	// subfinder
	subfinderCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 7,
			Name:  "subfinder",
			Help:  "信息收集 | 子域名收集",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				params := append([]string{"run", "--rm", "-it", "-v", currentDir + ":/tools/", "-w", "/tools/", "ayuxy/tools-subfinder"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"recon"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}

	//scaninfo 端口扫描工具
	scaninfoCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 8,
			Name:  "scaninfo",
			Help:  "信息收集 | 端口扫描 | 扫描速度快准确性也不错",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				params := append([]string{"run", "--rm", "-it", "-v", currentDir + ":/tools/", "-w", "/tools/", "ayuxy/tools-scaninfo"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"recon"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}

	// sqlmap
	sqlmapCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 9,
			Name:  "sqlmap",
			Help:  "漏洞扫描 | sql注入利用工具",
			Func: func(c *ishell.Context) {

				if len(c.Args) > 0 && c.Args[0] == "-edit" {
					// 执行其他 Docker 命令
					params := append([]string{"run", "--rm", "-it", "-v", "sqlmap_data-volume" + ":/sqlmap/", "-e", "TOOL_NAME=sqlmap", "-w", "/sqlmap", "ayuxy/data_container"}, c.Args[1:]...)
					exec.CmdExec("docker", params...)
					return
				}
				
				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}

				params := append([]string{"run", "--rm", "-it", "--network", "host", "-v", "sqlmap_data-volume" + ":/sqlmap-config/", "-v", currentDir + ":/sqlmap-r/","-w", "/sqlmap-r/","ayuxy/tools-sqlmap"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"vulnscan"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}


	// sqlmap 中文版本
	sqlmapcnCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 10,
			Name:  "sqlmapcn",
			Help:  "漏洞扫描 | sql注入利用工具中文版本",
			Func: func(c *ishell.Context) {

				if len(c.Args) > 0 && c.Args[0] == "-edit" {
					// 执行其他 Docker 命令
					params := append([]string{"run", "--rm", "-it", "-v", "sqlmap_data-volume" + ":/sqlmap/", "-e", "TOOL_NAME=sqlmap", "-w", "/sqlmap", "ayuxy/data_container"}, c.Args[1:]...)
					exec.CmdExec("docker", params...)
					return
				}
				
				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}

				params := append([]string{"run", "--rm", "-it", "--network", "host", "-v", "sqlmap_data-volume" + ":/sqlmap-config/", "-v", currentDir + ":/sqlmap-r/","-w", "/sqlmap-r/","ayuxy/tools-sqlmapcn"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"vulnscan"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}


	//xray 1.94 社区高级版
	var token string = "123456" //定义钉钉token
	xrayCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 11,
			Name:  "xray",
			Help:  "漏洞扫描 | xray1.94社区高级版",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}

				if len(c.Args) > 0 && c.Args[0] == "-edit" {
					// 执行其他 Docker 命令
					params := append([]string{"run", "--rm", "-it", "-v", "xray_data-volume" + ":/xray/", "-e", "TOOL_NAME=xray", "-w", "/xray", "ayuxy/data_container"}, c.Args[1:]...)
					exec.CmdExec("docker", params...)
					return
				}

				// 获取 token 参数的值
				if len(c.Args) > 0 && strings.HasPrefix(c.Args[0], "-token=") {
					fmt.Printf("修改前的token值：%v\n", token)
					token = strings.TrimPrefix(c.Args[0], "-token=")
					fmt.Printf("修改后的token值：%v\n", token)
					return
				}

				// 存在 xray 配置文件，则执行如下命令
				params := append([]string{"run", "--rm", "-it", "--network", "host", "-v", "xray_data-volume" + ":/xray-config/", "-v", currentDir + ":/xray-ca-temp/", "-v", currentDir  + ":/report/","-e", "ACCESS_TOKEN=" + token, "ayuxy/tools-xray"}, c.Args...)
				exec.CmdExec("docker", params...)

			},
		},
		Tags:     []string{"vulnscan"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}
	
	
	//nuclei
	nucleiCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 12,
			Name:  "nuclei",
			Help:  "漏洞扫描 | 基于YAML语法模板的快速漏洞扫描器",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				params := append([]string{"run", "--rm", "-it", "--network", "host", "-v", currentDir + ":/tools/", "-v", "nuclei_data-volume"+":/root/", "-w", "/tools/", "ayuxy/tools-nuclei"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"vulnscan"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}
	
		//recon
	reconftwCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 13,
			Name:  "reconftw",
			Help:  "漏洞扫描 | 自动化信息收集工具",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				reportPath := filepath.Join(currentDir, "recon_result")
				params := append([]string{"run", "--rm", "-it", "--network", "host", "-v",reportPath + ":/reconftw/Recon/", "six2dez/reconftw:main"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"vulnscan"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}

	//httpx是一种快速且多功能的HTTP工具包
	morefindCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 14,
			Name:  "morefind",
			Help:  "信息收集 | 分拣ip和域名工具",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				params := append([]string{"run", "--rm", "-it", "--network", "host", "-v", currentDir + ":/tools/", "-w", "/tools/", "ayuxy/tools-morefind"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"recon"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}

	//httpx是一种快速且多功能的HTTP工具包
	wafw00fCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 15,
			Name:  "wafw00f",
			Help:  "信息收集 | WAF检测工具",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				params := append([]string{"run", "--rm", "-it", "--network", "host", "-v", currentDir + ":/usr/src/app", "-w", "/usr/src/app", "ayuxy/tools-wafw00f"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"recon"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}

	//httpx是一种快速且多功能的HTTP工具包
	observer_wardCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 16,
			Name:  "observer_ward",
			Help:  "信息收集 | 社区化指纹识别工具",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				params := append([]string{"run", "--rm", "-it", "--network", "host", "-v", "observer_ward_data-volume:/root/", "-v", currentDir + ":/tools/", "-w", "/tools/", "ayuxy/tools-observer_ward"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"recon"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}		

	jqCmd := &Command{
		Cmd: &ishell.Cmd{
			Order: 16,
			Name:  "jq",
			Help:  "信息收集 | jq",
			Func: func(c *ishell.Context) {

				//获取当前目录
				currentDir, err := os.Getwd()
				if err != nil {
					log.Println("os.Getwd failed,err:", err)
					return
				}
				params := append([]string{"run", "--rm", "-i", "--network", "host", "-v", currentDir + ":/tools/", "-w", "/tools/", "ayuxy/tools-jq"}, c.Args...)
				exec.CmdExec("docker", params...)
			},
		},
		Tags:     []string{"recon"},
		TagHelps: TagHelps, // 将TagHelps作为参数传入
	}

	// 为了让Command命令和对应的Tags标签能够被查询和显示，需要进行添加
	routers := []Command{
		*dirsearchCmd,
		*httpxCmd,
		*urlfinderCmd,
		*scaninfoCmd,
		*sqlmapCmd,
		*sqlmapcnCmd,
		*oneforallCmd,
		*subfinderCmd,
		*xrayCmd,
		*nucleiCmd,
		*ipinfosearchCmd,
		*reconftwCmd,
		*domain_search_ipCmd,
		*morefindCmd,
		*wafw00fCmd,
		*observer_wardCmd,
		*jqCmd,

		// 添加其他的Command和Tags
	}
	// 将所有tag放到一个map中，并且去重
	tagMap := make(map[string]string)
	for _, r := range routers {
		for _, tag := range r.Tags {
			tagMap[tag] = r.TagHelps[tag]
		}
	}

	// 添加帮助工具tagf
	// 查询所有标签Tags，并且调用了tagMap，tagMap里存放了所有的标签，并且经过了去重，并且可以用"tagf 标签名"可以进行查询
	shell.AddCmd(&ishell.Cmd{
		Name:  "tagf",
		Help:  "帮助工具 | 显示标签",
		Order: -4,
		Func: func(c *ishell.Context) {
			if len(c.Args) == 0 {
				c.Printf("\n")
				c.Println("ALL Tags：")
				for tag, tagHelp := range tagMap {
					fmt.Printf("    %-15s", tag)
					if tagHelp != "" {
						fmt.Printf("%s\n", tagHelp)
					} else {
						fmt.Printf("\n")
					}
				}
				c.Printf("\n")
				c.Printf("\n")
				return
			}
			for _, tag := range c.Args {
				found := false
				c.Printf("\n%s Commands：\n", tag)
				for _, r := range routers {
					if contains(r.Tags, tag) {
						c.Printf("    %-20s%s\n", r.Name, r.Help)
						found = true
					}
				}
				if !found {
					c.Println("  Error: Not Found Commands")
				}
				c.Printf("\n")
				c.Printf("\n")
			}
		},

		// 自动补全逻辑
		Completer: func([]string) []string {
			tags := make([]string, 0, len(tagMap))
			for tag := range tagMap {
				tags = append(tags, tag)
			}
			return tags
		},
	})

	// 添加帮助工具tool-helper
	shell.AddCmd(&ishell.Cmd{
		Name:  "tool-helper",
		Help:  "帮助工具 | 获取工具的帮助文档",
		Order: -5,
		Func: func(c *ishell.Context) {
			if len(c.Args) > 0 && c.Args[0] == "-edit" {
				// 执行其他 Docker 命令
				params := append([]string{"run", "--rm", "-it", "-v", "tool-helper_data-volume" + ":/tool-helper/", "-e", "TOOL_NAME=tool-helper", "ayuxy/data_container"}, c.Args[1:]...)
				exec.CmdExec("docker", params...)
				return
			}
			params := append([]string{"run", "--rm", "-it", "-v", "tool-helper_data-volume" + ":/help-config/", "ayuxy/tool-helper"}, c.Args...)
			exec.CmdExec("docker", params...)
		},
	})

	// 添加所有的Command命令
	for _, r := range routers {
		cmd := r.Cmd
		shell.AddCmd(cmd)
	}

	// 未找到命令时
	shell.NotFound(controllers.NotFoundHandler)
	return nil
}
