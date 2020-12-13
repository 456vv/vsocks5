# vsocks5 [![Build Status](https://travis-ci.org/456vv/vsocks5.svg?branch=master)](https://travis-ci.org/456vv/vsocks5)
golang socks5, ssh proxy server, 代理服务器

命令行：
-----------------------------------
      -addr string
            代理服务器地 (format "0.0.0.0:1080")
      -dataBufioSize int
            代理数据交换缓冲区大小，单位字节 (default 10240)
      -log string
            日志文件(默认留空在控制台显示日志)  (format "./vsocks5.txt")
      -proxy string
            代理服务器的上级代理IP地址 (format "https://admin:admin@11.22.33.44:8888" or "ssh://admin:admin@11.22.33.44:22")
      -pwd string
            密码
      -user string
            用户名

    命令行例子：vsocks5 -addr 0.0.0.0:1080
