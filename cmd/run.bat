cd /D ./main
set GOPROXY=https://goproxy.cn,https://mirrors.aliyun.com/goproxy/,https://gocenter.io,https://proxy.golang.org,https://goproxy.io,https://athens.azurefd.net,direct
set GOSUMDB=sum.golang.org

set GOOS=windows
set GOARCH=amd64
go build -o ../bin/vsocks5-win-amd64.exe  -gcflags "-N -l -m"

cd /D ../bin/
vsocks5-win-amd64.exe -addr :1081 -user admin -pwd 123 -proxy "https://127.0.0.1:803"

pause
exit 0