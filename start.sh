export APP_PORT=:8085
go build
nohup ./GolangKP > output.log 2>&1 &