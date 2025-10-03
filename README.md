# dnskip
A simple Golang DoT proxy using TRS.

## Usage

### Run
```bash
go run -ldflags "-checklinkname=0" main.go
```

### Build
```bash
go build -ldflags "-s -w -checklinkname=0" -trimpath -o dnskip main.go
```
