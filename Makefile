generate: 
	go generate ./...

build-ebpf-tcprtt:
	go build -ldflags "-s -w" -o ebpf-tcprtt cmd/main.go

build: generate build-ebpf-tcprtt

clean:
	rm -f ebpf-tcprtt
	rm -f internal/probe/probe_bpf*.go
	rm -f internal/probe/probe_bpf*.o