.PHONY: all build clean

all: build

gen:
	go generate ./...

build: gen
	go build -o ebpf-task-iter

clean:
	rm -f ebpf-task-iter
	rm -f cputime_*.go
	rm -f *.o
