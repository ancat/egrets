package main

import (
    egrets "github.com/ancat/egrets/src"
)

func main() {
    ebpf_binary := "ebpf/rdns.o"
    egrets.Main(ebpf_binary)
}
