package main

import (
    "os"

    egrets "github.com/ancat/egrets/src"
)

func main() {
    ebpf_binary := "ebpf/rdns.o"
    matcher := ".*"

    if len(os.Args) > 2 {
        ebpf_binary = os.Args[2]
    }

    if len(os.Args) > 1 {
        matcher = os.Args[1]
    }
    egrets.Main(ebpf_binary, matcher)
}
