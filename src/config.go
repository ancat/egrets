package egrets

import (
    "fmt"
    "io/ioutil"

    "gopkg.in/yaml.v2"
)

type EgretsConfig struct {
    Container_Metadata bool
    Use_Classic_BPF bool
    Allow []string
    Container_Allow map[string][]string
}

func LoadEgretsConfig(filename string) *EgretsConfig {
    config := EgretsConfig{}
    config_bytes, err := ioutil.ReadFile(filename)

    if err != nil {
        panic(err)
    }

    err = yaml.Unmarshal([]byte(config_bytes), &config)
    if err != nil {
        panic(err)
    }

    return &config
}

func DumpConfig(config *EgretsConfig) {
    if config.Container_Metadata {
        fmt.Printf("we will fetch container metadata\n")
    } else {
        fmt.Printf("we will not fetch container metadata")
    }

    for _, hostname := range config.Allow {
        fmt.Printf("allowed hosts: %s\n", hostname)
    }

    for key, hostnames := range config.Container_Allow {
        fmt.Printf("key=%s\n", key)
        for _, container_hostname := range hostnames {
            fmt.Printf("%s => %s\n", key, container_hostname)
        }
    }
}
