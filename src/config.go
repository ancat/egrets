package egrets

import (
    "fmt"
    "io/ioutil"

    "gopkg.in/yaml.v2"
)

type EgretsStats struct {
    PacketsSeen      int
    QueriesSeen      int
    MissingDns       int
    MissingContainer int
}

type EgretsConfig struct {
    Container_Metadata bool
    Async_Container_Metadata bool
    Use_Classic_BPF bool
    Log_Blocked bool
    Log_Dns bool
    Allow []string
    Trusted_Dns string
    Container_Allow map[string][]string
    Cache_Http bool
    Manual_Packet_Decode bool
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
        fmt.Printf("we will not fetch container metadata\n")
    }

    if config.Log_Blocked {
        fmt.Printf("we will only log blocked requests\n")
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
