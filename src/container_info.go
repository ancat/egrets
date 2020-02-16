package egrets

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "net"
    "net/http"
    "strconv"
)

type ContainerInfo struct {
    Hostname string
    IpAddress string
    Image string
}

func GetContainerInfo(pid int) *ContainerInfo {
    cgroup_name := GetCpusetCgroup(pid)

    if cgroup_name == nil || bytes.Equal(cgroup_name, []byte("/")) {
        return nil
    }

    // this makes spotting failures more obvious without having to crash
    // or worse, assume that there's no container info
    if bytes.Equal(cgroup_name, []byte("fail")) {
        cinfo := ContainerInfo{}
        cinfo.Hostname = "fail"
        cinfo.IpAddress = "fail"
        cinfo.Image = "fail"
        return &cinfo
    }

    if bytes.Contains(cgroup_name, []byte("/docker")) {
        container_id := bytes.TrimPrefix(cgroup_name, []byte("/docker/"))
        return GetDockerMetadata(container_id)
    }

    return nil
}

func GetCpusetCgroup(pid int) []byte {
    cgroup_path := fmt.Sprintf("/proc/%d/cgroup", pid)
    cgroup_data, err := ioutil.ReadFile(cgroup_path)
    if err != nil {
        return []byte("fail")
    }

    lines := bytes.Split(cgroup_data, []byte("\n"))
    var cgroup_id int
    var cgroup_controller []byte
    var cgroup_name []byte
    for _, line := range lines {
        if len(line) < 2 {
            break
        }

        parts := bytes.Split(line, []byte(":"))
        cgroup_id, _ = strconv.Atoi(string(parts[0]))
        cgroup_controller = parts[1]
        cgroup_name = parts[2]
        if cgroup_id == 1 || bytes.Equal(cgroup_controller, []byte("cpuset")) {
            return cgroup_name
        }
    }

    return nil
}

func GetDockerMetadata(docker_id []byte) *ContainerInfo {
    unix_path := fmt.Sprintf("http://unix/v1.24/containers/%s/json", string(docker_id))
    httpc := http.Client{
        Transport: &http.Transport{
            DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
                return net.Dial("unix", "/var/run/docker.sock")
            },
        },
    }

    response, err := httpc.Get(unix_path)
    if err != nil {
        panic(err)
    }

    var infoblob map[string]interface{}
    ploop := &bytes.Buffer{}
    io.Copy(ploop, response.Body)
    if err := json.Unmarshal(ploop.Bytes(), &infoblob); err != nil {
        panic(err)
    }

    info := ContainerInfo{}
    info.Hostname = infoblob["Config"].(map[string]interface{})["Hostname"].(string)
    info.Image = infoblob["Config"].(map[string]interface{})["Image"].(string)
    info.IpAddress = infoblob["NetworkSettings"].(map[string]interface{})["IPAddress"].(string)

    return &info
}
