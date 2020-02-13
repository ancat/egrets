package egrets

import (
        "fmt"
        "net"
)

/*
    Use a binary search tree to quickly find an IP address in the list of seen
    DNS responses. This is faster than the built in hash table for the first few
    thousand inserts but then becomes slower. The difference between the two is
    measured in the nanoseconds the whole time, so I'm going to stop pretending
    like I'm a computer scientist for now
*/
type IpNode struct {
    left  *IpNode
    right *IpNode
    Data  int
    Tags []string
}

func ipv4toint(ip_address net.IP) int {
    var a,b,c,d int
    fmt.Sscanf(ip_address.String(), "%d.%d.%d.%d", &a,&b,&c,&d)
    return (a<<24) | (b<<16) | (c<<8) | (d<<0)
}

// computer scientist roleplay time
// use a trie
func tag_exists(haystack []string, needle string) bool {
    for _, candidate := range haystack {
        if candidate == needle {
            return true
        }
    }

    return false
}

func (t* IpNode) insert(data int, tags []string) {
    if data == t.Data {
        if len(t.Tags) == 0 {
            t.Tags = make([]string, 0)
            t.Tags = append(t.Tags,tags...)
        } else if !tag_exists(t.Tags, tags[0]) {
            // `tags []string` should really be just a string
            t.Tags = append(t.Tags,tags...)
        }
    } else if data > t.Data {
        if t.right != nil {
            t.right.insert(data, tags)
        } else {
            t.right = &IpNode{}
            t.right.Data = data
            t.right.Tags = tags
        }
    } else if data < t.Data {
        if t.left != nil {
            t.left.insert(data, tags)
        } else {
            t.left = &IpNode{}
            t.left.Data = data
            t.left.Tags = tags
        }
    }
}

func (t* IpNode) dump() {
    left_int := 0
    right_int := 0

    if t.left != nil {
        left_int = t.left.Data
    }

    if t.right != nil {
        right_int = t.right.Data
    }

    if left_int == 0 && right_int == 0 {
    } else {
        fmt.Printf("     %d [%+v]\n", t.Data, t.Tags)
        fmt.Printf("%d <--^--> %d\n", left_int, right_int)
    }

    if t.left != nil {
        t.left.dump()
    }

    if t.right != nil {
        t.right.dump()
    }
}

func (t* IpNode) get_tags(data int) []string {
    var tags_left []string
    var tags_right []string

    if t.Data == data {
        return t.Tags
    }

    if t.left != nil {
        tags_left = t.left.get_tags(data)
    }

    if t.right != nil {
        tags_right = t.right.get_tags(data)
    }

    if tags_left != nil {
        return tags_left
    } else if tags_right != nil {
        return tags_right
    }

    return nil
}
