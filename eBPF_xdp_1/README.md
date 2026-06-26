# Solution 1 (dropping packets to a particular port number system wide)

### Usage - 
- First generate the go bindings and build the go code (see README of this repository)
- After that, use - sudo ./loader <interface_name> <port_number> (root previleges are necessary)
- The eBPF program will drop packets on the specified interface and port number
