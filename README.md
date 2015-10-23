# dd-tcp-rtt

## Requirements
This go package requires the great [gopacket](https://github.com/google/gopacket) - it provides awesome packet decoding and pcap integration in Go.
Unfortunately *gopacket* imposes a restriction on the go version due to some language features such as three-index slices - you will need go >=1.2.
You will also need the *PCAP* library in your system - should be easy to find in any \*NIX-style system in your package manager (apt-get, yum, ports, homebrew, etc). Also available in windows [here](http://www.winpcap.org/) - untested though!:

## Description
This tool aims to passively calculate TCP RTTs between hosts communicating with us. What we do is fairly straightforward, we follow TCP streams active within a certain period of time and estimate the RTT between any outgoing packet with data, and its corresponding TCP acknowledgement. Because the PCAP library provides timestamping we are able to compute with a realtive high degree of precision the difference in time between these two events. To protect ourselves from duplicates and breaks in
communication we use the TS and TSecr values in the TCP Options, if available, to differentiate between duplicates. For the time being we have chosen to ignore streams in which our host in not _actively_ participating (ie. just ACKing incoming data) because in that scenario we do not know when the next incoming packet may come - it may not be imminent, there may be breaks in communication - and that would cause reporting inflated RTT values.

## Usage
* Make sure you have cloned [gopacket](https://github.com/google/gopacket) into your `$GOPATH/src`, and have _PCAP_ lib in your system.
* Clone this repo into your `$GOPATH/src`
```bash
cd $GOPATH
go get -v github.com/google/gopacket
go get -v github.com/google/dd_tcp_rtt
go install github.com/Datadog/dd-tcp-rtt
```
* You should now have the executable in `$GOPATH/bin`.
* Have fun!

### Linux tip
You don't need to run this as `root`, you can set CAP_NET_RAW capabilities on the executable - you will need sudo rights to do that though.
```bash
sudo setcap cap_net_raw+ep $GOPATH/bin/dd-tcp-rtt
```
And you're good to go, no need to be *super* anymore!

Note: Please note that you will need your filesystem to have extended security attributes enabled to allow setting _capabilities_ on files. This will normally involve having your kernel built with a configuration enabling `CONFIG_EXT3_FS_SECURITY`, `CONFIG_EXT4_FS_SECURITY`, `CONFIG_REISERFS_FS_SECUIRTY`, etc and `CONFIG_EXT3_FS_XATTR`, `CONFIG_EXT4_FS_XATTR`, `CONFIG_REISERFS_FS_XATTR`, etc - depending on your filesystem. The good news is that Ubuntu/Fedora/Mint kernels are typically
built with these features enabled straight out of the box. Also, you might have to ensure the partition is mounted to enable support xattr.
