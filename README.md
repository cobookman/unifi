# Unifi API

A very basic Unifi API client written in golang.

Right now only does 2 things, login and authorize a given MAC Address for Guest wifi.

To run unit tests simply provide a valid username & credential and run with access to a Ubiquiti cloudkey running at 192.168.1.1 (aka local network):
```
$ user="<YOUR USERNAME>" pass="<YOUR PASSWORD>" go test
```


