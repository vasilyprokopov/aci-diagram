# ACI Diagram generator

This is a simple tool to connect to a Cisco ACI Application Policy Infrastructure Controller using the [acitoolkit](http://github.com/datacenter/acitoolkit) library, interrogate the configuration and generate logical diagrams. 

##Usage

The usage is simple - the login (username), password and URL arguments are required. By default the tool will include all tenants in the diagram, but you can restrict this to a subset of tenants using the `-t` argument.


```
usage: diagram.py [-h] -l LOGIN -p PASSWORD -u URL -o OUTPUT
                  [-t [TENANTS [TENANTS ...]]] [-v]

Generate logical diagrams of a running Cisco ACI Application Policy
Infrastructure Controller

optional arguments:
  -h, --help            show this help message and exit
  -l LOGIN, --login LOGIN
                        Login for authenticating to APIC
  -p PASSWORD, --password PASSWORD
                        Password for authenticating to APIC
  -u URL, --url URL     URL for connecting to APIC
  -o OUTPUT, --output OUTPUT
                        Output file for diagram - e.g. out.png, out.jpeg
  -t [TENANTS [TENANTS ...]], --tenants [TENANTS [TENANTS ...]]
                        Tenants to include when generating diagrams
  -v, --verbose         show verbose logging information
```

