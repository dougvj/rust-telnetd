# rust-telnetd

## Simple Telnet Server written in Rust.

This was written as a simple exercise, do not use this except for local testing
and learning.

Implements basic telnet capability, but does not properly parse the linemode
option for setting special characters and other terminal handling

## Usage:

```
Usage:
  rust-telnetd [OPTIONS]

Optional arguments:
  -h,--help             Show this help message and exit
  -p,--port PORT        Port to listen on
  -b,--bind BIND        Address to bind to
  -c,--command COMMAND  Login command to run. If not specified, the system will
                        search for the login binary in the path
```
