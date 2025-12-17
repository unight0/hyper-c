# Hyper-C
Hyper-C is an ultra-minimalistic static HTTP server.

## Usage
```sh
./hyprc DIR PORT [-hqQ] [-b /page1:/page2:...]
```
Hyper-C executable serves the contents of the directory DIR at the port PORT.
Several options are available to modify the behaviour of the server. `-h` prints
the usage. `-q` sets the loggin mode to error-only, while `-Q` disables output
altogether. `-b` allows to specify a number of disallowed resources within the
directory -- the server will return 404 Not Found (not 403 Forbidden, for
security purposes).
