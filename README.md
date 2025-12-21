# Hyper-C
Hyper-C is an ultra-minimalistic static HTTP/S server.

## Usage
```sh
./hyprc d DIR p PORT [s SPORT c CERTFILE k KEYFILE] [hqQv] [b /page1:/page2:...]
```
Hyper-C executable serves the contents of the directory DIR at the insecure 
(HTTP) port PORT and/or at the secure port SPORT with certificate file CERTFILE
and private key file KEYFILE.

Several options are available to modify the behaviour of the server. `h` prints
the usage. `q` (`quiet`) sets the logging mode to error-only, while `qq` (`silent`)
disables output altogether. `v` sets the logging mode to debug with additional
verbosity. `b` allows to specify a number of disallowed resources within the
directory for which the server will return 404 Not Found.
