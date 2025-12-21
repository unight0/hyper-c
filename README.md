# Hyper-C
Hyper-C is an ultra-minimalistic static HTTP/S server.

## Usage
```sh
./hyprc d DIR p PORT [s SPORT c CERTFILE k KEYFILE] [hqQv] [b /page1:/page2:...]
```
Hyper-C executable serves the contents of the directory DIR at the insecure 
(HTTP) port PORT and/or at the secure (HTTPS) port SPORT with certificate file CERTFILE
and private key file KEYFILE.

Several options are available to modify the behaviour of the server. `h` prints
the usage. `q` (`quiet`) sets the logging mode to error-only, while `qq` (`silent`)
disables output altogether. `v` (`verbose`) sets the logging mode to debug with additional
verbosity. `b` (`blacklist`) allows to specify a number of disallowed resources within the
directory for which the server will return 404 Not Found.

## Compilation
Hyper-C can be easily compiled by going into the source directory and executing
`make`. This will produce an output file called `hyprc`, which can then
be directly used.
