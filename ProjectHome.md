A light-weight, self-contained, secure login package. It's conceptually similar to SSH, but with the following:

- it supports an EKE-like protocol for identity based authentication (see IEEE P1363.3), preventing man-in-the-middle attacks.

- the server supports proxying, so the client can connect through any number of aeke servers en route to the final destination.

- the client understands the HTTP CONNECT protocol, allowing tunneling through restrictive web proxies.

- port-knocking is supported (the client can 'knock' on a number of ports on the remote / intermediate host prior to attempting to connect)

- the server is light-weight: only one process is forked per connection (and that process runs the shell / command prompt).

- encryption is end-to-end: compromised intermediate / proxying servers can not decode information intended for the final destination.

- Supported under MacOS X, Linux, BSD. Windows support via cygwin.