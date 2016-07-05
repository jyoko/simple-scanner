# Simple Scanner

Not as simple anymore -- slowly building a fully-featured port scanner with various enumeration features in Node!  Warning: This can easily be a **NOISY** scan and cause network issues or upset a host (and the usual scanner/open source caveats).

## Usage

Requires modern Node (4+?), uses template strings, arrow functions, `class`, and default params (possibly others, but modern v8 compatible). Note that if you want to use the UDP scan and other experimental scanning techniques that require raw sockets, you may need to have elevated privileges. If you're using nvm/n your system version of Node (used by sudo) may not support these features, type `which node` and use that one directly.

```sh
$ npm install
```

For [request](https://github.com/request/request) used in WPScanner, [commander](https://github.com/tj/commander.js) used in the CLI (simple-scanner.js), and [raw-socket](https://github.com/stephenwvickers/node-raw-socket) for the UDP scan and other incoming types.

```sh
$ ./simple-scanner.js scanthissite.com
```

Full help text:

```
  Usage: simple-scanner <host> [options]

  Options:

    -h, --help               output usage information
    -V, --version            output the version number
    -p, --ports [22,80,443]  Enter a comma-delimited list of port numbers (will override range)
    -r, --range [1-1000]     Enter a range of ports (default: 1-1000)
    -i, --interval [1]       For use with --range, enter an interval (default: 1)
    -m, --maxParallel [12]   Max parallel connections
    -w, --wordpress          Do only wordpress probe on indicated ports
    -b, --baseuri [wp]       URI to use as base for wordpress probe
    -U, --udp                Do only UDP scan - WARNING: experimental, slow, likely requires root
    -S, --syn                Do only SYN (half-open) scan - WARNING: experimental, in-progress
    -C, --connect            Do only connect scan
    -v, --verbose            More status updates

  Default scan is a TCP Connect on ports 1-1000 using Node's Net library,
  any open ports that do not respond with a banner will be probed for an HTTP
  server and Wordpress instances.

  Other scan types are experimental and may not work as-intended on all
  operating systems.

```

## Scanning Methods

The default scan first runs a connect scan (using Node's built-in net) over the entire range of ports and saves any banners sent from the server during this probe. From the initial scan, any open ports that _did not_ send a banner will be probed via HTTP(S) for Wordpress markers.

### Connect -C

Uses Node's Net library to attempt to connect to specified ports on the host. Reports any open ports and banners sent.

Code in `lib/PortScanner.js`

### Wordpress -w

Uses request to probe for HTTP(S) servers and attempts to enumerate a Wordpress instance via:

* Meta generator tag
* "Powered By Wordpress"
* Comment containing "Wordpress" (mostly plugins)
* wp-strings, default reference locations to content files
* the existence of /wp-admin or /wp-login.php
* a license.txt or readme.html containing the string "wordpress"

Code in `lib/WPProbe.js`

### UDP -U

**Requires privileged user**

Uses Node's built-in dgram to send UDP datagrams and listen for responses and raw-socket to listen for ICMP response codes. This is ripped directly from [nmap's -sU scan description](https://nmap.org/book/man-port-scanning-techniques.html).

`lib/ICMPWatcher` contains the code that looks for relevant ICMP replies, `lib/UDPScanner` sets up the dgram listener and sends the packets.

### SYN (half-open) -S

**Requires privileged user**

The standard half-open SYN scan - it doesn't complete the handshake. No ICMP response filtering yet and issues scanning a loopback address, but working. Feel free to crank up parallel connections for a faster scan, haven't gotten into setting saner defaults yet (or testing a high load).

`lib/SYNScanner` does the scan logic, but the real magic is in `TCPSocket` and `TCPutils`. The former is the beginning of a generic TCP class for general use and the latter builds/reads TCP segments.

## Fingerprinting & Detection 

The methods used are extremely basic but mostly effective.

Any self-identifying server banner will be reported and any Server HTTP header response is saved. Additionally, the WPScanner uses an iPhone user agent to avoid simple bot detection.

More, better detection will be incoming along with the scanning methods we've all come to know and love.

## Known Issues

* No support for scanning multiple hosts
* No backoff and retries, sometimes leading to bad results (imagine throwing rocks to see if someone left any windows open)
* Unknown cross-platform support for raw-socket

## Contributing

Hopefully the code itself is readable and commented, the main architectural thing to be aware of is all scan types should inherit from the base class in `lib/Scanner`. This lets them be EventEmitters and lets you focus on writing a scan from the perspective of a single check (as well as making the interface to the UI consistent). 

If the method itself is complicated (or has involved parts) by all means move that to a standalone section and write an XXScaner to mediate.
