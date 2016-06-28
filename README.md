# Simple Scanner (revised)

Naively identify core server utilities and scan for Wordpress with no dependencies in Node!  Warning: This is a **NOISY** scanner and you can easily cause network issues or get yourself blocked.

## Usage

Requires modern Node (4+?), uses template strings, arrow functions, `class`, and default params (possibly others, but modern v8 compatible).

```sh
$ npm install
```

For [request](https://github.com/request/request) used in WPScanner and [commander](https://github.com/tj/commander.js) used in example-scan.

```sh
$ ./example-scanner.js -h scanthissite.com
```

Full help text:

```sh
  Usage: example-scan [options]

  Options:

    -h, --help               output usage information
    -V, --version            output the version number
    -h, --host <host>        The host to scan
    -p, --ports [22,80,443]  Enter a comma-delimited list of port numbers (will override range)
    -r, --range [1-1000]     Enter a range of ports (default: 1-1000)
    -i, --interval [1]       For use with --range, enter an interval (default: 1)
    -m, --maxParallel [12]   Max parallel connections
    -v, --verbose            More status updates
```

## Scanning Methods

The example script first runs a connect scan (using Node's built-in net) over the entire range of ports and saves any banners sent from the server during this probe. From the initial scan, any open ports that _did not_ send a banner will be probed via HTTP(S) for Wordpress markers.

## Fingerprinting & Detection 

The methods used are extremely basic, but mostly effective.

Any self-identifying server banner will be reported and the initial Server HTTP header response is saved to avoid false information from later probes. Additionally, the WPScanner uses an iPhone user agent to avoid simple bot detection.

WPScanner attempts to confirm a Wordpress server via:

* Meta generator tag
* "Powered By Wordpress"
* Comment containing "Wordpress" (mostly plugins)
* wp-strings, default reference locations to content files
* the existence of /wp-admin or /wp-login.php
* a license.txt or readme.html containing the string "wordpress"

In the next update there will be more detection methods and the WPScanner will be cleaned up, the original didn't transfer well.

## Known Issues

* No support for scanning multiple hosts
* No backoff and retries, sometimes leading to bad results (imagine throwing rocks to see if someone left any windows open)

