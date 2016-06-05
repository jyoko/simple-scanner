# Simple Scanner

Naively identify core server utilities and scan for Wordpress with no dependencies in Node!  Warning: This is a **NOISY** scanner and you can easily cause network issues or get yourself blocked. Code is short and heavily annotated, take a look.

## Usage

Requires modern Node (4+?), uses template strings & arrow functions.

```sh
node scanner.js scanthissite.com 1-500 100
```

Will check for standard ssh/http/https servers and try to identify them, then do a TCP Connect scan on ports 1-500 with 100 concurrent sockets.

* Host is required (domain/IPv4/IPv6 supported per Node native modules)
* Range is optional (defaults `1-1000`)
* Max parallel connections is optional (defaults `12`)

## Fingerprinting & Detection 

The methods used are extremely basic, but mostly effective.

It attempts to identify what's running on 22/80/443 by checking `Server` headers on the HTTP(S) ports and reading any response on SSH (hope the daemon is friendly and identifies itself).

The scanning option searches for open ports that respond to HTTP (plaintext and via SSL/TLS), then scans the responses looking for strings that suggest Wordpress. Those include:

* Meta generator tag
* "Powered By Wordpress"
* Comment containing "Wordpress" (mostly plugins)
* wp-strings, default reference locations to content files

Inside the code is an unworking function that would additionally check for known Wordpress files, the string search works well enough for this script.

## Other Notes

This was written more in the style of a throwaway script or example than a serious module. Node is a terrible choice for a general-purpose port scanner. Use `nmap -sV` for better service identification, nevermind advanced timing and techniques that will likely never be usable in JS (unless someone hacks in low-level socket access). For wargames or testing applications, though, it's great to hack little scripts in Node and get the easy speed boost of the usual async coding patterns. I might add a repo with more examples that I've written for wargames and such...

The Wordpress identification could be useful spun off as an actual module.

If you're still interested and read this far then take a look at the code. It's only ~250 lines and I put tons of comments and commentary in there. Probably won't make up for the hacky code and lack of structure, but you'll hopefully find it entertaining!

## Known Issues

* If you give a bad (nonexistent/unreachable but valid) host you'll get spammed with errors, it doesn't end gracefully.
* No support for scanning multiple hosts
* No backoff and retries, sometimes leading to bad results (imagine throwing rocks to see if someone left any windows open)
* Reports results at end, you won't get running feedback

