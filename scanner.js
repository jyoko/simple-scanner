#!/usr/bin/env node

/*
 * Requires a more modern node to run (using template strings & arrow funcs)
 * No other dependencies beyond Node built-ins
 *
 * This scanner does (naive) server detection for ports
 * 22(ssh)/80(http)/443(https) and will run a _NOISY_ TCP connect port scan
 * within a defined range to find Wordpress instances over HTTP or HTTPS.
 *
 * Gotta stress this again: The scanner is simple and noisy. Expect to see
 * erroneous results from most servers at some point, very quickly if you crank
 * the connections up. Default checks (SSH/HTTP/HTTPS) are not included in
 * config.
 *
 * Code is heavily commented with commentary and fairly short, take a skim!
 *
 * Usage:
 *
 *  scanner [host] [WP scan range, default: 1-1000] [max sockets, default: 12]
 *
 *  Note: Setting max-sockets too high may cause unpredictable behavior from
 *        the server or in extreme cases use up available file descriptors
 */

// 6 per nmap, but we don't do much fingerprinting. Time in ms
var timeout = 2000;

/*
 * Basic ARGV checks first... yes I'm lazy and enforce argument order
 * instead of switches like a decent human being. Host validity is
 * checked prior to starting execution via the DNS module, I'd add it up
 * here but would have to roll my own synchronous version
 *
 * TODO: user interface
 */

// no arguments check and usage output
var script_src = process.argv[1].split('/').pop();
if (process.argv.length < 3) {
  console.log('\nERROR: host required');
  console.log(`  ${script_src} [host] [WP scan range, 1-1000] [WP sockets, 12]`);
  console.log('\nIf slow, timeout variable is at top of file (default 2s)\n');
  return;
}
var host = process.argv[2];

// verify port range is valid format & numbers, default 1-1000
var range = [1,1000];
if (process.argv[3]) {
  range = process.argv[3].split('-').map(Number).filter(_=>!isNaN(_)&&_>0&&_<65536);
  if (range.length!==2 || range[1]<range[0]) {
    console.log('ERROR: bad port range');
    console.log(`  ${script_src} ${host} 1-65535`);
    return;
  }
}

/*
 * Worth noting Fyodor found diminished performance with >18 parallel sockets
 * on a decent connections, given the writeup was a little dated.
 * Realistically, you can scan SUPER-FAST with this at 50-100-1000+, but will
 * have tons of closed false-positives (ECONNREFUSED) or other broken responses
 * on most servers (typically behind some kind of DoS protection if nothing
 * else)
 *
 */
var maxSocks = 12;
if (process.argv[4]) {
  maxSocks = parseInt(process.argv[4]);
  if (isNaN(maxSocks)) {
    console.log('ERROR: invalid max sockets');
    console.log(`  ${script_src} ${host} ${range.join('-')} 50`);
    return;
  }
}

/*
 * Variable definitions & helper functions
 *
 */
var net = require('net');
var tls = require('tls');
var dns = require('dns');
var services = {22:'ssh',80:'http',443:'https'}; // TODO: full port list?
var defaultPorts = [22,80,443]; // for the server-id scan

// use regular HTTP1.1 GET request, more likely to get a good response than
// HEAD or HTTP1.0 when scanning. TODO: full fake browser, at least for WP
var httpString = `GET / HTTP/1.1\r\nHost: ${host}\r\n\r\n`;

/*
 * ScanTracker is just a function that tracks when our requests have finished
 * and triggers a callback that takes the time it "started" for good-enough
 * timing output (data is updated via side-effects below). The returned
 * function takes in a port number or 'upgrade' to decrement the count when
 * trying the port again via TLS.
 *
 * If this gets triggered after a timeout and no open/closed status was set in
 * the main logic, we'll call the port filtered. More-or-less matches a proper
 * scanner from limited testing
 *
 */
function makeScanTracker(loopObj,loopArr,cb) {
  var count=0;
  var startTime = Date.now();
  return function(p) {
    if (p==='upgrade' && count>-1) return --count;
    if (loopObj[p].status==='') {
      loopObj[p].status = 'filtered'; // obviously ;-)
    }
    if (++count === loopArr.length) {
      cb(startTime);
    }
  };
}
/*
 * Not going nuts with Wordpress logic here as it's probably better-suited to
 * its own module (to be used in tandem with a real port scanner), but we have
 * minimal checks for a generator meta tag, wp-XX, <!--wordpress-->, or powered
 * by strings in HTTP responses to catch lots of default installs and plugins.
 *
 * The second function is not used and isn't complete, but works as a
 * placeholder for other checks on possible Wordpress URLs (would require more
 * response parsing).  To be really useful, should probably include either
 * calls out to other Wordpress/theme detectors or a more exhaustive set of
 * identifiers.
 *
 */
function checkWPStrings(str) {
  return /(?:name="generator" content="wordpress)|(?:wp\-\w+)|(?:powered by wordpress)|(?:<!--.+wordpress.+-->)/i.test(str);
}
function checkWPurls(socket) {
  var port = socket.remotePort;
  var host = socket.remoteHost;
  var urls = ['/wp-admin','wp-login.php','license.txt','readme.html'];
  var doNextConnect = function() {
    /* track where we are in the list */
    socket.connect(port,host,function(){
      /*http req*/
    });
  }
  socket.removeAllListeners();
  socket.on('close', doNextConnect);
  socket.end();
}

/*
 * Not that pretty, but slightly easier to read than logging objects. Suppose I
 * could TODO formatting options (say for piping) here, after implementing a
 * sane UI.
 *
 * Fun note: Almost included leftpad and double-reversed strings just for the
 * hell of it, but I think the one-liner, then bound function, then stupid
 * IIFE-included ternary is appropriately frightening.
 *
 */
function prettyPrint(obj) {
  // obj = {PORT : {INFO_NAME: INFO_DATA}}
  var pad = (n,s)=>s.length<n?(s+Array(n+1).join(' ')).substr(0,n):s;
  var p10 = pad.bind(0,10);
  Object.keys(obj).forEach(port=>{
    var info = typeof obj[port] !== 'object' ?
      obj[port] :
      (function(d) {
        var s = '';
        for (var k in d) {
          s += `${p10(k)} - ${d[k]}\n`
          s += pad(13,'');
        }
        return s;
    })(obj[port]);
    console.log(`${p10(port)} : ${info}`);
  });
}
  
/*
 * "Default" fingerprint logic
 *
 * Naming is a bit stupid here but I'm used to it. Basically, we create
 * our object that'll get populated as the requests finish (side effects!), then
 * make a function to fire off the loop that actually makes the requests. It gets
 * called at the bottom of the script.
 *
 */
var defaultServices = defaultPorts.reduce((o,p)=>{
  o[p] = {
    service: services[p],
    status: '',
    type: '',
  };
  return o;
},{});
var defaultClose = makeScanTracker(defaultServices,defaultPorts,_=>{
  var time = (Date.now()-_)/1000;
  console.log('DEFAULT SCAN RESULTS:');
  console.log(`Scanned ${defaultPorts.length} ports in ${time}s\n`);
  prettyPrint(defaultServices)
});

function checkDefaults() {
  defaultPorts.forEach(function(port) {
    function onData(d) {
      if (/^http/.test(defaultServices[port].service)) {
        if (defaultServices[port].type === '') {
          // The above check is because the Server header should be early in
          // the response data, if the page includes a matching regex we don't
          // want to overwrite
          defaultServices[port].type = (d.toString().match(/Server: (.+)/) || [])[1];
        }
      } else {
        // ssh daemons identify themselves nicely with a string often enough
        // for this to be a comfortable default
        defaultServices[port].type = d.toString();
      }
      s.end();
    }
    function onError(e) {
      if (defaultServices[port].status==='') {
        defaultServices[port].status = 'closed'; // said it was naive
      }
    }
    function onClose() {
      defaultClose(port);
    }
    var s = new net.Socket();
    s.setTimeout(timeout, _=>s.destroy());
    s.connect(port,host,_=>{
      defaultServices[port].status='open';
      // switch, ez way to add more later
      switch(port) {
        case 80:
          s.write(httpString);
          break;
        case 443: // try upgrade to TLS/SSL
          s.end();
          defaultClose('upgrade');
          s = new tls.TLSSocket();
          s.setTimeout(timeout,_=>s.destroy());
          s.connect(port,host,_=>{
            defaultServices[port].status='open';
            s.write(httpString)
          });
          s.on('data', onData);
          s.on('error',onError);
          s.on('close',onClose);
          break;
      }
    });
    s.on('data', onData); 
    s.on('error', onError);
    s.on('close', onClose);
  });
}

/*
 * Wordpress scanner starts here
 *
 * Code is virtually identical to above, should be an easy skim. Probe is what
 * checks a port (HTTP-then-HTTPS), but is called via next(). Next is dumb,
 * you can pass it an index of scanPorts but I don't, it progresses on its own.
 * The purpose is to obey maxSocks, when a socket ends it call next.
 *
 * Yes, I apologize for the array populating for.
 *
 */
var scanPorts = new Array(range[1]-range[0]+1);
for (var i=0,l=scanPorts.length; i<l; scanPorts[i]=range[0]+i++);
var scanData = scanPorts.reduce((o,p) => {
  o[p] = {
    status: '',
    wordpress: false,
  }
  return o;
},{});
var wpClose = makeScanTracker(scanData, scanPorts, _=>{
  var time = (Date.now()-_)/1000;
  var output = Object.keys(scanData).reduce((o,port)=>{
    if (scanData[port].status === 'filtered') {
      o.filtered++;
    }
    if (scanData[port].status === 'closed') {
      o.closed++;
    }
    if (scanData[port].status === 'open') {
      o[port] = scanData[port];
    }
    return o;
  },{filtered:0,closed:0});
  console.log('WORDPRESS SCAN RESULTS: ');
  console.log(`Scanned ${scanPorts.length} ports in ${time}s\n`);
  prettyPrint(output);
});

var next = function() {
  var i=-1;
  return function(p) {
    if (p===void 0) {
      p = ++i;
    }
    if (p<scanPorts.length) {
      probe(scanPorts[p]);
    } else {
      return;
    }
  }
}();

function probe(port) {
  function onData(d) {
    scanData[port].status = 'open';
    var str = d.toString();
    if (!foundHTTP && /HTTP\/1\.1/.test(str)) { // not great, but good enough for our purposes
      foundHTTP = true;
    }
    if (scanData[port].wordpress) { // no need to continue if we think its WP
      return s.end();
    }
    if (foundHTTP) {
      scanData[port].wordpress = checkWPStrings(str);

      /* upgrade on 400 responses some servers give on plaintext reqs
       * EPROTO will upgrade like any other negative response
       * TODO: follow 300s that match HTTPS?
       */
      if (!upgraded && /400 Bad Request/i.test(str)) {
        s.removeListener('close',onClose);
        s.on('close', upgradeTLS);
      }
    }
  }
  function onError(e) {
    if (scanData[port].status === '') {
      scanData[port].status = 'closed';
    }
    /* ignore refused connection errors (but still mark closed),
     * as scanner will end up on drop lists. Log other errors as they
     * might be helpful or informative
     */
    if (e.code!=='ECONNREFUSED') {
      console.log(`Connection error : ${e.code}, ${port} may be marked closed`);
    }
  }
  function onClose() {
    if (upgraded) {
      wpClose(port);
      next();
    } else {
      upgradeTLS();
    }
  }
  function upgradeTLS() {
    upgraded = true;
    s = new tls.TLSSocket();
    s.setTimeout(timeout,_=>s.destroy());
    s.connect(port,host,_=>{
      defaultServices[port].status='open';
      s.write(httpString)
    });
    s.on('data', onData);
    s.on('error',onError);
    s.on('close',onClose);
  }

  var upgraded = false;
  var foundHTTP = false;
  var s = net.createConnection(port,host,_=>{
    scanData[port].status='open';
    // accepting connections, try GET request!
    s.write(httpString);
  });
  s.setTimeout(timeout, _=>s.destroy());
  s.on('data', onData); 
  s.on('error', onError);
  s.on('close', onClose);
};

/* 
 * Do lookup on the provided host, then fire off the script.
 *
 * This lookup serves two purposes, first is confirming a valid address.
 * Second is a bit more interesting: Node (at least on Debian-family kernels)
 * seems to have issues with large amounts of DNS lookups if you pass domains
 * into lots of net calls. No idea what exactly happens under the hood to cause
 * it, but the requests will fire and end and then node will still be
 * epoll_waiting around for (UDP) responses to lookups (I saw the note & know
 * it's synchronous in libuv). Maybe it's a quirk with my local setup, but
 * you'd think something would cache between this script and getaddrinfo
 * sending thousands of DNS requests. TODO: ask someone about that!
 *
 */
dns.lookup(host, function(err, address) {
  if (err) {
    console.log(`ERROR: cannot resolve ${host}`);
    console.log(err);
    return;
  }
  host = address;
  checkDefaults();
  // ternary saves some calls if maxSocks is higher than scan range
  for (var i=0,l=scanPorts.length<maxSocks?scanPorts.length:maxSocks; i<l; i++) {
    next();
  }
});

