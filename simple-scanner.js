#!/usr/bin/env node

/*
 * simple-scanner CLI
 *
 * Uses commander for easy access to basic scanning usages.
 *
 * Will likely be expanded to mimic more familiar scanners (ie: nmap)
 *
 * TODO: Better support for verbose logging, give full scan result (closed&filtered)
 */

const program         = require('commander');
const ConnectScanner  = require('./lib/ConnectScanner');
const WPScanner       = require('./lib/WPScanner');
const UDPScanner      = require('./lib/UDPScanner');
const SYNScanner      = require('./lib/SYNScanner');
const NULLScanner     = require('./lib/NULLScanner');
const FINScanner      = require('./lib/FINScanner');
const XmasScanner     = require('./lib/XmasScanner');
const ACKScanner      = require('./lib/ACKScanner');
const utilities       = require('./lib/utilities');
const log             = require('./lib/log');

const scanners = {
  connect: ConnectScanner,
  wordpress: WPScanner,
  udp: UDPScanner,
  syn: SYNScanner,
  null: NULLScanner,
  fin: FINScanner,
  xmas: XmasScanner,
  ack: ACKScanner,
};

let defaultScan = true;

program
  .version('0.7.0')
  .usage('<host> [options]')
  .option('-p, --ports [22,80,443]', 'Enter a comma-delimited list of port numbers (will override range)', portsFromList)
  .option('-r, --range [1-1000]', 'Enter a range of ports (default: 1-1000)', portsFromRange,{start:1,end:1000})
  .option('-i, --interval [1]', 'For use with --range, enter an interval (default: 1)', validPositiveNumber)
  .option('-m, --maxParallel [12]', 'Max parallel connections', validPositiveNumber)
  .option('-t, --timeout [2000]', 'Time to wait for response from target', validPositiveNumber)
  //.option('-w, --wordpress', 'Do only wordpress probe on indicated ports', false)
  .option('-b, --baseuri [wp]', 'URI to use as base for wordpress probe', '')
  .option('-C, --connect', 'Do only connect scan', false)
  .option('-U, --udp', 'Do only UDP scan - requires raw-socket', false)
  .option('-S, --syn', 'Do only SYN (half-open) scan - requires raw-socket', false)
  .option('-N, --null', 'Do only NULL scan - requires raw-socket', false)
  .option('-F, --fin', 'Do only FIN scan - requires raw-socket', false)
  .option('-X, --xmas', 'Do only Xmas scan - requires raw-socket', false)
  .option('-A, --ack', 'Do only ACK scan - requires raw-socket', false)
// TODO .option('--randomize', 'Randomize port order (default is sequential)', false);
  .option('-6, --ipv6', 'Use IPv6', false)
  .option('-4, --ipv4', 'Use IPv4', false)
  .option('-v, --verbose', 'More status updates', false);

program.on('--help', function() {
  console.log(`
  Default scan is a TCP Connect on ports 1-1000 using Node's Net library.
  HTTP probes are currently disabled.
  `);
});

program.parse(process.argv);

program.host = program.args[0];

if (!program.host) {
  program.help();
}

if (program.host === 'localhost' || program.host === '127.0.0.1' || program.host === '::1') {
  // concatenation because a single backtick string causes odd behavior in editor
  console.log(
    '\n'+
    'Scanning yourself via loopback (localhost/127.0.0.1/::1) may not work,\n'+
    'try your network addresses:\n'+
    `  IPv4: ${utilities.getLocalIP(4)}`+
    `  IPv6: ${utilities.getLocalIP(6)}\n`
  );
}

/*
 * Utility functions
 *
 */

function portsFromList(str) {
  return utilities.filterValidPorts(str.split(','));
}

function portsFromRange(str) {
  const [start,end] = str.split('-');
  return {start:parseInt(start)||1,end:parseInt(end)||1000};
}

function validPositiveNumber(n) {
  n = parseInt(n);
  return (isNaN(n) || n<1) ? 1 : n;
}

// for timing info
function secondsFromNow(time) {
  return Math.round((Date.now()-time)/1000);
}

// for rearranging scan results
function portSort(a,b) {
  return a.port-b.port;
}

function onError(e) {
  log.error(e);
}

// not-particularly-sophisticated
function statusUpdate(scanHeader, length, alertOnOpen) {
  let count = 0;
  let percent = 0;
  let previous = 0;
  const jumpToDisplay = program.verbose? 4 : 19;
  return function(result) {
    count++;
    percent = Math.floor(count/length*100);
    if (percent-previous > jumpToDisplay) {
      log.info(`${scanHeader}: ${percent}% complete`);
      previous = percent;
    }
    if (alertOnOpen && result.data.status === 'open') {
      log.info(`OPEN: port ${result.port}`);
    }
  };
}

function prettyPrint(o) {
  // o = {port: num, data: {wordpress: bool, server: str}}

  var pad = (n,s)=>s.length<n?(s+Array(n+1).join(' ')).substr(0,n):s;
  var p10 = pad.bind(0,10);

  var output = p10(o.port.toString())+' : ';
  for (var k in o.data) {
    // in case of multiple servers reported by wpScan
    if (Array.isArray(o.data[k])) {
      keyValue = o.data[k].join(' & ');
    } else {
      keyValue = o.data[k];
    }

    output += `${pad(12,k)} : ${keyValue}\n`;
    output += pad(13,'');
  }
  console.log(output);
}

/*
 * The actual scanning
 *
 */

const config = {
  host: program.host,
  ports: program.ports,
  start: program.range.start,
  end: program.range.end,
  interval: program.interval,
  maxParallel: program.maxParallel,
  timeout: program.timeout,
  ipFamily: program.ipv6 ? 6 : (program.ipv4 ? 4 : 0),
};

const scan = Object.keys(scanners).find(name=>{
  if (program[name]) doScan(scanners[name]);
});

if (!scan) doScan(ConnectScanner);

function doScan(Scanner) {
  const scanner = new Scanner(config);
  let startTime;
  scanner.on('error', function(e) {
    if (e.message === 'Operation not permitted') {
      log.warn('Scan requires elevated privileges, try it with sudo');
      process.exit();
    } else {
      log.error(e);
    }
  });
  scanner.on('ready', function() {
    startTime = Date.now();
    scanner.scan();
  });
  scanner.on('portFinished', statusUpdate('SCAN', scanner.portList.length));
  scanner.on('complete', function(results) {
    log.info(`Scan completed in ${secondsFromNow(startTime)} seconds`);
    results.forEach(prettyPrint);
  });
}

function doConnectScan() {

  let portScan = new PortScanner(config);
  let startTime;

  portScan.on('error', onError);

  portScan.on('ready', function() {
    log.info('Starting connect scan');
    startTime = Date.now();
    portScan.scan();
  });

  portScan.on('portFinished', statusUpdate('CONNECT SCAN', portScan.portList.length, true));
      
  portScan.on('complete', function(results) {

    log.info(`Connect scan completed in ${secondsFromNow(startTime)} seconds`);

    var openPorts = results.filter(_=>_.data.status==='open').sort(portSort);

    if (!openPorts.length) {
      log.info('No open ports found');
      return;
    }

    if (defaultScan) {
      var sorted = openPorts.reduce(function(obj, result) {
        if (result.data.response) {
          obj.noScan.push({port:result.port,data:{
            wordpress:false,server:result.data.response.trim()
          }});
        } else {
          obj.toScan.push(result.port);
        }
        return obj;
      }, {toScan:[],noScan:[]});
      doWpScan(sorted);
    } else {
      openPorts.forEach(prettyPrint);
    }
  });
}

function doWpScan(previousResults) {

  if (previousResults) {
    if (!previousResults.toScan.length) {
      log.info('No HTTP servers to probe');
      log.info('Banner results:');
      previousResults.noScan.forEach(prettyPrint);
      return;
    }

    config.ports = previousResults.toScan;
  }

  let startTime;

  if (program.baseuri) {
    config.baseUri = program.baseuri;
  }

  var wpScan = new WPScanner(config);

  wpScan.on('error', onError);

  wpScan.on('ready', function() {
    startTime = Date.now();
    log.info('Starting WP probe');
    wpScan.scan();
  });

  wpScan.on('portFinished', statusUpdate('WP SCAN', wpScan.portList.length));

  wpScan.on('complete', function(results) {
    log.info(`WP scan completed in ${secondsFromNow(startTime)} seconds`);
    log.info(`Results for ${program.host}:`);
    var finalResults;
    if (previousResults) {
      finalResults = results.concat(previousResults.noScan).sort(portSort);
    } else {
      finalResults = results.filter(o=>o.data.wordpress).sort(portSort);
      if (!finalResults.length) {
        log.info('No wordpress instances found');
      }
    }
    finalResults.forEach(prettyPrint);
  });
}

