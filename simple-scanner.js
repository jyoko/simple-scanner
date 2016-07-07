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

var program = require('commander');
var PortScanner = require('./lib/PortScanner');
var WPScanner = require('./lib/WPScanner');
var UDPScanner = require('./lib/UDPScanner');
var SYNScanner = require('./lib/SYNScanner');
var NULLScanner = require('./lib/NULLScanner');
var FINScanner = require('./lib/FINScanner');
var XmasScanner = require('./lib/XmasScanner');
var ACKScanner = require('./lib/ACKScanner');
var utilities = require('./lib/utilities');
var defaultScan = true;

program
  .version('0.6.0')
  .usage('<host> [options]')
  .option('-p, --ports [22,80,443]', 'Enter a comma-delimited list of port numbers (will override range)', portsFromList)
  .option('-r, --range [1-1000]', 'Enter a range of ports (default: 1-1000)', portsFromRange,{start:1,end:1000})
  .option('-i, --interval [1]', 'For use with --range, enter an interval (default: 1)', validPositiveNumber)
  .option('-m, --maxParallel [12]', 'Max parallel connections', validPositiveNumber)
  .option('-w, --wordpress', 'Do only wordpress probe on indicated ports', false)
  .option('-b, --baseuri [wp]', 'URI to use as base for wordpress probe', '')
  .option('-C, --connect', 'Do only connect scan', false)
  .option('-U, --udp', 'Do only UDP scan - WARNING: experimental, slow, likely requires root', false)
  .option('-S, --syn', 'Do only SYN (half-open) scan - WARNING: experimental, in-progress', false)
  .option('-N, --null', 'Do only NULL scan - WARNING: experimental', false)
  .option('-F, --fin', 'Do only FIN scan - WARNING: experimental', false)
  .option('-X, --xmas', 'Do only Xmas scan - WARNING: experimental', false)
  .option('-A, --ack', 'Do only ACK scan - WARNING: experimental', false)
// TODO .option('--randomize', 'Randomize port order (default is sequential)', false);
  .option('-v, --verbose', 'More status updates', false);

program.on('--help', function() {
  console.log(
`  Default scan is a TCP Connect on ports 1-1000 using Node's Net library,
  any open ports that do not respond with a banner will be probed for an HTTP
  server and Wordpress instances.

  Other scan types are experimental and may not work as-intended on all
  operating systems.
  `);
});

program.parse(process.argv);

program.host = program.args[0];

if (!program.host) {
  program.help();
}

/*
 * Utility functions
 *
 */

function portsFromList(str) {
  return utilities.filterValidPorts(str.split(','));
}

function portsFromRange(str) {
  var [start,end] = str.split('-');
  return {start:parseInt(start)||1,end:parseInt(end)||1000};
}

function validPositiveNumber(n) {
  n = parseInt(n);
  return (isNaN(n) || n<1) ? 1 : n;
}

// for timing info
var startTime;
function secondsFromNow(time) {
  return Math.round((Date.now()-time)/1000);
}

// for rearranging scan results
function portSort(a,b) {
  return a.port-b.port;
}

function onError(e) {
  console.log('ERROR: ');
  console.log(e);
}

// not-particularly-sophisticated
function statusUpdate(scanHeader, length, alertOnOpen) {
  var count = 0;
  var percent = 0;
  var previous = 0;
  var jumpToDisplay = program.verbose? 4 : 19;
  return function(result) {
    count++;
    percent = Math.floor(count/length*100);
    if (percent-previous > jumpToDisplay) {
      console.log(`${scanHeader}: ${percent}% complete`);
      previous = percent;
    }
    if (alertOnOpen && result.data.status === 'open') {
      console.log(`OPEN: port ${result.port}`);
    }
  };
};

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

var config = {
  host: program.host,
  ports: program.ports,
  start: program.range.start,
  end: program.range.end,
  interval: program.interval,
  maxParallel: program.maxParallel,
};


// TODO: this flow control
if (program.wordpress) {
  defaultScan = false;
  doWpScan();
} 

if (program.udp) {
  defaultScan = false;
  doUdpScan();
}

if (program.connect) {
  defaultScan = false;
  doConnectScan();
}

if (program.syn) {
  defaultScan = false;
  doSynScan();
}

if (program.null) {
  defaultScan = false;
  doNullScan();
}

if (program.fin) {
  defaultScan = false;
  doFinScan();
}

if (program.xmas) {
  defaultScan = false;
  doXmasScan();
}

if (program.ack) {
  defaultScan = false;
  doAckScan();
}

if (defaultScan) {
  doConnectScan();
}

function doConnectScan() {

  var portScan = new PortScanner(config);

  portScan.on('error', onError);

  portScan.on('ready', function() {
    console.log('Starting connect scan');
    startTime = Date.now();
    portScan.scan();
  });

  portScan.on('portFinished', statusUpdate('CONNECT SCAN', portScan.portList.length, true));
      
  portScan.on('complete', function(results) {

    console.log(`Connect scan completed in ${secondsFromNow(startTime)} seconds`);

    var openPorts = results.filter(_=>_.data.status==='open').sort(portSort);

    if (!openPorts.length) {
      console.log('No open ports found');
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
      console.log('No HTTP servers to probe');
      console.log('Banner results:');
      previousResults.noScan.forEach(prettyPrint);
      return;
    }

    config.ports = previousResults.toScan;
  }

  if (program.baseuri) {
    config.baseUri = program.baseuri;
  }

  var wpScan = new WPScanner(config);

  wpScan.on('error', onError);

  wpScan.on('ready', function() {
    startTime = Date.now();
    console.log('Starting WP probe');
    wpScan.scan();
  });

  wpScan.on('portFinished', statusUpdate('WP SCAN', wpScan.portList.length));

  wpScan.on('complete', function(results) {
    console.log(`WP scan completed in ${secondsFromNow(startTime)} seconds`);
    console.log(`Results for ${program.host}:`);
    var finalResults;
    if (previousResults) {
      finalResults = results.concat(previousResults.noScan).sort(portSort);
    } else {
      finalResults = results.filter(o=>o.data.wordpress).sort(portSort);
      if (!finalResults.length) {
        console.log('No wordpress instances found');
      }
    }
    finalResults.forEach(prettyPrint);
  });
}

// experimental, bear with me
function doUdpScan() {

  var udpScan = new UDPScanner(config);
  udpScan.on('error', function(e) {
    if (e.message === 'Operation not permitted') {
      console.log('\nUDP scan requires elevated privileges, try sudo\n');
      process.exit();
    }
    console.log('ERROR: ');
    console.log(e);
  });
  udpScan.on('icmpready', function() {
    udpScan.scan();
  });
  udpScan.on('portFinished', statusUpdate('UDP SCAN', udpScan.portList.length));
  udpScan.on('complete', function(results) {
    results.forEach(prettyPrint);
  });

}

// see above :-D
function doSynScan() {
  console.log(`
Scanning yourself via loopback (localhost/127.0.0.1) may not work,
try your network address - ${utilities.getLocalIP()}
`);
  var synScan = new SYNScanner(config);
  synScan.on('error', function(e) {
    if (e.message === 'Operation not permitted') {
      console.log('\nSYN scan requires elevated privileges, try sudo\n');
      process.exit();
    } else {
      console.log('ERROR: ');
      console.log(e);
    }
  });
  synScan.on('icmpready', function() {
    synScan.scan();
  });
  synScan.on('portFinished', statusUpdate('SYN SCAN', synScan.portList.length));
  synScan.on('complete', function(results) {
    // holy ugly results TODO
    var filteredResults = results.reduce((o,result)=>{
      if (result.data.status === 'closed') {
        o[0].data.closed++;
      }
      if (result.data.status === 'filtered') {
        o[1].data.filtered++;
      }
      if (result.data.status === 'open') {
        o.push(result);
      }
      return o;
    }, [{port:'combined',data:{closed:0}},{port:'combined',data:{filtered:0}}]);

    filteredResults.forEach(prettyPrint);
  });
}

function doNullScan() {
  console.log(`
Scanning yourself via loopback (localhost/127.0.0.1) may not work,
try your network address - ${utilities.getLocalIP()}
`);
  var nullScan = new NULLScanner(config);
  nullScan.on('error', function(e) {
    if (e.message === 'Operation not permitted') {
      console.log('\nNULL scan requires elevated privileges, try sudo\n');
      process.exit();
    } else {
      console.log('ERROR: ');
      console.log(e);
    }
  });
  nullScan.on('icmpready', function() {
    nullScan.scan();
  });
  nullScan.on('portFinished', statusUpdate('NULL SCAN', nullScan.portList.length));
  nullScan.on('complete', function(results) {
    // holy ugly results TODO
    var filteredResults = results.reduce((o,result)=>{
      if (result.data.status === 'closed') {
        o[0].data.closed++;
      }
      if (result.data.status === 'filtered') {
        o[1].data.filtered++;
      }
      if (result.data.status === 'open|filtered') {
        o.push(result);
      }
      return o;
    }, [{port:'combined',data:{closed:0}},{port:'combined',data:{filtered:0}}]);

    filteredResults.forEach(prettyPrint);
  });
}

function doFinScan() {
  console.log(`
Scanning yourself via loopback (localhost/127.0.0.1) may not work,
try your network address - ${utilities.getLocalIP()}
`);
  var finScan = new FINScanner(config);
  finScan.on('error', function(e) {
    if (e.message === 'Operation not permitted') {
      console.log('\nNULL scan requires elevated privileges, try sudo\n');
      process.exit();
    } else {
      console.log('ERROR: ');
      console.log(e);
    }
  });
  finScan.on('icmpready', function() {
    finScan.scan();
  });
  finScan.on('portFinished', statusUpdate('NULL SCAN', finScan.portList.length));
  finScan.on('complete', function(results) {
    // holy ugly results TODO
    var filteredResults = results.reduce((o,result)=>{
      if (result.data.status === 'closed') {
        o[0].data.closed++;
      }
      if (result.data.status === 'filtered') {
        o[1].data.filtered++;
      }
      if (result.data.status === 'open|filtered') {
        o.push(result);
      }
      return o;
    }, [{port:'combined',data:{closed:0}},{port:'combined',data:{filtered:0}}]);

    filteredResults.forEach(prettyPrint);
  });
}


function doXmasScan() {
  console.log(`
Scanning yourself via loopback (localhost/127.0.0.1) may not work,
try your network address - ${utilities.getLocalIP()}
`);
  var xmasScan = new XmasScanner(config);
  xmasScan.on('error', function(e) {
    if (e.message === 'Operation not permitted') {
      console.log('\nNULL scan requires elevated privileges, try sudo\n');
      process.exit();
    } else {
      console.log('ERROR: ');
      console.log(e);
    }
  });
  xmasScan.on('icmpready', function() {
    xmasScan.scan();
  });
  xmasScan.on('portFinished', statusUpdate('NULL SCAN', xmasScan.portList.length));
  xmasScan.on('complete', function(results) {
    // holy ugly results TODO
    var filteredResults = results.reduce((o,result)=>{
      if (result.data.status === 'closed') {
        o[0].data.closed++;
      }
      if (result.data.status === 'filtered') {
        o[1].data.filtered++;
      }
      if (result.data.status === 'open|filtered') {
        o.push(result);
      }
      return o;
    }, [{port:'combined',data:{closed:0}},{port:'combined',data:{filtered:0}}]);

    filteredResults.forEach(prettyPrint);
  });
}

function doAckScan() {
  console.log(`
Scanning yourself via loopback (localhost/127.0.0.1) may not work,
try your network address - ${utilities.getLocalIP()}
`);
  var ackScan = new ACKScanner(config);
  ackScan.on('error', function(e) {
    if (e.message === 'Operation not permitted') {
      console.log('\nNULL scan requires elevated privileges, try sudo\n');
      process.exit();
    } else {
      console.log('ERROR: ');
      console.log(e);
    }
  });
  ackScan.on('icmpready', function() {
    ackScan.scan();
  });
  ackScan.on('portFinished', statusUpdate('NULL SCAN', ackScan.portList.length));
  ackScan.on('complete', function(results) {
    // holy ugly results TODO
    var filteredResults = results.reduce((o,result)=>{
      if (result.data.status === 'filtered') {
        o[0].data.filtered++;
      }
      if (result.data.status === 'unfiltered') {
        o.push(result);
      }
      return o;
    }, [{port:'combined',data:{filtered:0}}]);

    filteredResults.forEach(prettyPrint);
  });
}
