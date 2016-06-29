#!/usr/bin/env node

/*
 * Example script using reworked Scanners to similarly do a naive port
 * scan and attempt to find Wordpress installations.
 *
 * Uses commander for a more sane CLI.
 *
 * The script first uses a PortScanner insance to do basic service
 * identification (really just saving banners), then use unidentified
 * open ports to test for HTTP(S) and WP.
 *
 * It would be easier to read with this separated into interface/scan1/scan2,
 * everything is included here for easy browsing from top to bottom.
 *
 * TODO: Better support for verbose logging, give full scan result (closed&filtered)
 */

var program = require('commander');
var PortScanner = require('./lib/PortScanner');
var WPScanner = require('./lib/WPScanner');

/*
 * CLI stuff
 *
 */

program
  .version('0.3.0')
  .option('-h, --host <host>', 'The host to scan')
  .option('-p, --ports [22,80,443]', 'Enter a comma-delimited list of port numbers (will override range)', portsFromList)
  .option('-r, --range [1-1000]', 'Enter a range of ports (default: 1-1000)', portsFromRange,{start:1,end:1000})
  .option('-i, --interval [1]', 'For use with --range, enter an interval (default: 1)', validPositiveNumber)
  .option('-m, --maxParallel [12]', 'Max parallel connections', validPositiveNumber)
  .option('-v, --verbose', 'More status updates', false)
  .parse(process.argv);

function portsFromList(str) {
  return str.split(',').map(Number).filter(_=>!isNaN(_)&&_>0&&0<65536);
}

function portsFromRange(str) {
  var [start,end] = str.split('-');
  return {start:parseInt(start)||1,end:parseInt(end)||1000}
}

function validPositiveNumber(n) {
  n = parseInt(n);
  return (!n || n<1) ? 1 : n;
}

if (!program.host) {
  console.log('Host is required');
  program.help();
}

/*
 * Utility functions
 *
 */

// for timing info
var startTime;
function secondsFromNow(time) {
  return Math.round((Date.now()-time)/1000);
}

// sort fn for rearranging scan results
function portSort(a,b) {
  return a.port-b.port;
}

function onError(e) {
  console.log('ERROR: ');
  console.log(e);
}

var config = {
  host: program.host,
  ports: program.ports,
  start: program.range.start,
  end: program.range.end,
  interval: program.interval,
  maxParallel: program.maxParallel,
};


// not-particularly-sophisticated status update
var statusUpdate = function(scanHeader, alertOnOpen) {
  var count = 0;
  var percent = 0;
  var previous = 0;
  var length = portScan.portList.length;
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

var portScan = new PortScanner(config);

portScan.on('error', onError);

portScan.on('ready', function() {
  console.log('Starting initial scan');
  startTime = Date.now();
  portScan.scan();
});

portScan.on('portFinished', statusUpdate('INITIAL SCAN', true));
    
portScan.on('complete', function(results) {

  console.log(`Initial scan completed in ${secondsFromNow(startTime)} seconds`);

  var openPorts = results.filter(_=>_.data.status==='open').sort(portSort);
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

  if (!sorted.toScan.length && !sorted.noScan.length) {
    console.log('No open ports found');
    return;
  }

  doWPScan(sorted);
});

function doWPScan(previousResults) {
  // reusing previous config var
  config.ports = previousResults.toScan;

  if (!config.ports.length) {
    console.log('No likely HTTP servers to probe');
    console.log('Banner results:');
    previousResults.noScan.forEach(prettyPrint);
    return;
  }

  var wpScan = new WPScanner(config);

  wpScan.on('error', onError);

  wpScan.on('ready', function() {
    startTime = Date.now();
    console.log('Starting WP probe');
    wpScan.scan();
  });

  wpScan.on('portFinished', statusUpdate('WP SCAN'));

  wpScan.on('complete', function(results) {
    console.log(`WP scan completed in ${secondsFromNow(startTime)} seconds`);
    console.log(`Results for ${program.host}:`);
    var finalResults = results.concat(previousResults.noScan).sort(portSort);
    finalResults.forEach(prettyPrint);
  });
}

