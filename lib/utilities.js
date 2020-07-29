/*
 * Common domain-specific utility functions
 */

// only actually check interfaces once, presumably this isn't changing
// while the script is running
// punted on multiples-per-iface, returns first match (TODO)
const getLocalIP = function() {
  const netIfaces = require('os').networkInterfaces();
  const localIPs = {IPv4:[],IPv6:[]};
  Object.keys(netIfaces).forEach(ifname=>{
    netIfaces[ifname].forEach(iface=>{
      // ignore internal like ::1, 127.0.0.1
      if (iface.internal) return;
      localIPs[iface.family].push(iface.address);
    });
  });
  return function(version) {
    version = version===6 ? 'IPv6' : 'IPv4';
    return localIPs[version][0];
  };
}();

function isValidPort(p) {
  return (typeof p === 'number' && !isNaN(p) && p>0 && p<65536);
}

function filterValidPorts(arr) {
  return arr.map(Number).filter(isValidPort);
}

function makeFirstAndLastSlash(str) {
  if (!/\//.test(str[0])) {
    str = '/'+str;
  }
  if (!/\//.test(str[str.length-1])) {
    str += '/';
  }
  return str;
}

function makeArrayForIntervalRange(start,end,interval) {
  var range = new Array(Math.ceil((end-start+1)/interval));
  for(var i=0, l=range.length; i<l; i++) {
    range[i] = start+(interval*i);
  }
  return range;
}

module.exports = {
  isValidPort,
  filterValidPorts,
  makeFirstAndLastSlash,
  makeArrayForIntervalRange,
  getLocalIP,
};

