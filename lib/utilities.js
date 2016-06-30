/*
 * Common domain-specific utility functions
 */


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
};

