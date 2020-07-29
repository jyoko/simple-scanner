/*
 * NULL Scanner
 *
 * TCP NULL scan (no flags set)
 *
 * TCP experiments inherit from SYN scanner for convenience,
 * unknown if it'll be easier to have one generic "TCPPacketScanner" class
 * or if there will be enough special-case handling to make that useless
 *
 * For testing and getting the feature available to tweak, this works
 *
 */

const TCPScanner = require('./TCPScanner');
const TCP = require('./TCPutils');

class NULLScanner extends TCPScanner {
  flags = 0;

  constructor(config={}) {
    super(config);
  }

  onTimeout(port) {
    this.markOpenFiltered(port);
  }

  onResponse(resp) {
    // confirm source matches our host,
    // _may_ not always be desired behavior
    if (resp.sourceAddress !== this.host) {
      return;
    }

    // RST == open | closed 
    if (resp.flags.RST_FLAG) {
      this.markClosed(resp.sourcePort);
    }
  }

  onIcmpResponse(resp) {
    if (response.type === 3) {
      switch (response.code) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 9:
        case 10:
        case 13:
          return this.markFiltered(response.originalDestinationPort);
      }
    }
  }

}

module.exports = NULLScanner;
