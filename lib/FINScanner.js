/*
 * FIN Scanner
 *
 * TCP FIN scan
 *
 */

const TCPScanner = require('./TCPScanner');
const TCP = require('./TCPutils');

class FINScanner extends TCPScanner {
  flags = TCP.FIN_FLAG;

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

module.exports = FINScanner;
