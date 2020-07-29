/*
 * SYN Scanner
 *
 * Classic half-open scan, known & loved by all!
 *
 * TODO: 
 *       test server!
 *       better interfaces for helper libs
 *       figure out why it hates localhost/127.0.0.1
 */

const TCPScanner = require('./TCPScanner');
const TCP = require('./TCPutils');

class SYNScanner extends TCPScanner {
  flags = TCP.SYN_FLAG;

  constructor(config={}) {
    super(config);
  }

  onTimeout(port) {
    this.markFiltered(port);
  }

  onResponse(resp) {
    // confirm source matches our host,
    // _may_ not always be desired behavior
    if (resp.sourceAddress !== this.host) {
      return;
    }

    // RST == closed
    if (resp.flags.RST_FLAG) {
      this.markClosed(resp.sourcePort);
    }

    // terrible check for split handshake & SYN/ACK
    if (resp.flags.SYN_FLAG) {
      this.markOpen(resp.sourcePort);
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
    // ignore other cases
  }

}

module.exports = SYNScanner;
