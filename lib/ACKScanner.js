/*
 * ACK Scanner
 *
 * TCP ACK scan - sets ACK only. Classifies filtered/unfiltered (see nmap -sA)
 *
 * TCP experiments inherit from SYN scanner for convenience,
 * unknown if it'll be easier to have one generic "TCPPacketScanner" class
 * or if there will be enough special-case handling to make that useless
 *
 * For testing and getting the feature available to tweak, this works
 *
 */

const SYNScanner = require('./SYNScanner');
const TCP = require('./TCPutils');

class ACKScanner extends SYNScanner {

  constructor(config={}) {
    super(config);
  }

  checkPort(port, cb) {

    this.callbacks[port] = cb;
    var req = {
      sourceAddress: this.localIP,
      destinationAddress: this.host,
      destinationPort: port,
      flags: TCP.ACK_FLAG,
    };
    this.icmpWatcher.addDest(port);
    this.tcpSocket.send(req);
    this.timedout[port] = setTimeout(function() {
      this.markFiltered(port);
    }.bind(this), this.timeout);

  }

  onResponse(resp) {
    // confirm source matches our host,
    // _may_ not always be desired behavior
    if (resp.sourceAddress !== this.host) {
      return;
    }

    // RST == open | closed 
    if (resp.flags.RST_FLAG) {
      this.markUnfiltered(resp.sourcePort);
    }

  }

  // TODO: simplify/consolidate/DRY out these markPort functions
  markUnfiltered(port) {
    if (!this.callbacks[port]) return;
    if (this.timedout[port]) {
      clearTimeout(this.timedout[port]);
      delete this.timedout[port];
    }
    this.callbacks[port]({
      port,
      data: {
        status: 'unfiltered',
      }
    });
    delete this.callbacks[port];
  }

}

module.exports = ACKScanner;
