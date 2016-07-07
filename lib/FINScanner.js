/*
 * FIN Scanner
 *
 * TCP FIN scan
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

class FINScanner extends SYNScanner {

  constructor(config={}) {
    super(config);
  }

  checkPort(port, cb) {

    this.callbacks[port] = cb;
    var req = {
      sourceAddress: this.localIP,
      destinationAddress: this.host,
      destinationPort: port,
      flags: TCP.FIN_FLAG,
    };
    this.icmpWatcher.addDest(port);
    this.tcpSocket.send(req);
    this.timedout[port] = setTimeout(function() {
      this.markOpenFiltered(port);
    }.bind(this), this.timeout);

  }

  markOpenFiltered(port) {
    if (!this.callbacks[port]) return;
    this.callbacks[port]({
      port,
      data: {
        status: 'open|filtered',
      }
    });
    delete this.callbacks[port];
  }

}

module.exports = FINScanner;
