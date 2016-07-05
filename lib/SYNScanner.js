/*
 * SYN Scanner
 *
 * Experimental half-open scan, known & loved by all!
 *
 * TODO: incorporate ICMP responses
 *       better interfaces for helper libs
 *       figure out why it hates localhost/127.0.0.1
 *       make getSocket call more obvious (hidden in socket.send for the record)
 */

const Scanner = require('./Scanner');
const TCPSocket = require('./TCPSocket');
const TCP = require('./TCPutils');
const utilities = require('./utilities');


class SYNScanner extends Scanner {

  constructor(config={}) {
    super(config);
    this.timeout = config.timeout || 2000;
    this.localIP = utilities.getLocalIP();
    this.socket = new TCPSocket();
    this.socket.on('error', this.onError.bind(this));
    this.socket.on('response', this.onResponse.bind(this));
    this.callbacks = {};
    this.on('complete', this.close.bind(this));
  }

  checkPort(port, cb) {

    this.callbacks[port] = cb;
    var req = {
      sourceAddress: this.localIP,
      destinationAddress: this.host,
      destinationPort: port,
      flags: TCP.SYN_FLAG,
    };
    this.socket.send(req);
    setTimeout(function() {
      this.markFiltered(port);
    }.bind(this), this.timeout);

  }

  markClosed(port) {
    if (!this.callbacks[port]) return;
    this.callbacks[port]({
      port,
      data: {
        status: 'closed',
      }
    });
    delete this.callbacks[port];
  }

  markFiltered(port) {
    if (!this.callbacks[port]) return;
    this.callbacks[port]({
      port,
      data: {
        status: 'filtered',
      }
    });
    delete this.callbacks[port];
  }

  markOpen(port) {
    if (!this.callbacks[port]) return;
    this.callbacks[port]({
      port,
      data: {
        status: 'open',
      }
    });
    delete this.callbacks[port];
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

  onError(e) {
    this.emit('error', e);
  }

  close() {
    this.socket.close();
  }

}

module.exports = SYNScanner;
