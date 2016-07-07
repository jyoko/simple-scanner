/*
 * SYN Scanner
 *
 * Experimental half-open scan, known & loved by all!
 *
 * TODO: confirm ICMP responses work - theoretically should, want to test reusing same socket
 *       test server!
 *       better interfaces for helper libs
 *       figure out why it hates localhost/127.0.0.1
 *       generic TCP scan?
 */

const Scanner = require('./Scanner');
const TCPSocket = require('./TCPSocket');
const TCP = require('./TCPutils');
const ICMPWatcher = require('./ICMPWatcher');
const utilities = require('./utilities');


class SYNScanner extends Scanner {

  constructor(config={}) {
    super(config);
    this.timeout = config.timeout || 2000;
    this.localIP = utilities.getLocalIP();
    this.tcpSocket = new TCPSocket();
    this.on('complete', this.close.bind(this));
    this.tcpSocket.on('error', this.onError.bind(this));
    this.tcpSocket.on('response', this.onResponse.bind(this));
    this.callbacks = {};
    this.timedout = {};
    // delay getting socket til event listeners are registered
    process.nextTick(this._getSocket.bind(this));
  }

  // gets socket and sets up ICMPWatcher
  _getSocket() {
    this.tcpSocket.getSocket();
    this.icmpWatcher = new ICMPWatcher({
      sourcePort: this.tcpSocket.sourcePort,
//      socket: this.tcpSocket.socket,
    });
    // want to catch errors, but if we got here we have proper perms
    this.icmpWatcher.on('error', this.onError.bind(this));
    this.icmpWatcher.on('response', this.onIcmpResponse.bind(this));
    this.icmpWatcher.getSocket();
    // ^^ unpredictable timing on getSocket
    process.nextTick(function() {
      this.emit('icmpready');
    }.bind(this));
  }

  checkPort(port, cb) {

    this.callbacks[port] = cb;
    var req = {
      sourceAddress: this.localIP,
      destinationAddress: this.host,
      destinationPort: port,
      flags: TCP.SYN_FLAG,
    };
    this.icmpWatcher.addDest(port);
    this.tcpSocket.send(req);
    this.timedout[port] = setTimeout(function() {
      this.markFiltered(port);
    }.bind(this), this.timeout);

  }

  markClosed(port) {
    if (!this.callbacks[port]) return;
    if (this.timedout[port]) clearTimeout(this.timedout[port]);
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
    if (this.timedout[port]) clearTimeout(this.timedout[port]);
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
    if (this.timedout[port]) clearTimeout(this.timedout[port]);
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
          return this.markFiltered(response.originalDestPort);
      }
    }
    // ignore other cases
  }

  onError(e) {
    this.close();
    this.emit('error', e);
  }

  close() {
    this.tcpSocket.close();
    if (this.icmpWatcher) this.icmpWatcher.close();
  }

}

module.exports = SYNScanner;
