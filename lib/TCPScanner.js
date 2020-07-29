/*
 * TCP Scanner
 *
 * Generic scanner for sending arbitrary TCP packets.
 *
 * TODO: 
 *       test server!
 *       figure out why it hates localhost/127.0.0.1
 */

const Scanner = require('./Scanner');
const TCPSocket = require('./TCPSocket');
const TCP = require('./TCPutils');
const ICMPWatcher = require('./ICMPWatcher');
const utilities = require('./utilities');

class TCPScanner extends Scanner {

  constructor(config={}) {
    super(config);
    this.addPrepare('_setupSockets');
    this.flags = config.flags || TCP.SYN_FLAG;
    this.data = config.data || undefined;
    this.icmpListen = config.icmpListen===undefined ? true : !!config.icmpListen;
  }

  _setupSockets() {
    this.tcpSocket = new TCPSocket({addressFamily:this.addressFamily});
    this.on('complete', this.close.bind(this));
    this.tcpSocket.on('error', this.onError.bind(this));
    this.tcpSocket.on('response', this.onResponse.bind(this));
    // delay getting socket til event listeners are registered
    process.nextTick(this._getSocket.bind(this));
  }

  // gets socket and sets up ICMPWatcher
  _getSocket() {
    this.tcpSocket.getSocket();
    if (this.icmpListen) {
      this.icmpWatcher = new ICMPWatcher({
        sourcePort: this.tcpSocket.sourcePort,
        addressFamily: this.addressFamily,
      });
      // want to catch errors, but if we got here we have proper perms
      this.icmpWatcher.on('error', this.onError.bind(this));
      this.icmpWatcher.on('response', this.onIcmpResponse.bind(this));
      this.icmpWatcher.getSocket();
    }
    // ^^ unpredictable timing on getSocket
    process.nextTick(()=>this.ready());
  }

  onError(e) {
    this.close();
    this.emit('error', e);
  }

  close() {
    if (this.tcpSocket) this.tcpSocket.close();
    if (this.icmpWatcher) this.icmpWatcher.close();
  }

  checkPort(port, cb) {
    this.callbacks[port] = cb;
    const req = {
      sourceAddress: this.localIP,
      destinationAddress: this.host,
      destinationPort: port,
      flags: this.flags,
      data: this.data,
    };
    if (this.icmpListen) this.icmpWatcher.addDest(port);
    this.tcpSocket.send(req);
    this.timedout[port] = setTimeout(()=>this.onTimeout(port), this.timeout);
  }

  onTimeout(port) {
    // placeholder
  }

  onResponse(resp) {
    // placeholder
  }

  onIcmpResponse(resp) {
    // placeholder
  }

}

module.exports = TCPScanner;
