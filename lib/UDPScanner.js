/*
 * UDP Scanner
 *
 * Essentially borrowing nmap's UDP scan logic from description (not source):
 *
 *   Send rate-limited packets (using Node dgram)
 *   If packet received mark 'open' (using Node dgram)
 *   If no response or ICMP type 3, codes 0,1,2,9,10,13 mark 'open|filtered'
 *   If ICMP type 3 code 3 mark 'closed'
 *
 * TODO: use raw socket to send UDP req, just listen with dgram
 */

const dgram = require('dgram');
const Scanner = require('./Scanner');
const ICMPWatcher = require('./ICMPWatcher');

class UDPScanner extends Scanner {

  constructor(config={}) {
    config.rateLimit = config.rateLimit || 500; // default 2 per sec
    super(config);
    this.msg = config.udpMsg || Buffer.alloc(0);
    this.callbacks = {};
    this.timedout = {};
    this.addPrepare('_setupSockets');
  }

  _setupSockets() {
    this.udp = dgram.createSocket('udp'+this.addressFamily);
    this.udp.on('error', this.onError.bind(this));
    this.udp.on('message', this.markOpen.bind(this));
    this.udp.on('listening', this._setupICMPWatch.bind(this));
    this.udp.bind();
  }

  _setupICMPWatch() {
    this.udpListeningPort = this.udp.address().port;
    this.icmpWatcher = new ICMPWatcher({
      sourcePort: this.udpListeningPort,
    });
    this.on('complete', this.close.bind(this));
    this.icmpWatcher.on('error', e=>this.emit('error', e));
    this.icmpWatcher.on('response', (response)=>{
      // not sure if the explicitness helps, but good for reference purposes
      if (response.type === 3) {
        switch (response.code) {
          case 3:
            return this.markClosed(response.originalDestPort);
          case 0:
          case 1:
          case 2:
          case 9:
          case 10:
          case 13:
            return this.markOpenFiltered(response.originalDestPort);
        }
      }
      // all other cases
      this.markUnknown(response.originalDestPort);
    });
    this.icmpWatcher.getSocket();
    process.nextTick(()=>this.ready());
  }

  checkPort(port, cb) {
    if (!this.ready) return;
    this.callbacks[port] = cb;
    this.icmpWatcher.addDest(port);
    this.udp.send(this.msg, 0, this.msg.length, port, this.host);
    this.timedout[port] = setTimeout(()=>{
      this.markOpenFiltered(port);
    }, this.timeout);
  }

  close() {
    if (this.icmpWatcher) this.icmpWatcher.close();
    if (this.udp) this.udp.close();
  }

}

module.exports = UDPScanner;
