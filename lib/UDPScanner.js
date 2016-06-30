/*
 * UDP Scanner
 *
 * Consumer of UDPScanner should wait until icmpready event
 *
 * Probably requires root (maybe not on some Macs or Windows??)
 * Because raw socket needed to listen for relevant ICMP responses
 * Essentially borrowing nmap's UDP scan logic from description (not source):
 *
 *   Send rate-limited packets (using Node dgram)
 *   If packet received mark 'open' (using Node dgram)
 *   If no response or ICMP type 3, codes 0,1,2,9,10,13 mark 'open|filtered'
 *   If ICMP type 3 code 3 mark 'closed'
 *
 * Code is a bit messy and is an experiment with using raw-socket, expect
 * this to change!
 *
 *
 * TODO: use raw socket to send UDP req, just listen with dgram
 *       dgramSocket.send in node docs seems to require a msg/length
 *       support IPv6
 */

const dgram = require('dgram');
const Scanner = require('./Scanner');
const ICMPWatcher = require('./ICMPWatcher');

class UDPScanner extends Scanner {

  constructor(config={}) {
    config.rateLimit = config.rateLimit || 500; // default 2 per sec
    super(config);
    this.timeout = config.timeout || 2000;
    this.ready = false;
    this.callbacks = {};
    this.udp = dgram.createSocket('udp4');
    this.udpMsg = new Buffer('');
    this.udpMsgLength = this.udpMsg.length;
    this.udp.on('error', this.onError.bind(this));
    this.udp.on('message', this.markOpen.bind(this));
    this.udp.on('listening', this.setupICMPWatch.bind(this));
    this.udp.bind();
  }

  setupICMPWatch() {
    this.udpListeningPort = this.udp.address().port;
    this.icmpWatcher = new ICMPWatcher({
      srcPort: this.udpListeningPort,
    });
    this.on('complete', this.close.bind(this));
    this.icmpWatcher.on('error', function(e) {
      this.emit('error', e);
      return;
    }.bind(this));
    this.icmpWatcher.on('response', function(response) {
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
      this.markUnknown(response);
    }.bind(this));
    this.icmpWatcher.getSocket();
    this.ready = true;
    if (this.state === 1) {
      this.emit('icmpready');
    } else {
      this.on('ready', function() {
        this.emit('icmpready');
      }.bind(this));
    }
  }

  checkPort(port, cb) {

    if (!this.ready) return;
    this.callbacks[port] = cb;
    this.icmpWatcher.addDest(port);
    this.udp.send(this.udpMsg, 0, this.udpMsgLength, port, this.host);

  }

  markClosed(port) {
    this.callbacks[port]({
      port,
      data: {
        status: 'closed',
      }
    });
  }

  markOpenFiltered(port) {
    this.callbacks[port]({
      port,
      data: {
        status: 'open|filtered',
      }
    });
  }

  markOpen(msg, rinfo) {
    // check incoming data is from our desired host
    // _may_ not always be desired behavior
    if (rinfo.address !== this.host && rinfo.address !== this.hostName) {
      return;
    }
    var port = rinfo.port;
    this.callbacks[port]({
      port,
      data: {
        status: 'open',
      }
    });
  }

  onError(e) {
    console.log(e);
  }

  close() {
    this.icmpWatcher.close();
    this.udp.close();
  }

}

module.exports = UDPScanner;
