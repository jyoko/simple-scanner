/*
 * TCPSocket
 *
 * Beginnings of a generic TCP wrapper for more advanced scans
 *
 * Used only in SYN half-open experiment for now.
 *
 * TODO: Document, test, make usable for Xmas/RST/NULL/etc
 *       wrap/expose useful bits in TCPutils?
 */

const raw = require('raw-socket');
const TCP = require('./TCPutils');
const EventListener = require('events');

class TCPSocket extends EventListener {

  constructor(config={}) {
    super();

    this.sourcePort = config.sourcePort || 54354; // TODO
    this.retries = config.retries || 1;
    this.timeout = config.timeout || 2000;
    this.addressFamily = raw.AddressFamily.IPv4;
    this._debug = config.debug || false;
    this.defaultTTL = config.ttl || 128;
    this.socket = null;
  }

  close() {
    if (this.socket) {
      this.socket.close();
    }
    delete this.socket;
  }

  _debugRequest(dest,req) {
    console.log(`request: target=${dest} buf=${req.buffer.toString('hex')}`);
  }

  _debugResponse(src, buf) {
    console.log(`response: src=${src} buf=${buf.toString('hex')}`);
  }

  getSocket() {
    if (this.socket) return this.socket;

    var protocol = raw.Protocol.TCP;
    var options = {
      addressFamily: this.addressFamily,
      protocol,
    };

    try {
      this.socket = raw.createSocket(options);
    } catch(e) {
      this.emit('error', e);
    }
    this.socket.on('error', this.onSocketError.bind(this));
    this.socket.on('close', this.onSocketClose.bind(this));
    this.socket.on('message', this.onSocketMessage.bind(this));

    return this.socket;
  }

  onSocketClose() {
    this.emit('close');
  }

  onSocketError(e) {
    this.emit('error',e);
  }

  onSocketMessage(buf,src) {
    if (this._debug) {
      this._debugResponse(src,buf);
    }

    var req = this.fromBuffer(buf);
    if (req) {
      this.emit('response', req);
    }
  }

  onBeforeSocketSend() {
    this.setTTL(this.defaultTTL);
  }

  onSocketSend(req, error, bytes) {
    // placeholder
  }

  setTTL(ttl) {
    if (this.ttl && this.ttl === ttl) return;

    var level = raw.SocketLevel.IPPROTO_IP;
    this.getSocket().setOption(level, raw.SocketOption.IP_TTL, ttl);
    this.ttl = ttl;
  }

  send(req) {

    req.sourcePort = req.sourcePort || this.sourcePort;
    var buf = TCP.createSegment(req);
    if (this.getSocket().recvPaused) {
      this.getSocket().resumeRecv();
    }
    this.getSocket().send(buf, 0, buf.length, req.destinationAddress,
                          this.onBeforeSocketSend.bind(this,req),
                          this.onSocketSend.bind(this,req));

  }

  fromBuffer(buf) {
    var offset;

    // minimum IP header & IPv4
    if (buf.length < 20 || (buf[0]&0xf0) !== 0x40) {
      return;
    }

    // length of IPv4 in multiples of dbl words
    var ip_offset = (buf[0] & 0x0f) * 4;

    // check minimum TCP header length
    if (buf.length - ip_offset < 20) {
      return;
    }

    // get src/dest IP
    var srcIp = '', destIp = '';
    for (var i=0; i<4; i++) {
      srcIp += buf.readUInt8(12+i) + (i<3?'.':'');
      destIp += buf.readUInt8(16+i) + (i<3?'.':'');
    }

    var info = TCP.parseSegment(buf.slice(ip_offset));
    info.sourceAddress = srcIp;
    info.destinationAddress = destIp;

    // only filtering by port
    if (info.destinationPort === this.sourcePort) {
      return info;
    }
  }

}

module.exports = TCPSocket;
