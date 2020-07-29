/*
 * TCPSocket
 *
 * Beginnings of a generic TCP wrapper for more advanced scans
 *
 * TODO: Document, test
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
    this.addressFamily = config.addressFamily === 6 ? raw.AddressFamily.IPv6 : raw.AddressFamily.IPv4;
    this._debug = config.debug || false;
    this.defaultTTL = config.ttl || 128;
    this.socket = null;
  }

  close() {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }

  _debugRequest(dest,buf) {
    console.log(`request: target=${dest} buf=${buf.toString('hex')}`);
  }

  _debugResponse(src, buf) {
    console.log(`response: src=${src} buf=${buf.toString('hex')}`);
  }

  getSocket() {
    if (this.socket) return this.socket;

    const protocol = raw.Protocol.TCP;
    const options = {
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

    const incoming = this.fromBuffer(buf);
    // only checks port
    if (incoming) {
      // not given IP headers with IPv6
      if (!incoming.sourceAddress) incoming.sourceAddress = src;
      this.emit('response', incoming);
    }
  }

  onBeforeSocketSend() {
    this.setTTL(this.defaultTTL);
  }

  onSocketSend(req, error, bytes) {
    if (error) this.emit('error',error);
  }

  setTTL(ttl) {
    if (this.ttl && this.ttl === ttl) return;

    if (this.addressFamily === raw.AddressFamily.IPv6) {
      this.getSocket().setOption(raw.SocketLevel.IPPROTO_IPV6, raw.SocketOption.IPV6_TTL, ttl);
    } else {
      this.getSocket().setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_TTL, ttl);
    }
    this.ttl = ttl;
  }

  send(req) {

    req.sourcePort = req.sourcePort || this.sourcePort;
    const buf = TCP.createSegment(req);
    if (this._debug)  {
      this._debugRequest(req.destinationAddress,buf);
    }
    if (this.getSocket().recvPaused) {
      this.getSocket().resumeRecv();
    }
    this.getSocket().send(buf, 0, buf.length, req.destinationAddress,
                          this.onBeforeSocketSend.bind(this,req),
                          this.onSocketSend.bind(this,req));

  }

  fromBuffer(buf) {

    if (this.addressFamily === raw.AddressFamily.IPv4) {
      // minimum IP header & IPv4
      if (buf.length < 20 || (buf[0]&0xf0) !== 0x40) {
        return;
      }

      // length of IPv4 in multiples of dbl words
      const ip_offset = (buf[0] & 0x0f) * 4;

      // check minimum TCP header length
      if (buf.length - ip_offset < 20) {
        return;
      }

      // get src/dest IP
      let srcIp = '', destIp = '';
      for (let i=0; i<4; i++) {
        srcIp += buf.readUInt8(12+i) + (i<3?'.':'');
        destIp += buf.readUInt8(16+i) + (i<3?'.':'');
      }

      const info = TCP.parseSegment(buf.slice(ip_offset));
      info.sourceAddress = srcIp;
      info.destinationAddress = destIp;

      // only filtering by port
      if (info.destinationPort === this.sourcePort) {
        return info;
      }
    }

    if (this.addressFamily === raw.AddressFamily.IPv6) {
      // minimum IP header and IPv6
      const info = TCP.parseSegment(buf);
      if (info.destinationPort === this.sourcePort) {
        return info;
      }
    }

  }

}

module.exports = TCPSocket;
