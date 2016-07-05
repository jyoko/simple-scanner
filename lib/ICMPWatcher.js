/*
 * Looks for relevant incoming ICMPv4 packets
 * Specifically type 3, codes 0,1,2,3,9,10,13
 *
 * Heavily inspired by code in node-net-ping
 *
 * TODO: full parsing, v6
 */

const raw = require('raw-socket');
const EventEmitter = require('events');

class ICMPWatcher extends EventEmitter {

  constructor(opts={}) {
    super();

    this.timeout = opts.timeout || 2000;
    this.defaultTTL = opts.ttl || 128;
    this.srcPort = opts.srcPort;
    this.destPort = opts.destPort;
    this._debug = opts.debug || false;
    this.socket = null;
    this.addressFamily = raw.AddressFamily.IPv4;
    this.packetSize = 12;
    this.ports = [];

  }

  _debugResponse(src, buf) {
    console.log(`src=${src} buf=${buf.toString('hex')}`);
  }

  close() {
    if (this.socket) {
      this.socket.close();
      delete this.socket;
    }
  }

  getSocket() {
    if (this.socket) return this.socket;

    var protocol = raw.Protocol.ICMP;

    var options = {
      addressFamily: this.addressFamily,
      protocol: protocol,
    };

    try {
      this.socket = raw.createSocket(options);
    } catch(e) {
      this.emit('error',e);
    }
    this.socket.on("error", this.onSocketError.bind(this));
    this.socket.on("close", this.onSocketClose.bind(this));
    this.socket.on("message", this.onSocketMessage.bind(this));
    
    this.ttl = null;
    this.setTTL(this.defaultTTL);
    
    return this.socket;
  }

  onSocketClose() {
    this.emit('close');
  }

  onSocketError(err) {
    this.emit('error', err);
  }

  onSocketMessage(buf, src) {
    if (this._debug) {
      this._debugResponse(src,buf);
    }

    var resp = this.fromBuffer(buf);
    if (resp) {
      var ix = this.ports.indexOf(resp.originalDestPort);
      this.ports.splice(ix,1);
      this.emit('response', resp);
    }
  }

  setTTL(ttl) {
    if (this.ttl && this.ttl === ttl) return;

    var level = raw.SocketLevel.IPPROTO_IP;
    this.getSocket().setOption(level, raw.SocketOption.IP_TTL, ttl);
    this.ttl = ttl;
  }

  addDest(port) {
    this.ports.push(port);
  }

  fromBuffer(buf) {
    var offset, type, code, originalSourcePort, originalDestPort;

    // check minimum IP header length and matches IPv4
    if (buf.length<20 || (buf[0] & 0xf0) !== 0x40) {
      return;
    }

    // IP header in multiples of double words
    var ip_icmp_offset = (buf[0] & 0x0f) * 4;

    // check ICMP length (is at least valid header)
    if (buf.length - ip_icmp_offset < 8) {
      return;
    }

    type = buf.readUInt8(ip_icmp_offset);
    code = buf.readUInt8(ip_icmp_offset+1);

    offset = ip_icmp_offset;

    // error type responses require extra offset to find
    // sequence/identifier (includes request data)
    if (type === 3 || type === 4 || type === 5 || type === 11) {
      var ip_icmp_ip_offset = ip_icmp_offset + 8;
      if (buf.length - ip_icmp_ip_offset < 20 || (buf[ip_icmp_ip_offset]&0xf0)!==0x40) {
        return;
      }
      var ip_icmp_ip_len = (buf[ip_icmp_ip_offset] & 0x0f) * 4;

      // msg too short (UDP also 8byte min header)
      if (buf.length - ip_icmp_ip_offset - ip_icmp_ip_len < 8) {
        return;
      }

      offset = ip_icmp_ip_offset + ip_icmp_ip_len;
    }

    // this will be the src/dest port from our UDP probe header
    originalSourcePort = buf.readUInt16BE(offset);
    originalDestPort = buf.readUInt16BE(offset+2);
    if (originalSourcePort !== this.srcPort || this.ports.indexOf(originalDestPort) === -1) {
      return;
    }

    return {type,code,originalDestPort};
  }

}


module.exports = ICMPWatcher;
