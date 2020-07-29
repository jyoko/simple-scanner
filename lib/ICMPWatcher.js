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
    this.sourcePort = opts.sourcePort;
    this.destPort = opts.destPort;
    this._debug = opts.debug || false;
    this.socket = opts.socket || null;
    this.addressFamily = opts.addressFamily === 6 ? raw.AddressFamily.IPv6 : raw.AddressFamily.IPv4;
    this.protocol = opts.adressFamily === 6 ? raw.Protocol.ICMPv6 : raw.Protocol.ICMP;
    this.packetSize = 12;
    this.ports = [];
    this.socket = null;

  }

  _debugResponse(src, buf) {
    console.log(`src=${src} buf=${buf.toString('hex')}`);
  }

  close() {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }

  getSocket() {
    if (this.socket) return this.socket;

    var options = {
      addressFamily: this.addressFamily,
      protocol: this.protocol,
    };

    try {
      this.socket = raw.createSocket(options);
    } catch(e) {
      this.emit('error',e);
    }
    this.socket.on("error", this.onSocketError.bind(this));
    this.socket.on("close", this.onSocketClose.bind(this));
    this.socket.on("message", this.onSocketMessage.bind(this));
    
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

    const incoming = this.fromBuffer(buf);
    if (incoming) {
      const ix = this.ports.indexOf(incoming.originalDestinationPort);
      this.ports.splice(ix,1);
      this.emit('response', incoming);
    }
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

  addDest(port) {
    this.ports.push(port);
  }

  addDestination(port) {
    this.ports.push(port);
  }

  fromBuffer(buf) {
    let offset, type, code, originalSourcePort, originalDestinationPort;

    if (this.addressFamily === raw.AddressFamily.IPv6) {
      offset = 0;
      if (buf.length - offset < 8) return;
      type = buf.readUInt8(offset);
      code = buf.readUInt8(offset+1);
    } else {
      // check minimum IP header length and matches IPv4
      if (buf.length<20 || (buf[0] & 0xf0) !== 0x40) {
        return;
      }

      // IP header in multiples of double words
      const ip_icmp_offset = (buf[0] & 0x0f) * 4;

      // check ICMP length (is at least valid header)
      if (buf.length - ip_icmp_offset < 8) return;

      type = buf.readUInt8(ip_icmp_offset);
      code = buf.readUInt8(ip_icmp_offset+1);

      offset = ip_icmp_offset;

      // error type responses require extra offset to find
      // sequence/identifier (includes request data)
      if (type === 3 || type === 4 || type === 5 || type === 11) {
        const ip_icmp_ip_offset = ip_icmp_offset + 8;
        if (buf.length - ip_icmp_ip_offset < 20 || (buf[ip_icmp_ip_offset]&0xf0)!==0x40) {
          return;
        }
        const ip_icmp_ip_len = (buf[ip_icmp_ip_offset] & 0x0f) * 4;

        // msg too short (UDP also 8byte min header)
        if (buf.length - ip_icmp_ip_offset - ip_icmp_ip_len < 8) {
          return;
        }

        offset = ip_icmp_ip_offset + ip_icmp_ip_len;
      }
    }

    // sessionId = buf.readUInt16BE(offset+4);

    // this will be the src/dest port from our UDP probe header
    originalSourcePort = buf.readUInt16BE(offset);
    originalDestinationPort = buf.readUInt16BE(offset+2);
    if (originalSourcePort !== this.sourcePort || this.ports.indexOf(originalDestinationPort) === -1) {
      return;
    }

    return {type,code,originalDestinationPort};
  }

}


module.exports = ICMPWatcher;
