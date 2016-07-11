/*
 * IP utilities
 *
 * Getting setup to switch from ICMP/TCP/etc to raw headers for better filtering
 * from a single socket.
 *
 * Planning on pretty limited scope initially - and only IPv4 support.
 *
 * TODO: TEST ME! tentatively OK
 *       "Fast" parse funcs -> limit reading, maybe just ihl/proto/src/dest?
 *
 */

const createChecksum = require('raw-socket').createChecksum;

const Protocols = {
  ICMP: 1,
  ICMPv6: 58,
  TCP: 6,
  UDP: 17,
  SCTP: 132,
}

const Flags = {
  DF: 0b10,
  MF: 0b100,
}

function createHeader(config) {
  var version = config.version || 4;
  var data = config.data || new Buffer('');
  var dataLength = data.length;
  var ipOpts = config.ipOpts || new Buffer('');
  // 32-bit words
  var ipOptsLength = (ipOpts.length * 8) / 32;
  var ihl = 5 + ipOptsLength;
  var dscp = 0;
  var ecn = 0;
  var length = (ihl * 4) + data.length;
  var ident = config.identification || (Math.random() * 0xfffe + 1)|0;
  var ipFlags = config.ipFlags || 0;
  var fragmentOffset = config.fragmentOffset || 0;
  var ttl = config.ttl || 128;
  var protocol = config.protocol || Protocols.TCP;
  var checksum = 0;
  var sourceAddress = config.sourceAddress.split('.').map(Number).reduce((n,octet)=>{
    return (n<<8)|octet;
  },0)>>>0;
  var destinationAddress = config.destinationAddress.split('.').map(Number).reduce((n,octet,i)=>{
    return (n<<8)|octet;
  },0)>>>0;

  var header = Buffer.alloc(length, 0);
  var firstByte = (version<<4)|ihl;
  header.writeUInt8(firstByte,0);
  var secondByte = (dscp<<2) | ecn; // unnecessary: yes, 0 (for now)
  header.writeUInt8(secondByte,1);
  header.writeUInt16BE(length,2);
  header.writeUInt16BE(ident, 4);
  var sevenEightBytes = (ipFlags<<13)|fragmentOffset; // same as above
  header.writeUInt16BE(sevenEightBytes, 6);
  header.writeUInt8(ttl, 8);
  header.writeUInt8(protocol,9);
  // checksum = 0
  header.writeUInt32BE(sourceAddress,12);
  header.writeUInt32BE(destinationAddress,16);

  if (ipOptsLength) {
    ipOpts.copy(header, 20);
  }

  checksum = createChecksum(header);
  header.writeUInt16BE(checksum,10);
  if (data.length) {
    data.copy(header,ihl*4)
  }

  return header;
}

function parseHeader(buf) {
  // first 4 bits or 0x40/0x60 w/o shift
  var version = (buf[0]&0xf0)>>4;
  // 32bit words->bytes
  var ihl = (buf[0]&0xf)*4;
  // 6 and 2
  var dscp = (buf[1]&0xfc)>>2;
  var ecn = buf[1]&0x02;
  var length = buf.readUInt16BE(2);
  var ident = buf.readUInt16BE(4);
  // first 3 bits
  var ipFlags = (buf[6]&0xe0)>>5;
  // last 13 bits
  var fragOffset = buf.readUInt16BE(6)&0x1fff;
  var ttl = buf[8];
  var protocol = buf[9];
  var checksum = buf.readUInt16BE(10);
  var sourceIp = '', destinationIp = '';
  for (var i=0; i<4; i++) {
    sourceIp += buf.readUInt8(12+i) + (i<3?'.':'');
    destinationIp += buf.readUInt8(16+i) + (i<3?'.':'');
  }
  var opts = null;
  if (ihl>20) {
    opts = buf.slice(20,ihl);
  }
  var data = buf.slice(ihl);
  // not in v6
  var checksumOk = !createChecksum(buf.slice(0,ihl));

  return {
    checksumOk,
    version,
    ihl,
    dscp,
    ecn,
    length,
    ident,
    ipFlags,
    fragOffset,
    ttl,
    protocol,
    checksum,
    sourceIp,
    destinationIp,
    opts,
    data,
  };

}

module.exports = {
  Protocols,
  Flags,
  createHeader,
  parseHeader,
};
