/*
 * UDP utilities
 *
 * Simple & straightforward, not much to UDP
 *
 * TODO: Support IPv6 checksum
 *       All new Buffer('')'s -> Buffer.alloc(0)
 *       allocUnsafe
 *
 */

const createChecksum = require('raw-socket').createChecksum;
const udpIpProtocolNumber = 17;

// does not compute checksum
function createHeader(config) {
  var sourcePort = config.sourcePort || 0;
  var destinationPort = config.destinationPort;
  var checksum = 0;
  var data = config.data || new Buffer('');
  var length = 8 + data.length;
  var header = Buffer.alloc(8);

  header.writeUInt16BE(sourcePort,0);
  header.writeUInt16BE(destinationPort,2);
  header.writeUInt16BE(length, 4);
  header.writeUInt16BE(checksum, 6);

  return header;
}

function createIpv4Pseudoheader(config) {
  var pseudoheader = Buffer.alloc(12,0);
  config.sourceAddress.split('.').map(Number).forEach((n,i)=>{
    pseudoheader.writeUInt8(n,i);
  });
  config.destinationAddress.split('.').map(Number).forEach((n,i)=>{
    pseudoheader.writeUInt8(n,i+4);
  });
  pseudoheader.writeUInt8(udpIpProtocolNumber,9);
  pseudoheader.writeUInt16BE(config.udpLength, 10);

  return pseudoheader;
}

function createDatagram(config) {
  var header = createHeader(config);
  var data = config.data || Buffer.alloc(0);
  var datagram = Buffer.concat([header,data],header.length+data.length);
  var pseudoheader;

  // default is to compute a checksum, hence the double negative
  if (!config.noChecksum) {

    // default IPv4
    pseudoheader = createIpv4Pseudoheader({
      sourceAddress: config.sourceAddress,
      destinationAddress: config.destinationAddress,
      udpLength: datagram.length,
    });

    checksum = createChecksum(pseudoheader, datagram);
    datagram.writeUInt16BE(checksum, 6);
  }

  return datagram;
}

function parseDatagram(buf) {
  var sourcePort = buf.readUInt16BE(0);
  var destinationPort = buf.readUInt16BE(2);
  var length = buf.readUInt16BE(4);
  var checksum = buf.readUInt16BE(6);
  var data = buf.slice(8);
  return {
    sourcePort,
    destinationPort,
    length,
    checksum,
    data,
  };
}

module.exports = {
  createDatagram,
  parseDatagram,
};
