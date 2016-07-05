/*
 * TCP Utilities
 *
 * Functional, needs some TLC.
 *
 * Exposes TCP flags (SYN,ACK,FIN,RST, etc as NAME_FLAG) and 4 functions.
 *
 * createPseudoHeader : takes object with destinationAddress, sourceAddress, and segmentLength
 *                      returns Buffer with pseudo header for generating checksums
 * 
 * createHeader       : takes object with destinationPort, sourcePort, seqNum, ackNum, flags,
 *                       urgPointer, tcpOpts, windowSize, and data
 *                      returns Buffer with TCP header (0-filled checksum)
 *
 * createSegment      : takes the following values:
 *                       destinationAddress - IP of destination (required)
 *                       sourceAddress      - IP of sender (required)
 *                       destinationPort    - port of destination (required)
 *                       sourcePort         - port of sender (required)
 *                       data               - Buffer containing data body (default none)
 *                       seqNum             - sequence number to use (default random)
 *                       ackNum             - acknowledgement number to use (default 0)
 *                       flags              - single flag or array of flags (default none)
 *                       urgPointer         - offset from seqNum indicating final urgent byte if URG_FLAG set (default 0)
 *                       tcpOpts            - Buffer containing other options (default none) (TODO: not have to craft yourself)
 *                       windowSize         - size of the receive window (default 65532 - arbitrary)
 *                      returns Buffer with valid segment and checksum set
 *
 * parseSegment       : takes Buffer containing TCP segment
 *                      returns object with information matching createSegment's input
 *                       with two additional properties:
 *                       offset             - the length of the TCP header
 *                       checksum           - checksum from the TCP header
 *                      changed:
 *                       flags              - object with Boolean values for every flags.FLG_FLAG
 *
 * TODO: Usability (tcpOpts, input data, srcPort, URG data, etc)
 *       Optimization (unknown if problematic but lots of low-hanging inefficiencies)
 */

var utilities = require('./utilities');
var createChecksum = require('raw-socket').createChecksum;

var FIN_FLAG = 0b1;
var SYN_FLAG = 0b10;
var RST_FLAG = 0b100;
var PSH_FLAG = 0b1000;
var ACK_FLAG = 0b10000;
var URG_FLAG = 0b100000;
var ECE_FLAG = 0b1000000;
var CWR_FLAG = 0b10000000;
// 9th bit from experimental RFC 3540
// https://tools.ietf.org/html/rfc3540
var NS_FLAG  = 0b100000000;

// segmentLength in bytes
function createPseudoHeader(config) {
  config.protocol = 'IP4'; // TODO
  var segmentLength = config.segmentLength || 0;
  // always 12 bytes
  var pseudoHeader = Buffer.alloc(12,0);
  config.sourceAddress.split('.').map(Number).forEach((n,i)=>{
    pseudoHeader.writeUInt8(n,i);
  });
  config.destinationAddress.split('.').map(Number).forEach((n,i)=>{
    pseudoHeader.writeUInt8(n,i+4);
  });
  pseudoHeader.writeUInt8(0,8);
  pseudoHeader.writeUInt8(6,9);
  // length (in bytes) of entire segment (NOT including pseudoheader)
  pseudoHeader.writeUInt16BE(segmentLength,10);

  return pseudoHeader;
}

// TCP Options must be given as buffer,
// urgent pointer calculations also left to user
function createHeader(config) {
  var sourcePort = config.sourcePort;
  var destPort = config.destinationPort;
  if (!utilities.isValidPort(sourcePort) || !utilities.isValidPort(destPort)) {
    throw new Error('Invalid port given');
  }
  // zero-fill right shift coerces to unsigned 32-bit int (unlike other bitwise ops)
  // (needed to guarantee positive)
  var seqNum = config.seqNum || (Math.random()*0xfffffffe+1)>>>0;
  var ackNum = config.ackNum || 0;
  var tcpOpts = config.tcpOpts || null;
  var windowSize = config.windowSize || 0xfffc; // 0? 0xffff?
  var urgPointer = config.urgPointer || 0;
  var nsFlag=0,flags=0;
  if (Array.isArray(config.flags)) {
    config.flags.forEach(flag=>{
      if (flag === NS_FLAG) {
        nsFlag = 1;
        return;
      }
      flags = flags | flag;
    });
  } else if (config.flags) {
    if (config.flag === NS_FLAG) {
      nsFlag = 1;
    } else {
      flags = config.flags;
    }
  }

  // data offset = header length, 20 bytes if no options given
  var offset = tcpOpts? tcpOpts.length : 0;
  offset += 20;
  var offsetIn32Words = (offset*8)/32; // for 4-bit field
  if (offsetIn32Words%1 !== 0) {
    throw new Error('TCP options should be buffer containing 32 bit words');
  }

  var packet = Buffer.alloc(offset,0);
  packet.writeUInt16BE(sourcePort, 0);
  packet.writeUInt16BE(destPort,2);
  packet.writeUInt32BE(seqNum,4);
  packet.writeUInt32BE(ackNum,8);
  // offset . reserved(0) . NS_FLAG = byte
  var twelthByte = parseInt(offsetIn32Words.toString(2) + '000' + nsFlag, 2);
  packet.writeUInt8(twelthByte, 12);
  packet.writeUInt8(flags, 13);
  packet.writeUInt16BE(windowSize, 14);
  // checksum is 0'd
  packet.writeUInt16BE(urgPointer, 18);

  if (tcpOpts) {
    tcpOpts.copy(packet, 20);
  }

  return packet;
}

function createSegment(config) {
  var destinationAddress    = config.destinationAddress;
  var sourceAddress         = config.sourceAddress;
  var destinationPort       = config.destinationPort;
  var sourcePort            = config.sourcePort;
  var data                  = config.data           || new Buffer('');
  var dataLength            = data.length;
  var seqNum                = config.sequenceNumber || 0;
  var ackNum                = config.ackNumber      || 0;
  var flags                 = config.flags          || 0;
  var urgPointer            = config.urgentPointer  || 0;
  var tcpOpts               = config.tcpOptions     || 0;
  var windowSize            = config.windowSize     || 0;

  var header = createHeader({
    destinationPort,
    sourcePort,
    seqNum,
    ackNum,
    flags,
    urgPointer,
    tcpOpts,
    windowSize,
    dataLength,
  });
  var segmentLength = header.length + data.length;
  var pseudoheader = createPseudoHeader({
    destinationAddress,
    sourceAddress,
    segmentLength,
  });

  var segment = Buffer.concat([header,data], segmentLength);
  var checksum = createChecksum(pseudoheader,segment);
  segment.writeUInt16BE(checksum, 16);

  return segment;
}

function parseFlags(byte, nsFlag) {
  var found = {};
  found.FIN_FLAG = !!(byte&FIN_FLAG);
  found.SYN_FLAG = !!(byte&SYN_FLAG);
  found.RST_FLAG = !!(byte&RST_FLAG);
  found.PSH_FLAG = !!(byte&PSH_FLAG);
  found.ACK_FLAG = !!(byte&ACK_FLAG);
  found.URG_FLAG = !!(byte&URG_FLAG);
  found.ECE_FLAG = !!(byte&ECE_FLAG);
  found.CWR_FLAG = !!(byte&CWR_FLAG);
  found.NS_FLAG  = !!nsFlag;
  return found;
}

function parseSegment(buf) {
  var sourcePort = buf.readUInt16BE(0);
  var destinationPort = buf.readUInt16BE(2);
  var seqNum = buf.readUInt32BE(4);
  var ackNum = buf.readUInt32BE(8);
  var twelthByte = buf.readUInt8(12).toString(2).split('');
  var nsFlag = parseInt(twelthByte.pop());
  twelthByte.splice(-3); // ignore reserved
  // 32-bit word to byte length
  var offset = parseInt(twelthByte.join(''),2) * 4;
  var flags = parseFlags(buf.readUInt8(13), nsFlag);
  var windowSize = buf.readUInt16BE(14);
  var checksum = buf.readUInt16BE(16);
  var urgPointer = buf.readUInt16BE(18);
  var tcpOpts = (offset>20) ? buf.slice(20, offset) : null;
  var data = buf.slice(offset);
  return {
    sourcePort,
    destinationPort,
    seqNum,
    ackNum,
    offset,
    flags,
    windowSize,
    checksum,
    urgPointer,
    tcpOpts,
    data,
  };
}

module.exports = {
  FIN_FLAG,
  SYN_FLAG,
  RST_FLAG,
  PSH_FLAG,
  ACK_FLAG,
  URG_FLAG,
  ECE_FLAG,
  CWR_FLAG,
  NS_FLAG,
  createPseudoHeader,
  createHeader,
  createSegment,
  parseSegment,
};
