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

const utilities = require('./utilities');
const createChecksum = require('raw-socket').createChecksum;
const isIP = require('net').isIP;

const FIN_FLAG = 0b1;
const SYN_FLAG = 0b10;
const RST_FLAG = 0b100;
const PSH_FLAG = 0b1000;
const ACK_FLAG = 0b10000;
const URG_FLAG = 0b100000;
const ECE_FLAG = 0b1000000;
const CWR_FLAG = 0b10000000;
// 9th bit from experimental RFC 3540
// https://tools.ietf.org/html/rfc3540
const NS_FLAG  = 0b100000000;

function ipv4StrToIntArr(str) {
  return str.split('.').map(Number);
}

function ipv6StrToIntArr(str) {
  const fields = [];
  let expandIx = null;
  let v = '';
  function err(msg) {
    throw new Error(`Invalid IPv6 address: ${msg}`);
  }
  for (let i=0; i<str.length; i++) {
    if (str[i] === ':') {
      if (str[i+1] === ':') {
        if (expandIx !== null) err('too many delimiters');
        if (v !== '') {
          fields.push(parseInt(v,16));
          v='';
        }
        expandIx = fields.length;
        ++i;
      } else {
        if (v === '') err('bad delimiter');
        fields.push(parseInt(v,16));
        v='';
      }
    } else {
      v += str[i];
    }
  }

  if (v !== '') {
    fields.push(parseInt(v,16));
  } else {
    if (expandIx !== fields.length) err('ends incorrectly');
  }
  return expandIx === null ? fields : fields.slice(0,expandIx).concat(Array(8-fields.length).fill(0), fields.slice(expandIx));
}

// segmentLength in bytes
function createPseudoHeader(config) {
  let pseudoHeader;
  const segmentLength = config.segmentLength || 0;
  if (isIP(config.sourceAddress)===4 && isIP(config.destinationAddress)===4) {
    // always 12 bytes
    pseudoHeader = Buffer.alloc(12,0);
    ipv4StrToIntArr(config.sourceAddress).forEach((n,i)=>{
      pseudoHeader.writeUInt8(n,i);
    });
    ipv4StrToIntArr(config.destinationAddress).forEach((n,i)=>{
      pseudoHeader.writeUInt8(n,i+4);
    });
    //already 0'd out buffer
    //pseudoHeader.writeUInt8(0,8);
    // protocol for TCP
    pseudoHeader.writeUInt8(6,9);
    // length (in bytes) of entire segment (NOT including pseudoheader)
    pseudoHeader.writeUInt16BE(segmentLength,10);
  }
  if (isIP(config.sourceAddress)===6 && isIP(config.destinationAddress)===6) {
    // 128bit source, 128bit dest, 32bit length, 24bit zeroes, 8bit protocol
    pseudoHeader = Buffer.alloc(40,0);
    ipv6StrToIntArr(config.sourceAddress).forEach((n,i)=>{
      pseudoHeader.writeUInt16BE(n,i*2);
    });
    ipv6StrToIntArr(config.destinationAddress).forEach((n,i)=>{
      pseudoHeader.writeUInt16BE(n,(i*2)+16);
    });
    // length (in bytes) of entire segment (NOT including pseudoheader)
    pseudoHeader.writeUInt32BE(segmentLength,32);
    //already 0'd out buffer
    //pseudoHeader.writeUInt16BE(0,36);+byte
    // protocol for TCP
    pseudoHeader.writeUInt8(6,39);
  }

  return pseudoHeader;
}

// TCP Options must be given as buffer,
// urgent pointer calculations also left to user
function createHeader(config) {
  const sourcePort = config.sourcePort;
  const destPort = config.destinationPort;
  if (!utilities.isValidPort(sourcePort) || !utilities.isValidPort(destPort)) {
    throw new Error('Invalid port given');
  }
  // zero-fill right shift coerces to unsigned 32-bit int (unlike other bitwise ops)
  // (needed to guarantee positive)
  const seqNum = config.seqNum || (Math.random()*0xfffffffe+1)>>>0;
  const ackNum = config.ackNum || 0;
  const tcpOpts = config.tcpOpts || null;
  const windowSize = config.windowSize || 0xfffc; // 0? 0xffff?
  const urgPointer = config.urgPointer || 0;
  let nsFlag=0,flags=0;
  if (Array.isArray(config.flags)) {
    config.flags.forEach(flag=>{
      if (flag & NS_FLAG) {
        nsFlag = 1;
        return;
      }
      flags = flags | flag;
    });
  } else if (config.flags) {
    if (config.flags & NS_FLAG) {
      nsFlag = 1;
      flags = config.flags & 255;
    } else {
      flags = config.flags;
    }
  }

  // data offset = header length, 20 bytes if no options given
  const offset = 20 + (tcpOpts ? tcpOpts.length : 0);
  const offsetIn32Words = (offset*8)/32; // for 4-bit field
  if (offsetIn32Words%1 !== 0) {
    throw new Error('TCP options should be buffer containing 32 bit words');
  }

  const packet = Buffer.alloc(offset,0);
  packet.writeUInt16BE(sourcePort, 0);
  packet.writeUInt16BE(destPort,2);
  packet.writeUInt32BE(seqNum,4);
  packet.writeUInt32BE(ackNum,8);
  // offset . reserved(0) . NS_FLAG = byte
  const twelthByte = offsetIn32Words<<4 | nsFlag;
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
  const destinationAddress    = config.destinationAddress;
  const sourceAddress         = config.sourceAddress;
  const destinationPort       = config.destinationPort;
  const sourcePort            = config.sourcePort;
  const data                  = config.data           || Buffer.alloc(0);
  const dataLength            = data.length;
  const seqNum                = config.seqNum         || 0;
  const ackNum                = config.ackNum         || 0;
  const flags                 = config.flags          || 0;
  const urgPointer            = config.urgentPointer  || 0;
  const tcpOpts               = config.tcpOpts        || 0;
  const windowSize            = config.windowSize     || 0;

  const header = createHeader({
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
  const segmentLength = header.length + data.length;
  const pseudoheader = createPseudoHeader({
    destinationAddress,
    sourceAddress,
    segmentLength,
  });

  const segment = Buffer.concat([header,data], segmentLength);
  const checksum = createChecksum(pseudoheader,segment);
  segment.writeUInt16BE(checksum, 16);

  return segment;
}

function parseFlags(byte, nsFlag) {
  const found = {};
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
  const sourcePort = buf.readUInt16BE(0);
  const destinationPort = buf.readUInt16BE(2);
  const seqNum = buf.readUInt32BE(4);
  const ackNum = buf.readUInt32BE(8);
  const twelthByte = buf.readUInt8(12).toString(2).split('');
  const nsFlag = parseInt(twelthByte.pop());
  twelthByte.splice(-3); // ignore reserved
  // 32-bit word to byte length
  const offset = parseInt(twelthByte.join(''),2) * 4;
  const flags = parseFlags(buf.readUInt8(13), nsFlag);
  const windowSize = buf.readUInt16BE(14);
  const checksum = buf.readUInt16BE(16);
  const urgPointer = buf.readUInt16BE(18);
  const tcpOpts = (offset>20) ? buf.slice(20, offset) : null;
  const data = buf.slice(offset);
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
