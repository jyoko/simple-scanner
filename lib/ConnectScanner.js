/*
 * Port Scanner
 *
 * Simple TCP connect scanner, will detect open/closed/filtered ports
 * and pass on any data received upon connection (like a server banner)
 *
 */

const net = require('net');
const Scanner = require('./Scanner');

class ConnectScanner extends Scanner {

  // adds timeout
  constructor(config={}) {
    super(config);
  }

  // implements scanning method
  checkPort(port, cb) {

    const result = {
      port:port,
      data: {
        status:'filtered', // default, left alone if connection timed out
     }
    };

    function onData(d) {
      result.data.response = d.toString();
      probe.destroy();
    }

    function onError(e) {
      // only change status if connection hasn't been established
      // prior to error
      if (result.data.status === 'filtered') {
        result.data.status = 'closed';
      }

      // Refused connection errors are normal for packets being dropped
      // due to being rate limited, flagged by an IDS, or the firewall config.
      // Pass along other errors as they might be helpful or informative
      if (e.code!=='ECONNREFUSED') {
        result.data.warning = `Connection error : ${e.code}, ${port} may be marked closed`;
      }
    }

    function onClose() {
      cb(result);
    }

    const probe = net.createConnection(port, this.host, _=>{
      result.data.status = 'open';
    });
    probe.setTimeout(this.timeout, ()=>probe.destroy());
    probe.on('data', onData); 
    probe.on('error', onError);
    probe.on('close', onClose);
  };

}

module.exports = PortScanner;
