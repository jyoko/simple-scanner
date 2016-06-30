/*
 * WordPress Enumeration Scanner
 *
 * The magic happens in WPProbe, this only handles the Scanner logic for
 * multiple probes and translating results
 *
 * TODO: Add external site support and/or rip off their methods:
 *         whatwpthemeisthat.com
 *         builtwith.com
 *         www.wpthemedetector.com
 */

const Scanner = require('./Scanner');
const WPProbe = require('./WPProbe');

/*
 * Scanner extension
 */

class WPScanner extends Scanner {

  constructor(config={}) {
    super(config);
    this.timeout = config.timeout || 2000;
    this.baseUri = config.baseUri;
  }

  checkPort(port, cb) {

    function onProbeComplete(results) {

      // ignoring common errors due to http->https or closed/filtered port
      // TODO: remove hardcode log, pass other errs on?
      if (results.error &&
          results.error.code!=='ETIMEDOUT' &&
          results.error.code!=='ECONNREFUSED') {
        console.log(`ERROR WP SCAN: port ${port}, ${results.error.code}`);
      }

      cb({
        port: port,
        data: {
          wordpress: results.wordpress,
          server: results.servers,
        }
      });
    }

    var wpProbe = new WPProbe({
      host: this.host,
      hostName: this.hostName,
      timeout: this.timeout,
      baseUri: this.baseUri,
      port: port,
      onComplete: onProbeComplete,
    });

    wpProbe.start();

  }

}

module.exports = WPScanner;
