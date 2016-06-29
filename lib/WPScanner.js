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
  }

  checkPort(port, cb) {

    function onProbeComplete(results) {

      // ignore timeout errors, toss others into output
      if (results.error && results.error.code!=='ETIMEDOUT') {
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
      port: port,
      onComplete: onProbeComplete,
    });

    wpProbe.start();

  }

}

module.exports = WPScanner;
