/*
 * WordPress Enumeration Scanner
 *
 * Attempts to enumerate a WordPress installation using 3 methods:
 *
 *   1. Search index response(s) for WP strings
 *   2. Try default WP install files
 *   3. (Optional/TODO) Submit a URL to external checks like WP Theme Detectors
 *
 * Additionally it will note however the server self-identifies.
 *
 * TODO: Refactor to use WPProbe object
 *
 * TODO: Add external site support and/or rip off their methods:
 *         whatwpthemeisthat.com
 *         builtwith.com
 *         www.wpthemedetector.com
 */

const Scanner = require ('./Scanner');
const request = require('request');

// TODO: make this more dynamic, quick hack to workaround some blocks
const spoofUserAgent = 'Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543a Safari/419.3';

/*
 * Private (via module) functions
 */

function containsWPStrings(str) {
  return /(?:name="generator" content="wordpress)|(?:wp\-\w+)|(?:powered by wordpress)|(?:<!--.+wordpress.+-->)/i.test(str);
}

function containsWordpress(str) {
  return /wordpress/i.test(str);
}

/*
 * Scanner extension
 */

class WPScanner extends Scanner {

  constructor(config={}) {
    super(config);
    this.timeout = config.timeout || 2000;

    // TODO: Move this into separate file
    this.wpUrls = ['wp-admin','wp-login.php','license.txt','readme.html'];
    this.checkUrlStrings = 2; // hacky, starting index in wpUrls to also check strings
  }

  checkPort(port, cb) {

    function handleResponse(err, resp, body) {

      if (err) {
        return onError(err);
      }

      // TODO: hacking this in because some sites (looking at you, microsoft)
      //       like to lie on the URL probes, others (google) drop server
      //       headers on a 404. Need to clean it up
      originalServer = resp.headers['server'];

      if (resp.statusCode === 400) {
        return tryUpgrade();
      }

      wordpress = containsWPStrings(body);
      if (wordpress) {
        cb({
          port: port,
          data: {
            wordpress: wordpress,
            server: originalServer,
          }
        });
      } else {
        self._checkWPUrls(port, cb, upgrade, originalServer);
      }

    }

    function onError(e) {
      err = e;
      tryUpgrade();
    }

    function tryUpgrade() {
      if (upgrade) {
        cb({
          port: port,
          data: {
            error: err,
          }
        });
        return;
      }
      upgrade = true;
      var probe = self._makeRequest({
                https: upgrade,
                port: port,
                fn: handleResponse,
      });
    }

    var upgrade = false;
    var self = this;
    var err = null;
    var wordpress = false;
    var originalServer; // TODO: with above, hack to save first server header

    var probe = this._makeRequest({
      https: upgrade,
      port: port,
      fn: handleResponse,
    });

  }

  _makeRequest(opts) {
    var uri = (opts.https?'https':'http') + '://';
    uri += opts.https?this.hostName:this.host;
    uri += ':'+opts.port;
    uri += ('/'+opts.path || '');

    return request({
      uri: uri, 
      timeout: this.timeout,
      headers: {
        'User-Agent': spoofUserAgent,
      },
    }, opts.fn);
  }

  _checkWPUrls(port, cb, https, originalServer) {

    function handleResponse(err, resp, body) {
      // squashing errors here as they're almost certainly
      // not important to the results unless it's due to a network
      // failure. Maybe useful for advanced fingerprinting?
      if (err) {
        body = '';
        resp = {};
      }

      // check if response includes "wordpress" after this point
      if (urlIndex >= self.checkUrlStrings) {
        wordpress = containsWordpress(body);
      } else {
        // prior, a 200 response code indicates a positive result
        wordpress = (resp.statusCode === 200);
      }

      if (wordpress) {
        cb({
          port: port,
          data: {
            wordpress: wordpress,
            server: originalServer,
          }
        });
      } else {
        urlIndex++;
        if (urlIndex < self.wpUrls.length) {
          makeRequest();
        } else {
          // TODO external probe if indicated in config
          cb({
            port: port,
            data: {
              wordpress: wordpress,
              server: originalServer,
            }
          });
        }
      }
    }

    function makeRequest() {
      var probe = self._makeRequest({
        https: https,
        port: port,
        fn: handleResponse,
        path: self.wpUrls[urlIndex],
      });
    }

    var urlIndex = 0;
    var wordpress = false;
    var self = this;
    makeRequest();

  }
}

module.exports = WPScanner;
