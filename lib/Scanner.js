/*
 * Scanner base class
 *
 * Scanner is an EventEmitter, typically emitting:
 *   error, ready, portFinished, stop, complete
 *
 * It takes an array of ports or a range/interval and will cap parallel connections.
 *
 * This base class does a DNS lookup on the given host (see note in constructor) but requires
 * the user to add an implementation of checkPort (name configurable) to test a given port.
 *
 * There is a blank, static checkPort on Scanner for reference. Implementations must:
 *
 *   1. Take a port number as the first argument
 *   2. Take a callback as a second argument
 *   3. Pass an object to the callback when complete in the form:
 *      { port: portNumber, data: ANY_FORMAT }
 *
 * For user convenience, there are also state (returns number) and status (returns string)  
 * getters in addition to the emitted events.
 *
 *   State    -    Status
 *    -1          resolving
 *     0          error
 *     1          ready
 *     2          active (scan in progress)
 *     3          stopped (paused scan)
 *     4          complete (finished scan, data available in Scanner.scanResults
 *
 * Note that calling Scanner.pause or Scanner.stop does not immediately halt the scan,
 * only ceases new outgoing connections. Any in-progress probes will finish.
 *
 * Restart by calling Scanner.scan again.
 *
 *
 * TODO's:
 *
 *  - Centralize thrown error messages
 *  - TS definition or JSDoc or similar
 *  - Backoff and retry
 *
 */

const dns = require('dns');
const EventEmitter = require('events');
const utilities = require('./utilities');
const CHECK_PORT_METHOD = 'checkPort';

class Scanner extends EventEmitter {

  constructor(config={}) {
    super();

    this.hostName = config.host || 'localhost';
    this.maxParallel = config.maxParallel || 12;
    // rate limit (if non-zero) currently will set parallel connections to 1 to enforce
    // limited connections TODO: more timing controls!
    this.rateLimit = config.rateLimit || 0; // give in ms
    this.timeouts = [];
    // handles given list or range from config, optional start, end, interval for default 
    this.portList = this._makePortList(config, 1, 1000, 1);
    this._delta = 1;
    this._state = -1;
    this.portIndex = 0;
    this.scanResults = [];
    this.error = null;

    if (this.rateLimit) {
      this.maxParallel = 1;
    }

    // Force our error listener to run first, sets internal state
    // and saves error message to Scanner.error
    this.prependListener('error', function(err) {
      this._state = 0;
      this.error = err;
      if (this.timeouts.length) {
        this.timeouts.forEach(clearTimeout);
      }
    }.bind(this));

    // To avoid queued DNS queries, resolve the address once at creation.
    // Similar issue discussion: https://github.com/nodejs/node/issues/6189
    // Problem occurs with net/tls/http/https, AFAIK all Node libs do DNS lookup
    // on every request, meaning the memory growth and "hanging" script happen
    // with wrapper libs like request as well. This being an unusual edge for most
    // node apps, resolve it in the base class. At first call a Scanner state will
    // be -1 (resolving) until the lookup finishes
    this._resolveHost(this.hostName);

  }

  get state() {
    return this._state;
  }

  // translates state number
  get status() {
    switch (this._state) {
      case -1: return 'resolving'; // see note in constructor
      case  0: return 'error';
      case  1: return 'ready';
      case  2: return 'active';
      case  3: return 'stopped';
      case  4: return 'complete';
    }
  }

  // for internal use, increments portIndex
  // returns 0 at end of list
  get _nextPort() {
    return this.portList[this.portIndex++] || 0;
  }

  // for external use, does not increment portIndex
  // returns 0 at end of list
  get nextPort() {
    return this.portList[this.portIndex] || 0;
  }

  // for internal use at initialization/reset
  _resolveHost() {
    this._state = -1;
    dns.lookup(this.hostName, function(err, addr) {
      if (this.error) return;
      if (err) {
        this.emit('error', err);
        return;
      }
      this._state = 1;
      this.host = addr;
      this.emit('ready');
    }.bind(this));
  }

  // for internal use at initialization
  // TODO: expose range change mechanism?
  _makePortList(config, start=1, end=1000, interval=1) {

    var portList;
    // a given list takes precedence over a range
    if (Array.isArray(config.ports)) {

      // Ignore invalid values
      portList = utilities.filterValidPorts(config.ports);

    } else {
      this.start    = parseInt(config.start)    || start;
      this.end      = parseInt(config.end)      || end;
      this.interval = parseInt(config.interval) || interval;

      if (!utilities.isValidPort(this.start) ||
          !utilities.isValidPort(this.end)   ||
          this.end < this.start) {

        throw new Error('Invalid port range or interval, default range is '+
                        `${start}-${end} by ${interval}`);

      }

      portList = utilities.makeArrayForIntervalRange(this.start,this.end,this.interval);

    }

    if (portList.length === 0) {
      throw new Error('No ports to scan (check port config passed to scanner)');
    }

    return portList;
  }

  // alias for Scanner.stop
  pause() {
    this.stop();
  }

  // does nothing if Scanner is not active
  stop() {
    if (this.state !== 2) return;
    this._state = 3;
    this.emit('stop');
  }

  // alias for reset
  clearResults() {
    this.reset();
  }

  // clears scanResults and resets portIndex counter and error
  // Re-resolves Scanner.hostName to allow for easily reusing instances
  // to do the same scan on other hosts.
  // Will emit another "ready" event
  reset() {
    this.portIndex = 0;
    this.scanResults = [];
    this.error = null;
    this._resolveHost();
  }


  // Generic function that will properly limit connections (assuming one connection per-port)
  // requires instances (or inherited classes) to implement a checkPort method
  scan() {

    if (!this[CHECK_PORT_METHOD]) {
      throw new Error(`Scanner instance has no ${CHECK_PORT_METHOD} method`);
    }

    switch(this.state) {
      case -1: return this.on('ready', this.scan.bind(this));
      case  0: throw this.error;
      case  2: throw new Error('Scan is already running');
      case  4: throw new Error('Scanner has results of previous scan - call reset if you wish to reuse the Scanner');
    }

    this._state = 2;

    // Stores/emits results from checkPort and triggers next probe
    // Confirms lengths of scanResults and portList match before
    // marking complete: fatal errors trigger an error state, lesser
    // errors should be received as results
    function cb(result) {
      this.scanResults.push(result);
      this.emit('portFinished', this.scanResults[this.scanResults.length-1]);

      if (this.state !== 2) return;

      const nextPort = this._nextPort;
      if (nextPort) {
        if (this.rateLimit) {
          this.timeouts.push(setTimeout(function() {
            this[CHECK_PORT_METHOD](nextPort, cb.bind(this));
          }.bind(this), this.rateLimit));
        } else {
          this[CHECK_PORT_METHOD](nextPort, cb.bind(this));
        }
      } else {
        if (this.scanResults.length === this.portList.length) {
          this._state = 4;
          this.emit('complete', this.scanResults);
        }
      }

    }

    const limitStart = this.maxParallel>this.portList.length?this.portList.length:this.maxParallel;
    for (var i=0; i<limitStart; i++) {
      this[CHECK_PORT_METHOD](this._nextPort, cb.bind(this));
    }
  }

  static checkPort(portNumber, callback) {
    /*
     * For reference only: checkPort takes a portNumber and a callback.
     * Callback should be given a result object in the format:
     * { port: portNumber, data: anyType }
     *
     * For _EVERY_ port. This function should handle most errors, if there
     * is a fatal error and the scan needs to be aborted simply emit an error event.
     */
  }
}

module.exports = Scanner;
