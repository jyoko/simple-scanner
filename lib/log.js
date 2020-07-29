/*
 * Simple, mildly-prettier logger
 */

const USE_COLORS = true;

const log = {
  LOG_LEVEL: 'debug',
  LEVELS: ['trace','debug','info','warn','error','fatal'],
  _color: level=>{
    switch(level) {
      case 'date_start':  return '\x1b[85;2m[\x1b[0m\x1b[94m';
      case 'date_end':    return '\x1b[0m\x1b[85;2m]\x1b[0m';
      case 'level_start': return '\x1b[85;2m(\x1b[0m';
      case 'level_end':   return '\x1b[0m\x1b[85;2m)\x1b[0m';
      case 'debug':       return '\x1b[36m';
      case 'info':        return '\x1b[32m';
      case 'warn':        return '\x1b[33m';
      case 'error':       return '\x1b[31m';
      case 'fatal':       return '\x1b[91;1m';
      default: return '';
    }
  },
  _ok: function _ok(level) { return this.LEVELS.indexOf(level) >= this.LEVELS.indexOf(this.LOG_LEVEL); },
};
log._longest = log.LEVELS.reduce((high,word)=>high>word.length?high:word.length,0);
const makeLogger = level=>(...args)=>log._ok(level)&&
  console.log(
    (USE_COLORS ? log._color('date_start')                            : '[')+
    (new Date()).toISOString() + (USE_COLORS ? log._color('date_end') : ']'),
    (USE_COLORS ? log._color('level_start')+log._color(level)         : '(')+
    level.toUpperCase() + (USE_COLORS ? log._color('level_end')       : ')'), 
    ' '.repeat(log._longest-level.length),
    ...args
  );
log.LEVELS.forEach(level=>log[level]=makeLogger(level));

module.exports = log;
