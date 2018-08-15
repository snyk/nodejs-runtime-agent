var debug = require('./debugger');
var transmitter = require('./transmitter');

function start(options) {
  transmitter.start(options.projectId);
  debug.start();
}

module.exports = start;
