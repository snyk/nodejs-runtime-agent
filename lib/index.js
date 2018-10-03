var debug = require('./debugger');
var transmitter = require('./transmitter');

function start(config) {
  try {
    transmitter.start(config);
    debug.start();
  } catch (error) {
    console.log(JSON.stringify(error));
  };
}

module.exports = start;
