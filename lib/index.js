var debug = require('./debugger');
var transmitter = require('./transmitter');

function start(config) {
  try {
    transmitter.start(config.url, config.projectId);
    debug.start();
  } catch (error) {
    console.log(JSON.stringify(error));
  };
}

module.exports = start;
