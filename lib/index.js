var debug = require('./debugger');
var transmitter = require('./transmitter');

function start(options) {
    var projectId = options.projectId;
    transmitter.start(options.projectId);
    debug.start();
}

module.exports = start;