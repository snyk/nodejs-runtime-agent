var debug = require('debug')('snyk:nodejs-agent');
var needle = require('needle');

const DEFAULT_BEACON_BASE_URL = 'https://homebase.snyk.io';
const DEFAULT_BEACON_URL_PATH = '/api/v1/beacon';
const DEFAULT_BEACON_INTERVAL_MS = 60 * 1000;

var eventsToSend = [];
function start({
  projectId,
  url=DEFAULT_BEACON_BASE_URL + DEFAULT_BEACON_URL_PATH,
  beaconIntervalMs=DEFAULT_BEACON_INTERVAL_MS,
}) {
  if (!projectId) {
    throw new Error('No projectId defined in configuration');
  }

  setInterval(() => {
    transmitData();
    eventsToSend = [];
  }, beaconIntervalMs).unref();

  function transmitData() {
    if (eventsToSend.length) {
      needle.post(url, {projectId, eventsToSend}, {json: true});
      debug({eventsTransmittedCount: eventsToSend.length},
        'events transmitted.');
    }
  }
}

function addEvent(event) {
  eventsToSend.push(event);
  var message = {
    event,
    message: 'Event was added',
  };
  debug(JSON.stringify(message));
}

module.exports = {start,addEvent};
