const debug = require('debug')('snyk:nodejs:transmitter');
const needle = require('needle');

const config = require('./config');
const systemInfo = require('./system-info').getSystemInfo();

const filters = {};
const eventsToSend = [];

function handlePeriodicTasks() {
  const url = config.beaconUrl;
  return transmitEvents(url, config.projectId, config.agentId);
}

function transmitEvents(url, projectId, agentId) {
  let postPromise = Promise.resolve();
  debug(`agent:${agentId} transmitting ${eventsToSend.length} events to ${url} with project ID ${projectId}.`);
  const body = {projectId, agentId, eventsToSend, systemInfo, filters};
  postPromise = needle('post', url, body, {json: true})
    .then((response) => {
      if (response && response.statusCode !== 200) {
        debug('Unexpected response for events transmission: ' +
          `${response.statusCode} : ${JSON.stringify(response.body)}`);
      } else if (response && response.statusCode === 200) {
        debug('Successfully transmitted events.');
      }
    })
    .catch((error) => {
      debug(`Error transmitting events: ${error}`);
    });
  clearEvents();
  return postPromise;
}

function clearEvents() {
  eventsToSend.length = 0;
}

function addFilter(packageName, fileRelativePath, functionName) {
  if (!(packageName in filters)) {
    filters[packageName] = {};
  }
  if (!(fileRelativePath in filters[packageName])) {
    filters[packageName][fileRelativePath] = {};
  }
  filters[packageName][fileRelativePath][functionName] = null;
}

function removeFilter(packageName, fileRelativePath, functionName) {
  delete filters[packageName][fileRelativePath][functionName];
  if (Object.keys(filters[packageName][fileRelativePath]).length === 0) {
    delete filters[packageName][fileRelativePath];
  }
  if (Object.keys(filters[packageName]).length === 0) {
    delete filters[packageName];
  }
}

function addEvent(event) {
  event.timestamp = (new Date()).toISOString();
  eventsToSend.push(event);
  debug(`Event added to transmission queue: ${JSON.stringify(event)}`);
}

module.exports = {
  addEvent,
  addFilter,
  removeFilter,
  transmitEvents,
  handlePeriodicTasks,
};
