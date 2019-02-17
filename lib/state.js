const debug = require('debug')('snyk:nodejs:state');

const state = {
  events: [],
  filters: {},
  packages: {},
};

module.exports = {
  get,
  clean,
  addEvent,
  addFilter,
  addPackage,
  removeFilter,
};

function get() {
  return state;
}

function clean() {
  state.events.length = 0;
}

function addEvent(event) {
  event.timestamp = (new Date()).toISOString();
  state.events.push(event);
  debug(`Event added to transmission queue: ${JSON.stringify(event)}`);
}

function addFilter(packageName, fileRelativePath, functionName) {
  const filters = state.filters;

  if (!(packageName in filters)) {
    filters[packageName] = {};
  }
  if (!(fileRelativePath in filters[packageName])) {
    filters[packageName][fileRelativePath] = {};
  }
  filters[packageName][fileRelativePath][functionName] = null;
}

function removeFilter(packageName, fileRelativePath, functionName) {
  const filters = state.filters;

  delete filters[packageName][fileRelativePath][functionName];
  if (Object.keys(filters[packageName][fileRelativePath]).length === 0) {
    delete filters[packageName][fileRelativePath];
  }
  if (Object.keys(filters[packageName]).length === 0) {
    delete filters[packageName];
  }
}

function addPackage(name, version) {
  if (!(name in state.packages)) {
    state.packages[name] = {};
  }

  // an empty object so it's easier to overload additional data here
  // such as "introducedThrough" etc.
  state.packages[name][version] = {};
}
