const debug = require('debug')('snyk:nodejs-runtime-agent:inspector');
const inspector = require('inspector');

const state = require('./state');
const snapshot = require('./snapshot');
const moduleUtils = require('./module-utils');

let session;
const breakpointsMap = {};
const suspendedBreakpointIds = [];
const scriptUrlToInstrumentedFunctions = {};

function init() {
  if (!session) {
    session = new inspector.Session();
  }
  try {
    session.connect();
  } catch (error) {
    throw new Error('Debug session is already connected');
  }

  session.on('Debugger.scriptParsed', (script) => {
    // dealing only with 3rd party modules.
    if (moduleUtils.isNative(script.params.url)) {
      return;
    }

    scriptUrlToInstrumentedFunctions[script.params.url] = {};
    instrumentScript(script.params.url);
  });
  session.on('Debugger.paused', (message) => {
    try {
      const pauseContext = message.params;
      handleDebuggerPausedEvent(pauseContext);
    } catch (error) {
      debug(`Error handling debugger paused event: ${JSON.stringify(message)}, ${error}`);
    }
  });
  session.post('Debugger.enable');
  session.post('Debugger.setBreakpointsActive', {active: true});
}

function refreshInstrumentation() {
  Object.keys(scriptUrlToInstrumentedFunctions).forEach((scriptUrl) => {
    instrumentScript(scriptUrl);
  });
}

function instrumentScript(scriptUrl) {
  const moduleInfo = moduleUtils.getModuleInfo(scriptUrl);
  state.addPackage(moduleInfo.name, moduleInfo.version);
  const functionsToInstrument = snapshot.getVulnerableFunctionsLocations(moduleInfo);

  Object.keys(functionsToInstrument).forEach((functionName) => {
    const functionLocation = functionsToInstrument[functionName];
    if (!(functionName in scriptUrlToInstrumentedFunctions[scriptUrl])) {
      setBreakpointOnFunction(scriptUrl, moduleInfo, functionName, functionLocation);
      state.addFilter(moduleInfo.name, moduleInfo.scriptRelativePath, functionName);
    }
  });

  Object.keys(scriptUrlToInstrumentedFunctions[scriptUrl]).forEach((functionName) => {
    if (!(functionName in functionsToInstrument)) {
      removeBreakpoint(scriptUrlToInstrumentedFunctions[scriptUrl][functionName]);
      delete scriptUrlToInstrumentedFunctions[scriptUrl][functionName];
      state.removeFilter(moduleInfo.name, moduleInfo.scriptRelativePath, functionName);
    }
  });
}

function setBreakpointOnFunction(scriptUrl, moduleInfo, functionName, functionLocation) {
  const breakpointParameters = {
    lineNumber: functionLocation.start.line - 1, // lines are 0-based in the inspector but 1-based in acorn
    columnNumber: functionLocation.start.column - 1, // same for columns
    url: scriptUrl,
  };
  session.post('Debugger.setBreakpointByUrl', breakpointParameters, (error,response) => {
    if (error) {
      const errorEvent = {functionName, moduleInfo, error, message: 'Failed setting a breakpoint'};
      debug(`Failed setting a breakpoint on method ${functionName} in module ${moduleInfo.name}:`);
      debug(error);
      state.addEvent({error: errorEvent});
      return;
    }

    scriptUrlToInstrumentedFunctions[scriptUrl][functionName] = response.breakpointId;
    breakpointsMap[response.breakpointId] = {functionName, moduleInfo, scriptUrl, functionLocation};
    debug(`Successfully set a breakpoint on method ${functionName} in module ${moduleInfo.name}`);
  });
}

function resumeSnoozedBreakpoints() {
  suspendedBreakpointIds.forEach((breakpointId) => {
    debug(`resuming breakpoint ${breakpointId}`);
    const bpData = breakpointsMap[breakpointId];
    setBreakpointOnFunction(bpData.scriptUrl, bpData.moduleInfo, bpData.functionName, bpData.functionLocation);
  });
  suspendedBreakpointIds.length = 0;
}

function removeBreakpoint(breakpointId) {
  debug(`removing breakpoint ${breakpointId}`);
  session.post('Debugger.removeBreakpoint', {breakpointId});
}

function snoozeBreakpoint(breakpointId) {
  removeBreakpoint(breakpointId);
  suspendedBreakpointIds.push(breakpointId);
}

function handleDebuggerPausedEvent(pauseContext) {
  if (ignorePause(pauseContext)) {
    return;
  }

  const breakpointId = pauseContext.hitBreakpoints[0];
  const bpData = breakpointsMap[breakpointId];
  snoozeBreakpoint(breakpointId);

  const methodEntry = {
    source: 'nodejs-runtime-agent',
    coordinates: [`node:${bpData.moduleInfo.name}:${bpData.moduleInfo.version}`],
    methodName: `${bpData.moduleInfo.name}.${bpData.functionName}`,
    filterName: null, // TODO
    sourceUri:`file://${bpData.moduleInfo.baseDir}/${bpData.moduleInfo.scriptRelativePath}`,
    sourceCrc32c: null, // TODO - probably in the scriptParsed context
    breakpointId, // TODO: needed?
  };

  state.addEvent({methodEntry});
}

function ignorePause(pauseContext) {
  if (pauseContext.reason !== 'other') {
    debug(`ignoring debugger pause due to reason being ${pauseContext.reason}.`);
    return true;
  }

  if (!pauseContext.hitBreakpoints || pauseContext.hitBreakpoints.length === 0) {
    debug('ignoring debugger pause due to no breakpoints being present.');
    return true;
  }

  return false;
}

module.exports = {
  init,
  ignorePause,
  refreshInstrumentation,
  resumeSnoozedBreakpoints,
  scriptUrlToInstrumentedFunctions,
};
