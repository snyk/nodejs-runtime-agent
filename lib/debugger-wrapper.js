const debug = require('debug')('snyk:nodejs-runtime-agent:inspector');
const inspector = require('inspector');

const snapshot = require('./snapshot');
const moduleUtils = require('./module-utils');
const transmitter = require('./transmitter');

let session;
const breakpointsMap = {};
const monitoredScripts = [];
const suspendedBreakpointIds = [];

function handlePeriodicTasks() {
  resumeSnoozedBreakpoints();
}

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

    monitoredScripts.push(script.params.url);
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

function instrumentScript(scriptUrl) {
  const moduleInfo = moduleUtils.getModuleInfo(scriptUrl);
  const vulnerableMethods = snapshot.getVulnerableFunctionsLocations(moduleInfo);
  Object.keys(vulnerableMethods).forEach((methodName) => {
    const methodLocation = vulnerableMethods[methodName];
    transmitter.addInstrumentedFunction({url: scriptUrl, moduleInfo, methodName, methodLocation});
    setBreakpointOnFunction(scriptUrl, moduleInfo, methodName, methodLocation);
  });
}

function setBreakpointOnFunction(scriptUrl, moduleInfo, methodName, methodLocation) {
  const breakpointParameters = {
    lineNumber: methodLocation.line,
    columnNumber: 0,
    url: scriptUrl,
  };
  session.post('Debugger.setBreakpointByUrl', breakpointParameters, (error,response) => {
    if (!error) {
      breakpointsMap[response.breakpointId] = {methodName, moduleInfo, scriptUrl, methodLocation};
      debug(`Successfully set a breakpoint on method ${methodName} in module ${moduleInfo.name}`);
    } else {
      const errorEvent = {methodName, moduleInfo, error, message: 'Failed setting a breakpoint'};
      debug(`Failed setting a breakpoint on method ${methodName} in module ${moduleInfo.name}: ${error}`);
      transmitter.addEvent({error: errorEvent});
    }
  });
}

function resumeSnoozedBreakpoints() {
  suspendedBreakpointIds.forEach((breakpointId) => {
    debug(`resuming breakpoint ${breakpointId}`);
    const bpData = breakpointsMap[breakpointId];
    setBreakpointOnFunction(bpData.scriptUrl, bpData.moduleInfo, bpData.methodName, bpData.methodLocation);
  });
  suspendedBreakpointIds.length = 0;
}

function handleDebuggerPausedEvent(pauseContext) {
  if (ignorePause(pauseContext)) {
    return;
  }

  const breakpointId = pauseContext.hitBreakpoints[0];
  const bpData = breakpointsMap[breakpointId];

  debug(`removing breakpoint ${breakpointId}`);
  session.post('Debugger.removeBreakpoint', {breakpointId});
  suspendedBreakpointIds.push(breakpointId);
  const methodEntry = {
    source: 'nodejs-runtime-agent',
    coordinates: [`node:${bpData.moduleInfo.name}:${bpData.moduleInfo.version}`],
    methodName: `${bpData.moduleInfo.name}.${bpData.methodName}`,
    // TODO: settle the data format for methods.json so we can get
    // TODO: the filterName through to here.
    filterName: null,
    // TODO: moduleUtils does quite a lot of work to split this up;
    // TODO: maybe it shouldn't?
    sourceUri:`file://${bpData.moduleInfo.baseDir}/${bpData.moduleInfo.scriptRelativePath}`,
    sourceCrc32c: null,
    breakpointId,
  };

  transmitter.addEvent({methodEntry});
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

module.exports = {handlePeriodicTasks, init, ignorePause};
