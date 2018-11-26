const debug = require('debug')('snyk:nodejs:inspector');
const inspector = require('inspector');

const snapshot = require('./snapshot');
const moduleUtils = require('./module-utils');
const transmitter = require('./transmitter');

let session;
const loadedScripts = {};
const breakpointsMap = {};
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

  snapshot.loadsFunctionsToInspect();

  session.on('Debugger.scriptParsed', (script) => {
    loadedScripts[script.params.scriptId] = script.params;
    const scriptPath = moduleUtils.normalizeScriptPath(script.params.url);

    // dealing only with 3rd party modules.
    if (moduleUtils.isNative(scriptPath)) {
      return;
    }

    const moduleInfo = moduleUtils.getModuleInfo(scriptPath);
    const vulnerableMethods = snapshot.getVulnerableFunctionsLocations(moduleInfo, scriptPath);
    Object.keys(vulnerableMethods).forEach((methodName) => {
      const methodLocation = vulnerableMethods[methodName];
      transmitter.addInstrumentedFunction({url: scriptPath, moduleInfo, methodName, methodLocation});
      setBreakpointOnFunction(script.params.url, moduleInfo, methodName, methodLocation);
    });
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

function setBreakpointOnFunction(moduleUrl, moduleInfo, methodName, methodLocation) {
  const breakpointParameters = {
    lineNumber: methodLocation.line,
    columnNumber: 0,
    url: moduleUrl,
    condition: undefined,
  };
  session.post('Debugger.setBreakpointByUrl', breakpointParameters, (error,response) => {
    if (!error) {
      breakpointsMap[response.breakpointId] = {methodName, moduleInfo, moduleUrl, methodLocation};
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
    setBreakpointOnFunction(bpData.moduleUrl, bpData.moduleInfo, bpData.methodName, bpData.methodLocation);
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
