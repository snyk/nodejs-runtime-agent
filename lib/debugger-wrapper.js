var debug = require('debug')('snyk:nodejs:inspector');
var inspector = require('inspector');

var vulnMgmt = require('./vuln-mgmt');
var moduleUtils = require('./moduleUtils');
var transmitter = require('./transmitter');

var session;
var loadedScripts = {};
var breakpointsMap = {};

function start(config) {
  if (!session) {
    session = new inspector.Session();
  }
  try {
    session.connect();
  } catch (error) {
    throw new Error('Debug session is already connected');
  }

  vulnMgmt.loadsMethodsToInspect();

  session.on('Debugger.scriptParsed', (script) => {
    loadedScripts[script.params.scriptId] = script.params;
    var scriptPath = script.params.url;

    // Remove file prefix which was added in Node v10.12
    if (scriptPath.startsWith('file://')) {
      scriptPath = scriptPath.substring('file://'.length);
    }

    // dealing only with 3rd party modules.
    if (moduleUtils.isNative(scriptPath)) {
      return;
    }

    const moduleInfo = moduleUtils.getModuleInfo(scriptPath);
    if (vulnMgmt.isVulnerableModulePath(moduleInfo)) {
      const vulnerableMethods =
        vulnMgmt.getVulnerableMethodsLocations(moduleInfo, scriptPath);
      Object.keys(vulnerableMethods).forEach((methodName) => {
        const methodLocation = vulnerableMethods[methodName];
        setBreakpointsOnVulnerableMethods(
          script.params.url, moduleInfo, methodName, methodLocation);
      });
    }
  });
  session.on('Debugger.paused', (message) => {
    try {
      handleDebuggerPausedEvent(config, message.params);
    } catch (error) {
      debug('Error handling debugger paused event: ' +
        `${JSON.stringify(message)}, ${error}`);
    }
  });
  session.post('Debugger.enable');
  session.post('Debugger.setBreakpointsActive', {active: true});
}

function setBreakpointsOnVulnerableMethods(
  moduleUrl, moduleInfo, methodName, methodLocation) {
  session.post('Debugger.setBreakpointByUrl',
    {
      lineNumber: methodLocation.line,
      columnNumber: 0,
      url: moduleUrl,
      condition: undefined,
    }, (error,response) => {
      if (!error) {
        breakpointsMap[response.breakpointId] = {
          methodName,
          moduleInfo,
          moduleUrl,
          methodLocation,
        };
        debug(`Successfully set a breakpoint on method ${methodName}` +
          ` in module ${moduleInfo.name}`);
      } else {
        const errorEvent = {
          methodName,
          moduleInfo,
          error,
          message: 'Failed setting a breakpoint',
        };
        debug(`Failed setting a breakpoint on method ${methodName} ` +
          ` in module ${moduleInfo.name}: ${error}`);
        transmitter.addEvent({
          error: errorEvent,
          timestamp: (new Date()).toISOString(),
        });
      }
    });
}

function handleDebuggerPausedEvent(config, message) {
  const breakpointId = message.hitBreakpoints[0];
  const bpData = breakpointsMap[breakpointId];

  session.post('Debugger.removeBreakpoint', {breakpointId});
  setTimeout(
    function() {
      setBreakpointsOnVulnerableMethods(bpData.moduleUrl, bpData.moduleInfo, bpData.methodName, bpData.methodLocation);
    },
    config.snoozeMethodMs).unref();

  transmitter.addEvent( {
    methodEntry: {
      source: 'nodejs-runtime-agent',
      coordinates: [
        `node:${bpData.moduleInfo.name}:${bpData.moduleInfo.version}`,
      ],
      methodName: `${bpData.moduleInfo.name}.${bpData.methodName}`,
      // TODO: settle the data format for methods.json so we can get
      // TODO: the filterName through to here.
      filterName: null,
      // TODO: moduleUtils does quite a lot of work to split this up;
      // TODO: maybe it shouldn't?
      sourceUri:`file://${bpData.moduleInfo.baseDir}/` +
        bpData.moduleInfo.scriptRelativePath,
      sourceCrc32c: null,
      breakpointId,
    },
    timestamp: (new Date()).toISOString(),
  });
}

module.exports = {start};
