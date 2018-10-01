var inspector = require('inspector');
var vulnMgmt = require('./vuln-mgmt');
var moduleUtils = require('./moduleUtils');
var transmitter = require('./transmitter');

var loadedScripts = {};
var session;
var breakpointsMap = {};

function start() {
  if (!session) {
    session = new inspector.Session();
  }
  try {
    session.connect();
  } catch (error) {
    throw new Error('Debug session is already connected');
  }

  vulnMgmt.loadVulnerabiltiesMetadata();

  session.on('Debugger.scriptParsed', (script) => {
    loadedScripts[script.params.scriptId] = script.params;
    var scriptPath = script.params.url;

    // dealing only with 3rd party modules.
    if (moduleUtils.isNative(scriptPath)) {
      return;
    }

    var moduleInfo = moduleUtils.getModuleInfo(scriptPath);
    if (vulnMgmt.isVulnerableModulePath(moduleInfo)) {
      var vulnerableMethods =
        vulnMgmt.getVulnerableMethodsLocations(moduleInfo, scriptPath);
      Object.keys(vulnerableMethods).forEach((methodName) => {
        var methodLocation = vulnerableMethods[methodName];
        setBreakpointsOnVulnearbleMethods(
          script.params.url, moduleInfo, methodName, methodLocation);
      });
    }
  });
  session.on('Debugger.paused', (message) => {
    try {
      handleDebuggerPausedEvent(message.params);
    } catch (error) {
      console.log(error);
    }
  });
  session.post('Debugger.enable');
  session.post('Debugger.setBreakpointsActive', {active: true});

  function setBreakpointsOnVulnearbleMethods(
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
          };
          var message = {
            methodName,
            moduleInfo,
            message: 'Added breakpoint',
          };
          console.log(JSON.stringify(message));
        } else {
          console.log(JSON.stringify(error));
        }
      });
  }
}

function handleDebuggerPausedEvent(message) {
  var breakpointId = message.hitBreakpoints[0];
  transmitter.addEvent( {
    bp: breakpointId,
    info: breakpointsMap[breakpointId],
    timestamp: (new Date()).toISOString(),
  });
}

module.exports = {start};
