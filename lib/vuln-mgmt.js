var fs = require('fs');
var path = require('path');
var debug = require('debug')('snyk:nodejs-runtime-agent');
var semver = require('semver');

var ast = require('./ast');

const FUNCTIONS_METATDATA_FILE = path.join(__dirname, '../functions-to-track-runtime.json');
var vulnerabiltiesMetadata = {};

function loadsFunctionsToInspect() {
  var appDir = path.dirname(require.main.filename);
  var appMetadataFilePath = path.join(appDir, 'functions-to-track-runtime.json');
  var exists = fs.existsSync(appMetadataFilePath);
  if (!exists) {
    vulnerabiltiesMetadata = processFunctionsToInspect(require(FUNCTIONS_METATDATA_FILE));
  } else {
    debug('Using app defined method.json to load vulnerabilties');
    vulnerabiltiesMetadata = processFunctionsToInspect(require(appMetadataFilePath));
  }
}

function processFunctionsToInspect(functions) {
  const processedMethods = {};
  functions.forEach(currentMethod => {
    try {
      if (!(currentMethod.packageName in processedMethods)) {
        processedMethods[currentMethod.packageName] = {};
      }
      if (!(currentMethod.methodId.filePath in processedMethods[currentMethod.packageName])) {
        processedMethods[currentMethod.packageName][currentMethod.methodId.filePath] = [];
      }
      processedMethods[currentMethod.packageName][currentMethod.methodId.filePath].push({
        name: currentMethod.methodId.methodName,
        semver: currentMethod.version,
      });
    } catch (err) {
      debug(`Failed inspecting ${currentMethod}:`, err);
    }
  });
  return processedMethods;
}

function isVulnerableModulePath(moduleInfo) {
  var name = moduleInfo.name;
  var version = moduleInfo.version;
  var scriptRelativePath = moduleInfo.scriptRelativePath;
  if (!((name in vulnerabiltiesMetadata) &&
        (scriptRelativePath in vulnerabiltiesMetadata[name]))) {
    return false;
  }
  var scriptPathMethods =
    vulnerabiltiesMetadata[name][scriptRelativePath];
  var foundVulnerableMethod = false;
  scriptPathMethods.forEach(value => {
    value.semver.some(ver => {
      if (semver.satisfies(version, ver)) {
        foundVulnerableMethod = true;
      }

      return false;
    });
  });
  return foundVulnerableMethod;
}

//TODO: fix it hack for tests
function setVulnerabiltiesMetadata(vulnMetadata) {
  vulnerabiltiesMetadata = processFunctionsToInspect(vulnMetadata);
}

function getVulnerableFunctionsLocations(moduleInfo, scriptPath) {
  const name = moduleInfo.name;
  const version = moduleInfo.version;
  const scriptRelativePath = moduleInfo.scriptRelativePath;
  const vulnerableFunctionNames = [];
  const scriptPathFunctions = vulnerabiltiesMetadata[name][scriptRelativePath];
  scriptPathFunctions.forEach(value => {
    value.semver.some(ver => {
      if (semver.satisfies(version, ver)) {
        vulnerableFunctionNames.push(value.name);
        return true;
      }

      return false;
    });
  });

  const functionsLocationInScript = ast.findAllVulnerableFunctionsInScriptPath(
    scriptPath, vulnerableFunctionNames);
  return functionsLocationInScript;
}

module.exports = {
  setVulnerabiltiesMetadata,
  loadsFunctionsToInspect,
  isVulnerableModulePath,
  getVulnerableFunctionsLocations,
};
