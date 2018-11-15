var fs = require('fs');
var path = require('path');
var debug = require('debug')('snyk:nodejs-runtime-agent');
var semver = require('semver');

var ast = require('./ast');

const METHODS_METATDATA_FILE = path.join(__dirname, '../methods-to-track-runtime.json');
var vulnerabiltiesMetadata = {};

function loadsMethodsToInspect() {
  var appDir = path.dirname(require.main.filename);
  var appMetadataFilePath = path.join(appDir, 'methods-to-track-runtime.json');
  var exists = fs.existsSync(appMetadataFilePath);
  if (!exists) {
    vulnerabiltiesMetadata = processMethodsToInspect(require(METHODS_METATDATA_FILE));
  } else {
    debug('Using app defined method.json to load vulnerabilties');
    vulnerabiltiesMetadata = processMethodsToInspect(require(appMetadataFilePath));
  }
}

function processMethodsToInspect(methods) {
  const processedMethods = {};
  methods.forEach(currentMethod => {
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
  vulnerabiltiesMetadata = processMethodsToInspect(vulnMetadata);
}

function getVulnerableMethodsLocations(moduleInfo, scriptPath) {
  const name = moduleInfo.name;
  const version = moduleInfo.version;
  const scriptRelativePath = moduleInfo.scriptRelativePath;
  const vulnerableFunctionNames = [];
  const scriptPathMethods = vulnerabiltiesMetadata[name][scriptRelativePath];
  scriptPathMethods.forEach(value => {
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
  loadsMethodsToInspect,
  isVulnerableModulePath,
  getVulnerableMethodsLocations,
};
