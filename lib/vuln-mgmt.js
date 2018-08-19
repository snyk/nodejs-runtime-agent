var fs = require('fs');
var path = require('path');
var semver = require('semver');
var ast = require('./ast');

const METHODS_METATDATA_FILE = path.join(__dirname, '../methods.json');
var vulnerabiltiesMetadata = {};

function loadVulnerabiltiesMetadata() {
  var exists = fs.existsSync(METHODS_METATDATA_FILE);
  if (!exists) {
    console.log('Methods metadata file wasn\'t found');
    return;
  }
  vulnerabiltiesMetadata = require(METHODS_METATDATA_FILE);
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
        foundVulnerableMethod = foundVulnerableMethod || true;
      }

      return false;
    });
  });
  return foundVulnerableMethod;
}

function getVulnerableMethodsLocations(moduleInfo, scriptPath) {
  var name = moduleInfo.name;
  var version = moduleInfo.version;
  var scriptRelativePath = moduleInfo.scriptRelativePath;

  var vulnerableFunctionNames = [];
  var scriptPathMethods =
    vulnerabiltiesMetadata[name][scriptRelativePath];
  scriptPathMethods.forEach(value => {
    value.semver.some(ver => {
      if (semver.satisfies(version, ver)) {
        vulnerableFunctionNames =
          vulnerableFunctionNames.concat(value.name);
        return true;
      }

      return false;
    });
  });

  var functionsLocationInScript =
    ast.findAllVulnerableFunctionsInScriptPath(
      scriptPath, vulnerableFunctionNames);
  return functionsLocationInScript;
}

loadVulnerabiltiesMetadata();

module.exports = {isVulnerableModulePath, getVulnerableMethodsLocations};
