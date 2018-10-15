var fs = require('fs');
var path = require('path');
var debug = require('debug')('snyk:nodejs-runtime-agent');
var semver = require('semver');

var ast = require('./ast');

const METHODS_METATDATA_FILE = path.join(__dirname, '../methods.json');
var vulnerabiltiesMetadata = {};

function loadVulnerabiltiesMetadata() {
  var appDir = path.dirname(require.main.filename);
  var appMetadataFilePath = path.join(appDir, 'methods.json');
  var exists = fs.existsSync(appMetadataFilePath);
  if (!exists) {
    vulnerabiltiesMetadata = require(METHODS_METATDATA_FILE);
  } else {
    debug('Using app defined method.json to load vulnerabilties');
    vulnerabiltiesMetadata = require(appMetadataFilePath);
  }
  return vulnerabiltiesMetadata;
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

//TODO: fix it hack for tests
function setVulnerabiltiesMetadata(vulnMetadata) {
  vulnerabiltiesMetadata = vulnMetadata;
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

module.exports = {
  setVulnerabiltiesMetadata,
  loadVulnerabiltiesMetadata,
  isVulnerableModulePath,
  getVulnerableMethodsLocations,
};
