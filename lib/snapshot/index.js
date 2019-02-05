const fs = require('fs');
const debug = require('debug')('snyk:nodejs-runtime-agent:snapshot');
const semver = require('semver');

const ast = require('../ast');
const reader = require('./reader');
const transmitter = require('../transmitter');

function init() {
  reader.loadFromLocal();
}

function refresh() {
  return reader.loadFromUpstream()
    .then(() => {})
    .catch(() => {});
}

function getVulnerableFunctionsLocations(moduleInfo) {
  const vulnerabilitiesMetadata = reader.getLatest();
  const {name: packageName, version, scriptRelativePath, scriptPath} = moduleInfo;
  if (!((packageName in vulnerabilitiesMetadata) && (scriptRelativePath in vulnerabilitiesMetadata[packageName]))) {
    return {};
  }

  const functionNameToPublicId = {};
  const scriptPathFunctions = vulnerabilitiesMetadata[packageName][scriptRelativePath];
  scriptPathFunctions.forEach(value => {
    value.semver.some(ver => {
      if (semver.satisfies(version, ver)) {
        functionNameToPublicId[value.name] = value.publicId;
        return true;
      }

      return false;
    });
  });

  const wantedFunctionNames = Object.keys(functionNameToPublicId);
  try {
    const vulnerableFunctionsFound = ast.findAllVulnerableFunctionsInScript(
      fs.readFileSync(scriptPath), wantedFunctionNames);
    const foundFunctionNames = Object.keys(vulnerableFunctionsFound);
    validateFoundFunctions(
      scriptPathFunctions,
      moduleInfo,
      wantedFunctionNames,
      foundFunctionNames);
    const functionNameToLocationAndPublicId = {};
    for (const [functionName, location] of Object.entries(vulnerableFunctionsFound)) {
      const publicId = functionNameToPublicId[functionName];
      if (!publicId) {
        throw new Error('no public id for: ' + functionName);
      }
      functionNameToLocationAndPublicId[functionName] = {
        location,
        publicId,
      };
    }
    return functionNameToLocationAndPublicId;
  } catch (error) {
    debug(`Error finding vulnerable methods ${wantedFunctionNames}` +
      ` in script path ${scriptPath}: ${error}`);
    return {};
  }
}

function validateFoundFunctions(scriptPathFunctions, moduleInfo, functionsExpected, functionsActual) {
  const functionsNotFound = functionsExpected.filter(f => !functionsActual.includes(f));
  if (functionsNotFound && functionsNotFound.length > 0) {
    const warningEvent = {
      message: 'instrumentation discrepancy: missing functions from source code',
      moduleInfo,
      snapshotInfo: scriptPathFunctions,
      functionsInfo: {
        functionsExpected,
        functionsActual,
        functionsNotFound,
      },
    };
    transmitter.addEvent({warning: warningEvent});
  }
}

module.exports = {
  init,
  refresh,
  getVulnerableFunctionsLocations,
};
