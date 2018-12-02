const debug = require('debug')('snyk:nodejs-runtime-agent:snapshot');
const fs = require('fs');
const semver = require('semver');

const ast = require('../ast');
const reader = require('./reader');

let vulnerabiltiesMetadata = {};

function init() {
  vulnerabiltiesMetadata = reader.fromLocal();
}

function refresh() {
  return reader.fromUpstream()
    .then((newSnapshot) => {
      vulnerabiltiesMetadata = newSnapshot;
    })
    .catch((error) => {
      // TODO - log? ignore?
    });
}

function getVulnerableFunctionsLocations(moduleInfo) {
  const {name: packageName, version, scriptRelativePath, scriptPath} = moduleInfo;
  if (!((packageName in vulnerabiltiesMetadata) && (scriptRelativePath in vulnerabiltiesMetadata[packageName]))) {
    return {};
  }

  const vulnerableFunctionNames = [];
  const scriptPathFunctions = vulnerabiltiesMetadata[packageName][scriptRelativePath];
  scriptPathFunctions.forEach(value => {
    value.semver.some(ver => {
      if (semver.satisfies(version, ver)) {
        vulnerableFunctionNames.push(value.name);
        return true;
      }

      return false;
    });
  });

  try {
    return ast.findAllVulnerableFunctionsInScript(
      fs.readFileSync(scriptPath), vulnerableFunctionNames);
  } catch (error) {
    debug(`Error finding vulnerable methods ${vulnerableFunctionNames}` +
      ` in script path ${scriptPath}: ${error}`);
    return {};
  }
}

//TODO: fix it hack for tests
function setVulnerabiltiesMetadata(vulnMetadata) {
  vulnerabiltiesMetadata = reader.processFunctionsToInspect(vulnMetadata);
}

module.exports = {
  init,
  refresh,
  setVulnerabiltiesMetadata,
  getVulnerableFunctionsLocations,
};
