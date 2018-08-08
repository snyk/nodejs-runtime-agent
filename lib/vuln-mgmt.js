var fs = require('fs');
var path = require('path');
var ast = require('./ast');

const METHODS_METATDATA_FILE = path.join(__dirname, '../methods.json');
console.log(METHODS_METATDATA_FILE);
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
    var key = name + '@' + version;
    // console.log(key);
    var scriptRelativePath = moduleInfo.scriptRelativePath;
    return (key in vulnerabiltiesMetadata) && (scriptRelativePath in vulnerabiltiesMetadata[key]);
}

function getVulnerableMethodsLocations(moduleInfo, scriptPath) {
    var name = moduleInfo.name;
    var version = moduleInfo.version;
    var key = name + '@' + version;
    var scriptRelativePath = moduleInfo.scriptRelativePath;
    var vulnerableFunctionNames = vulnerabiltiesMetadata[key][scriptRelativePath];    
    var functionsLocationInScript = ast.findAllVulnerableFunctionsInScriptPath(scriptPath,vulnerableFunctionNames);
    return functionsLocationInScript;
}

loadVulnerabiltiesMetadata();

module.exports = {isVulnerableModulePath, getVulnerableMethodsLocations};