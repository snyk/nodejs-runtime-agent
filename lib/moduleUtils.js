var path = require('path');
var fs = require('fs');

function isNative(filePath) {
  return !filePath.includes('node_modules');
}

function getModuleInfo(filePath) {
  var segments = filePath.split(path.sep);
  var index = segments.lastIndexOf('node_modules');
  var scoped = segments[index + 1][0] === '@';
  var offset = scoped ? 3 : 2;
  var baseDir = segments.slice(0, index + offset).join(path.sep);
  var packageJsonStr =
    fs.readFileSync(path.join(baseDir, 'package.json'));
  var packageJson = JSON.parse(packageJsonStr);
  var moduleInfo = {
    version: packageJson.version,
    name: packageJson.name,
    baseDir: baseDir,
    scriptRelativePath: segments.slice(index + offset).join(path.sep),
  };
  return moduleInfo;
}
module.exports = {isNative, getModuleInfo};
