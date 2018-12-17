const fs = require('fs');

const ast = require('../lib/ast.js');

for (let i = 2; i < process.argv.length; ++i) {
  dump(process.argv[i]);
}

function dump(path) {
  const funcs = ast.findAllVulnerableFunctionsInScript(fs.readFileSync(path), {includes: () => true});
  for (const [name, loc] of Object.entries(funcs)) {
    console.log(name, showLoc(loc));
  }
}

function showLoc(loc) {
  return `${loc.start.line}c${loc.start.column}` +
    ` -> ${loc.end.line}c${loc.end.column}`;
}
