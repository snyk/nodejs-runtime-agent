var fs = require('fs');
var acorn = require('acorn');

function findAllVulnerableFunctionsInScriptPath(
  scriptPath, vulnerableFunctionNames) {
  var scriptContent = fs.readFileSync(scriptPath);
  var decleardFunctions = {};
  try {
    var parsedScript = acorn.parse(scriptContent,
      {locations:true, sourceType: 'module'});
    var body = parsedScript.body;
    body.forEach(function (node) {
      var loc, name;
      if (node.type === 'FunctionDeclaration') {
        loc = node.body.loc.start;
        name = node.id.name;
        if (vulnerableFunctionNames.includes(name)) {
          decleardFunctions[name] = loc;
        }
      } else if ((node.type === 'ExpressionStatement' &&
                  node.expression.right &&
                  node.expression.right.type === 'FunctionExpression')) {
        loc = node.expression.right.body.loc.start;
        // Todo: going recursively over object
        if (node.expression.left.object.object &&
            node.expression.left.object.object.name) {
          name = node.expression.left.object.object.name;
          name = name + '.' + node.expression.left.object.property.name;
        } else {
          name = node.expression.left.object.name;
        }
        name = name + '.' + node.expression.left.property.name;
        if (vulnerableFunctionNames.includes(name)) {
          decleardFunctions[name] = loc;
        }
      } else if (node.type === 'VariableDeclaration') {
        node.declarations.forEach((decl) => {
          if (decl.init && decl.init.type === 'FunctionExpression') {
            if (decl.init.id && decl.init.id.name) {
              name = decl.init.id.name;
            } else {
              name = decl.id.name;
            }
            loc = decl.init.body.loc.start;
            if (vulnerableFunctionNames.includes(name)) {
              decleardFunctions[name] = loc;
            }
          }
        });
      } else if (node.type === 'ExportNamedDeclaration') {
        if (node.declaration.type === 'FunctionDeclaration') {
          name = node.declaration.id.name;
          loc = node.declaration.body.loc.start;
          if (vulnerableFunctionNames.includes(name)) {
            decleardFunctions[name] = loc;
          }
        }
      };
    });
  } catch (error) {
    console.log(JSON.stringify(error));
  }
  return decleardFunctions;
};

module.exports = {findAllVulnerableFunctionsInScriptPath};
