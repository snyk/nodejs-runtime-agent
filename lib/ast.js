const acorn = require('acorn');

function findAllVulnerableFunctionsInScript(scriptContent, vulnerableFunctionNames) {
  const declaredFunctions = {};
  const parsedScript = acorn.parse(scriptContent,
    {locations: true, sourceType: 'module'});
  const body = parsedScript.body;
  body.forEach(function (node) {
    inspectNode(node,
      [],
      (nameParts, loc) => {
        const mangled = nameParts.join('.');
        if (vulnerableFunctionNames.includes(mangled)) {
          declaredFunctions[mangled] = loc;
        }
      });
  });

  return declaredFunctions;
}

function inspectNode(node, path, cb) {
  if (!node) {
    return;
  }
  if (node.type === 'FunctionDeclaration') {
    const loc = node.body.loc.start;
    const name = node.id.name;
    cb(path.concat(name), loc);
  } else if (node.type === 'FunctionExpression') {
    cb(path, node.body.loc.start);
  } else if ((node.type === 'ExpressionStatement' && node.expression.right)) {
    const name = [];
    const left = node.expression.left;

    if (!left.object) {
      return;
    }

    if (left.object.object && left.object.object.name) {
      name.push(left.object.object.name);
      if (left.object.property && left.object.property.name) {
        name.push(left.object.property.name);
      }
    } else {
      name.push(left.object.name);
    }
    name.push(left.property.name);

    inspectNode(node.expression.right, path.concat(name), cb);
  } else if (node.type === 'VariableDeclaration') {
    node.declarations.forEach((decl) => {
      let newPath;
      if (decl.init && decl.init.id && decl.init.id.name) {
        newPath = path.concat(decl.init.id.name);
      } else if (decl.id && decl.id.name) {
        newPath = path.concat(decl.id.name);
      }

      inspectNode(decl.init, newPath, cb);
    });
  } else if (node.type === 'ExportNamedDeclaration') {
    inspectNode(node.declaration, path, cb);
  } else if (node.type === 'AssignmentExpression') {
    inspectNode(node.left, path, cb);
    inspectNode(node.right, path, cb);
  } else if (node.type === 'ObjectExpression') {
    for (const prop of node.properties) {
      inspectNode(prop, path, cb);
    }
  } else if (node.type === 'Property') {
    const key = node.key;
    if (key.type !== 'Identifier') {
      // e.g. { ["concatenation" + "here"]: 5 }
      return;
    }
    inspectNode(node.value, path.concat(key.name), cb);
  }
}

module.exports = {findAllVulnerableFunctionsInScript};
