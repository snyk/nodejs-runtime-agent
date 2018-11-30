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
  switch (node.type) {
    case 'FunctionDeclaration': {
      const loc = node.body.loc.start;
      const name = node.id.name;
      cb(path.concat(name), loc);
      break;
    }
    case 'FunctionExpression':
      cb(path, node.body.loc.start);
      break;
    case 'ExpressionStatement': {
      if (!node.expression.right) {
        return;
      }
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
      break;
    }
    case 'VariableDeclaration':
      node.declarations.forEach((decl) => {
        let newPath;
        if (decl.init && decl.init.id && decl.init.id.name) {
          newPath = path.concat(decl.init.id.name);
        } else if (decl.id && decl.id.name) {
          newPath = path.concat(decl.id.name);
        }

        inspectNode(decl.init, newPath, cb);
      });
      break;
    case 'ExportNamedDeclaration':
      inspectNode(node.declaration, path, cb);
      break;
    case 'AssignmentExpression':
      inspectNode(node.left, path, cb);
      inspectNode(node.right, path, cb);
      break;
    case 'ObjectExpression':
      for (const prop of node.properties) {
        inspectNode(prop, path, cb);
      }
      break;
    case 'Property':
      const key = node.key;
      if (key.type !== 'Identifier') {
        // e.g. { ["concatenation" + "here"]: 5 }
        return;
      }
      inspectNode(node.value, path.concat(key.name), cb);
      break;
    case 'ClassDeclaration': {
      const name = node.id;
      if (name.type !== 'Identifier') {
        return;
      }
      const body = node.body;
      if (body.type !== 'ClassBody') {
        return;
      }
      body.body.forEach(child => {
        inspectNode(child, path.concat(`${name.name}.prototype`), cb);
      });
      break;
    }
    case 'MethodDefinition': {
      const key = node.key;
      if (key.type !== 'Identifier') {
        return;
      }
      inspectNode(node.value, path.concat(`${key.name}`), cb);
      break;
    }
  }
}

module.exports = {findAllVulnerableFunctionsInScript};
