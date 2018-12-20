const acorn = require('acorn');

function findAllVulnerableFunctionsInScript(scriptContent, vulnerableFunctionNames) {
  const declaredFunctions = {};
  const parser = new acorn.Parser(
    {locations: true, sourceType: 'module'},
    scriptContent);
  parser.strict = false;
  const parsedScript = parser.parse();
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
      const loc = node.body.loc;
      const name = node.id.name;
      cb(path.concat(name), loc);
      break;
    }
    case 'FunctionExpression':
      cb(path, node.body.loc);
      inspectNode(node.body, path, cb);
      break;
    case 'ExpressionStatement':
      inspectNode(node.expression, path, cb);
      break;
    case 'CallExpression':
      inspectNode(node.callee, path, cb);
      break;
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
    case 'AssignmentExpression': {
      inspectNode(node.left, path, cb);
      inspectNode(node.right, path.concat(unpackName(node.left)), cb);
      break;
    }
    case 'ObjectExpression':
      for (const prop of node.properties) {
        inspectNode(prop, path, cb);
      }
      break;
    case 'BlockStatement':
      for (const statement of node.body) {
        inspectNode(statement, path, cb);
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
    case 'MemberExpression':
      inspectNode(node.object, path, cb);
      break;
    case 'Identifier':
      break;
    case 'EmptyStatement':
      break;
  }
}

function unpackName(node) {
  if (!node) {
    return [];
  }

  const name = [];
  switch (node.type) {
    case 'MemberExpression': {
      pushAll(name, unpackName(node.object));
      pushAll(name, unpackName(node.property));
      break;
    }
    case 'Identifier':
      name.push(node.name);
      break;
  }

  return name;
}

function pushAll(array, values) {
  array.push.apply(array, values);
}

module.exports = {findAllVulnerableFunctionsInScript};
