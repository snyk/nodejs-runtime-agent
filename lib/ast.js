var fs = require('fs');
var acorn = require('acorn');

function findAllVulnerableFunctionsInScriptPath(scriptPath, vulnerableFunctionNames) {
    var scriptContent = fs.readFileSync(scriptPath);
    var parsedScript = acorn.parse(scriptContent, {locations:true});
    var decleardFunctions = {};
    var body = parsedScript.body;
    body.forEach((node) => {
        var loc, name;
        if (node.type === 'FunctionDeclaration') {
            loc = node.body.loc.start;
            name = node.id.name;
        } else if ((node.type === 'ExpressionStatement' && node.expression.right && node.expression.right.type === 'FunctionExpression')) {
            loc = node.expression.right.body.loc.start;
            name = node.expression.left.property.name;
        } else {
            return;
        }
        if (vulnerableFunctionNames.includes(name)) {
            decleardFunctions[name] = loc;    
        }
    })
    return decleardFunctions;
}
module.exports = {findAllVulnerableFunctionsInScriptPath};