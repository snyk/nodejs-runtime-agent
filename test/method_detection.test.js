const test = require('tap').test;

const ast = require('../lib/ast.js');

test('test st method detection', function (t) {
  const stPath = __dirname + '/fixtures/st/node_modules/st.js';
  const methods = ['Mount.prototype.getPath'];
  const line = 158;
  const found = ast.findAllVulnerableFunctionsInScriptPath(
    stPath, methods,
  );
  t.equal(found[methods[0]].line, line, 'Mount.prototype.getPath found');
  t.end();
});

test('test handlebars method detection', function (t) {
  const stPath = __dirname + '/fixtures/handlebars/lib/handlebars/utils.js';
  const methods = ['escapeExpression'];
  const line = 63;
  const found = ast.findAllVulnerableFunctionsInScriptPath(
    stPath, methods,
  );
  t.equal(found[methods[0]].line, line, 'escapeExpression found');
  t.end();
});

test('test uglify-js method detection', function (t) {
  const stPath = __dirname + '/fixtures/uglify-js/lib/parse.js';
  const methods = ['parse_js_number'];
  const line = 180;
  const found = ast.findAllVulnerableFunctionsInScriptPath(
    stPath, methods,
  );
  t.equal(found[methods[0]].line, line, 'parse_js_number found');
  t.end();
});
