const fs = require('fs');
const test = require('tap').test;

const ast = require('../lib/ast.js');

test('test st method detection', function (t) {
  const content = fs.readFileSync(__dirname + '/fixtures/st/node_modules/st.js');
  const methods = ['Mount.prototype.getPath'];
  const line = 158;
  const found = ast.findAllVulnerableFunctionsInScript(
    content, methods,
  );
  t.equal(found[methods[0]].line, line, 'Mount.prototype.getPath found');
  t.end();
});

test('test handlebars method detection', function (t) {
  const content = fs.readFileSync(__dirname + '/fixtures/handlebars/lib/handlebars/utils.js');
  const methods = ['escapeExpression'];
  const line = 63;
  const found = ast.findAllVulnerableFunctionsInScript(
    content, methods,
  );
  t.equal(found[methods[0]].line, line, 'escapeExpression found');
  t.end();
});

test('test uglify-js method detection', function (t) {
  const content = fs.readFileSync(__dirname + '/fixtures/uglify-js/lib/parse.js');
  const methods = ['parse_js_number'];
  const line = 180;
  const found = ast.findAllVulnerableFunctionsInScript(
    content, methods,
  );
  t.equal(found[methods[0]].line, line, 'parse_js_number found');
  t.end();
});

test('test export = { f() {} } method detection', function (t) {
  const contents = `
module.exports = {
  foo() {},
  bar() {},
};
`;
  const methods = ['module.exports.foo', 'module.exports.bar'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.equal(found[methods[0]].line, 3, 'foo found');
  t.equal(found[methods[1]].line, 4, 'bar found');
  t.end();
});

test('test class member detection', function (t) {
  const contents = `
class Moog {
  constructor() {}
  sampleRate(freq) {}
  static lfo() { return 5; }
}

module.exports = Moog;
`;
  const methods = ['Moog.prototype.constructor', 'Moog.prototype.sampleRate', 'Moog.prototype.lfo'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(methods), sorted(Object.keys(found)));
  t.equal(found[methods[0]].line, 3, 'constructor found');
  t.equal(found[methods[1]].line, 5, 'sampleRate found');
  t.equal(found[methods[2]].line, 4, 'lfo found');
  t.end();
});

function sorted(list) {
  list.sort();
  return list;
}
