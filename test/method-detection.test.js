const fs = require('fs');
const test = require('tap').test;

const ast = require('../lib/ast.js');

test('test bootstrap +function method detection', function (t) {
  const contents = `
+function ($){
  var Aye = function (one, two) {
  }
  Aye.prototype.foo = function (three) {
  }
  $.fn.aye = Aye
}(jQuery);
`;
  const methods = ['Aye', 'Aye.prototype.foo'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 3, 'A found');
  t.equal(found[methods[1]].start.line, 5, 'A.prototype.foo found');
  t.end();
});

test('test st method detection', function (t) {
  const content = fs.readFileSync(__dirname + '/fixtures/st/node_modules/st.js');
  const methods = ['Mount.prototype.getPath'];
  const line = 158;
  const found = ast.findAllVulnerableFunctionsInScript(
    content, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, line, 'Mount.prototype.getPath found');
  t.end();
});

test('test handlebars method detection', function (t) {
  const content = fs.readFileSync(__dirname + '/fixtures/handlebars/lib/handlebars/utils.js');
  const methods = ['escapeExpression'];
  const line = 63;
  const found = ast.findAllVulnerableFunctionsInScript(
    content, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, line, 'escapeExpression found');
  t.end();
});

test('test uglify-js method detection', function (t) {
  const content = fs.readFileSync(__dirname + '/fixtures/uglify-js/lib/parse.js');
  const methods = ['parse_js_number'];
  const line = 180;
  const found = ast.findAllVulnerableFunctionsInScript(
    content, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, line, 'parse_js_number found');
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
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 3, 'foo found');
  t.equal(found[methods[1]].start.line, 4, 'bar found');
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
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 3, 'constructor found');
  t.equal(found[methods[1]].start.line, 4, 'sampleRate found');
  t.equal(found[methods[2]].start.line, 5, 'lfo found');
  t.end();
});

test('test inner function function detection', function (t) {
  const contents = `
;(function() {
  var runInContext = (function yellow(context) {
    function baseMerge() {}
  });
  var _ = runInContext();
})();
`;
  const methods = ['yellow.baseMerge'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 4, 'baseMerge found');
  t.end();
});

test('test lodash-CC-style function detection', function (t) {
  const contents = `
;(function() {
  var runInContext = (function yellow(context) {
    function baseMerge() {}
  });
  var _ = runInContext();
}.call(this));
`;
  const methods = ['yellow.baseMerge'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 4, 'baseMerge found');
  t.end();
});

test('test ws const arrow function detection', function (t) {
  const contents = `
const parse = (value) => {
  console.log("hi!");
};

module.exports = { parse };
`;
  const methods = ['parse'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 2, 'parse found');
  t.end();
});

function sorted(list) {
  const copy = [];
  copy.push.apply(copy, list);
  copy.sort();
  return copy;
}
