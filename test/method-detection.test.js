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


test('test clashing variable/function declaration', function (t) {
  const contents = `
var foo;
function foo() {
}
`;
  const methods = ['foo'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 3, 'foo');
  t.end();
});

test('test function body method detection', function (t) {
  const contents = `
function foo() {
  function bar() {}
}
`;
  const methods = ['foo', 'foo.bar'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 2, 'foo');
  t.equal(found[methods[1]].start.line, 3, 'foo.bar');
  t.end();
});

test('test anonymous function not splatting parent', function (t) {
  const contents = `
function foo() {
  console.log(function() {});
}
`;
  const methods = ['foo'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 2, 'foo');
  t.end();
});

test('test array element inspection', function (t) {
  const contents = `
console.log([function() {
  function foo() {}
}]);
`;
  const methods = ['foo'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 3, 'foo');
  t.end();
});

test('test if body inspection', function (t) {
  const contents = `
if (console.singular) {
  function foo() {}
}
if (console.both) {
  function bar() {}
} else {
  function baz() {}
}
`;
  const methods = ['bar', 'baz', 'foo'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 6, 'foo');
  t.equal(found[methods[1]].start.line, 8, 'bar');
  t.equal(found[methods[2]].start.line, 3, 'baz');
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


test('test explicit fake-anonymous function', function (t) {
  const contents = `
const foo = function bar() {
  function baz() {}
};
`;
  const methods = ['bar', 'bar.baz'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 2, 'bar found');
  t.equal(found[methods[1]].start.line, 3, 'bar.baz found');
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

test('test literals in objects detection', function (t) {
  const contents = `
console.log({
  1: function() { function foo() { } },
  'foo-bar': function() { function foo_bar() { } },
});
`;
  const methods = ['1.foo', 'foo-bar.foo_bar'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 3, 'foo found');
  t.equal(found[methods[1]].start.line, 4, 'foo_bar found');
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

test('test moment-style wrapper detection', function (t) {
  const contents = `
;(function () {
}(this, (function () {
  function hooks() {}
})));
`;
  const methods = ['hooks'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 4, 'hooks found');
  t.end();
});

test('test octal parsing', function (t) {
  const contents = `
function foo() {
  return 0777;
}
`;
  const methods = ['foo'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 2, 'foo found');
  t.end();
});

test('test return expression parsing', function (t) {
  const contents = `
foo(function () {
  return function bar() {
    function baz() {}
  }
});
`;
  const methods = ['bar', 'bar.baz'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 3, 'bar found');
  t.equal(found[methods[1]].start.line, 4, 'bar.baz found');
  t.end();
});

test('test ws const arrow function detection', function (t) {
  const contents = `
const parse = (value) => {
  console.log("hi!");
  function foo() {}
};

module.exports = { parse };
`;
  const methods = ['parse', 'parse.foo'];
  const found = ast.findAllVulnerableFunctionsInScript(
    contents, methods,
  );
  t.same(sorted(Object.keys(found)), sorted(methods));
  t.equal(found[methods[0]].start.line, 2, 'parse found');
  t.equal(found[methods[1]].start.line, 4, 'parse.foo found');
  t.end();
});

function sorted(list) {
  const copy = [];
  copy.push.apply(copy, list);
  copy.sort();
  return copy;
}
