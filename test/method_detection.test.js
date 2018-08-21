const test = require('tap').test;

var ast = require('../lib/ast.js');

test('test st method detection', function (t) {
  var stPath = __dirname + '/fixtures/st/st.js';
  var methods = ['Mount.prototype.getPath'];
  var line = 158;
  var found = ast.findAllVulnerableFunctionsInScriptPath(
    stPath, methods
  );
  t.equal(found[methods[0]].line, line, 'Mount.prototype.getPath found');
  t.end();
});

test('test handlebars method detection', function (t) {
  var stPath = __dirname + '/fixtures/handlebars/lib/handlebars/utils.js';
  var methods = ['escapeExpression'];
  var line = 63;
  var found = ast.findAllVulnerableFunctionsInScriptPath(
    stPath, methods
  );
  t.equal(found[methods[0]].line, line, 'escapeExpression found');
  t.end();
});

test('test uglify-js method detection', function (t) {
    var stPath = __dirname + '/fixtures/uglify-js/lib/parse.js';
    var methods = ['parse_js_number'];
    var line = 180;
    var found = ast.findAllVulnerableFunctionsInScriptPath(
      stPath, methods
    );
    t.equal(found[methods[0]].line, line, 'parse_js_number found');
    t.end();
  });
  
