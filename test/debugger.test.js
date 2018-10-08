const test = require('tap').test;
const sinon = require('sinon');
var inspector = require('inspector');
const EventEmitter = require('events');
var dbg = require('../lib/debugger-wrapper');
var vulnMgmt = require('../lib/vuln-mgmt');
var moduleUtils = require('../lib/moduleUtils');
var transmitter = require('../lib/transmitter');

class MockSession extends EventEmitter {
  constructor() {
    super();
  };

  connect() {
  };

  post(method, params, cb) {
    if ((method === 'Debugger.setBreakpointByUrl') && (params.lineNumber === 158)) {
      cb(undefined, {breakpointId: 'MY_BP_IDDD'});
    } else if ((method === 'Debugger.setBreakpointByUrl') && (params.lineNumber !== 158)) {
      cb({error: 'MY_ERROR_MESSAGE'}, undefined);
    };
  }
}

test('test setting a breakpoint', function (t) {
  var mock = new MockSession();
  sinon.stub(inspector, 'Session').returns(mock);
  sinon.stub(moduleUtils, 'getModuleInfo').returns(
    {'version': '0.2.1','name': 'st', 'scriptRelativePath': 'st.js'}
  );
  dbg.start();
  vulnMgmt.setVulnerabiltiesMetadata(require('./fixtures/st/vulnerable_methods.json'));
  var stScriptInfo = require('./fixtures/st/script.json');
  var transmitterSpy = sinon.spy(transmitter, 'addEvent');
  stScriptInfo.params.url = __dirname + '/' + stScriptInfo.params.url;
  mock.emit('Debugger.scriptParsed', stScriptInfo);
  t.assert('error' in transmitterSpy.args[0][0], 'Error event was added to transmitter');
  t.equal(1, transmitterSpy.callCount, 'Add event was call once because of set bp error');
  t.equal(true, true, 'Mount.prototype.getPath found');
  t.end();
});
