const test = require('tap').test;
const sinon = require('sinon');
const inspector = require('inspector');
const EventEmitter = require('events');

const dbg = require('../lib/debugger-wrapper');
const state = require('../lib/state');
const moduleUtils = require('../lib/module-utils');
const snapshotReader = require('../lib/snapshot/reader');

class MockSession extends EventEmitter {
  constructor() {
    super();
  };

  connect() {};

  post(method, params, cb) {
    if ('Debugger.setBreakpointByUrl' !== method) {
      return;
    }

    switch (params.lineNumber) {
      case 157:
        cb(undefined, {breakpointId: 'getPath_BP_ID'});
        return;
      case 186:
        cb(undefined, {breakpointId: 'serve_BP_ID'});
        return;
      case 178:
        cb(undefined, {breakpointId: 'getUrl_BP_ID'});
        return;
      default:
        cb({error: `mocking has no mock for line number ${params.lineNumber}`}, undefined);
    }
  }
}

test('test setting a breakpoint', function (t) {
  const mock = new MockSession();
  sinon.stub(inspector, 'Session').returns(mock);
  sinon.stub(moduleUtils, 'getModuleInfo').returns({
    'version': '0.2.1',
    'name': 'st',
    'scriptRelativePath': 'st.js',
    'scriptPath': `${__dirname}/fixtures/st/node_modules/st.js`
  });
  dbg.init();
  snapshotReader.setVulnerabiltiesMetadata(require('./fixtures/st/vulnerable_methods.json'));
  const stScriptInfo = require('./fixtures/st/script.json');
  const stateSpy = sinon.spy(state, 'addEvent');
  stScriptInfo.params.url = __dirname + '/' + stScriptInfo.params.url;
  mock.emit('Debugger.scriptParsed', stScriptInfo);

  t.assert(stScriptInfo.params.url in dbg.scriptUrlToInstrumentedFunctions);
  const monitoredFunctionsBefore = dbg.scriptUrlToInstrumentedFunctions[stScriptInfo.params.url];
  t.equal(Object.keys(monitoredFunctionsBefore).length, 2, 'two monitored functions before');
  t.assert('Mount.prototype.getPath' in monitoredFunctionsBefore, 'getPath newly monitored');
  t.equal(monitoredFunctionsBefore['Mount.prototype.getPath'], 'getPath_BP_ID');
  t.assert('Mount.prototype.getUrl' in monitoredFunctionsBefore, 'getUrl newly monitored');
  t.equal(monitoredFunctionsBefore['Mount.prototype.getUrl'], 'getUrl_BP_ID');
  t.assert('error' in stateSpy.args[0][0], 'Error event was added to state');
  t.equal(1, stateSpy.callCount, 'Add event was called once because of set bp error');

  snapshotReader.setVulnerabiltiesMetadata(require('./fixtures/st/vulnerable_methods_new.json'));
  dbg.refreshInstrumentation();

  t.assert(stScriptInfo.params.url in dbg.scriptUrlToInstrumentedFunctions);
  const monitoredFunctionsAfter = dbg.scriptUrlToInstrumentedFunctions[stScriptInfo.params.url];
  t.equal(Object.keys(monitoredFunctionsAfter).length, 2, 'two monitored functions after');
  t.assert('Mount.prototype.getPath' in monitoredFunctionsAfter, 'getPath still monitored');
  t.equal(monitoredFunctionsAfter['Mount.prototype.getPath'], 'getPath_BP_ID');
  t.assert('Mount.prototype.serve' in monitoredFunctionsAfter, 'serve newly monitored');
  t.equal(monitoredFunctionsAfter['Mount.prototype.serve'], 'serve_BP_ID');
  t.assert(!('Mount.prototype.getUrl' in monitoredFunctionsBefore), 'getUrl removed');

  stateSpy.restore();
  t.end();
});

test('skip unnecessary debugger pauses', function (t) {
  const pauseContextDueToOOM = {reason: 'OOM'};
  t.assert(dbg.ignorePause(pauseContextDueToOOM));

  const pauseContextWithoutBreakpointsObject = {reason: 'other'};
  t.assert(dbg.ignorePause(pauseContextWithoutBreakpointsObject));

  const pauseContextWithoutBreakpoints = {reason: 'other', hitBreakpoints: []};
  t.assert(dbg.ignorePause(pauseContextWithoutBreakpoints));

  const pauseContextWithBreakpoints = {reason: 'other', hitBreakpoints: ['breakpoint-id']};
  t.assert(!dbg.ignorePause(pauseContextWithBreakpoints));

  t.end();
});

test('handle fuctions not instrumented', function (t) {
  const stateSpy = sinon.spy(state, 'addEvent');
  snapshotReader.setVulnerabiltiesMetadata(require('./fixtures/st/vulnerable_methods_invalid.json'));
  dbg.refreshInstrumentation();
  t.assert('warning' in stateSpy.args[0][0], 'warning event was added to state');
  t.equal(1, stateSpy.callCount, 'Add event was called once because of missing function from source');
  stateSpy.restore();
  t.end();
});
