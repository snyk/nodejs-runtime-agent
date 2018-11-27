const test = require('tap').test;
const sinon = require('sinon');
const inspector = require('inspector');
const EventEmitter = require('events');

const snapshot = require('../lib/snapshot');
const dbg = require('../lib/debugger-wrapper');
const transmitter = require('../lib/transmitter');
const moduleUtils = require('../lib/module-utils');

class MockSession extends EventEmitter {
  constructor() {
    super();
  };

  connect() {};

  post(method, params, cb) {
    if ((method === 'Debugger.setBreakpointByUrl') && (params.lineNumber === 158)) {
      cb(undefined, {breakpointId: 'MY_BP_IDDD'});
    } else if ((method === 'Debugger.setBreakpointByUrl') && (params.lineNumber !== 158)) {
      cb({error: 'MY_ERROR_MESSAGE'}, undefined);
    };
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
  snapshot.setVulnerabiltiesMetadata(require('./fixtures/st/vulnerable_methods.json'));
  const stScriptInfo = require('./fixtures/st/script.json');
  const transmitterSpy = sinon.spy(transmitter, 'addEvent');
  stScriptInfo.params.url = __dirname + '/' + stScriptInfo.params.url;
  mock.emit('Debugger.scriptParsed', stScriptInfo);
  t.assert('error' in transmitterSpy.args[0][0], 'Error event was added to transmitter');
  t.equal(1, transmitterSpy.callCount, 'Add event was call once because of set bp error');
  t.equal(true, true, 'Mount.prototype.getPath found');
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
