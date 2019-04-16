const test = require('tap').test;
const proxyquire =  require('proxyquire');
const nock = require('nock');
const needle = require('needle');

const sinon = require('sinon');
const spy = sinon.spy();
const debugMock = (loggerType) => (msg) => {spy(msg);};
const state = require('../lib/state');
const config = require('../lib/config');
config.initConfig({projectId: 'some-project-id'});
const transmitter = proxyquire('../lib/transmitter', {'debug': debugMock});

test('Transmitter transmits 0 events for no events', async function (t) {
  nock('http://host')
    .post('/method')
    .reply(200, {});
  nock('http://host')
    .post('/method')
    .reply(200, {});

  spy.resetHistory();
  const needleSpy = sinon.spy(needle, 'request');

  await transmitter.transmitEvents('http://host/method', 'some-project-id', 'some-agent-id');
  t.equal(needleSpy.args[0][0], 'post', 'beacons are being posted');
  t.equal(needleSpy.args[0][1], 'http://host/method', 'url is correct');
  t.ok('agentId' in needleSpy.args[0][2], 'agent ID is transmitted');
  t.equal(needleSpy.args[0][2]['agentId'], 'some-agent-id', 'agent ID is correct');
  t.ok('projectId' in needleSpy.args[0][2], 'project ID is transmitted');
  t.equal(needleSpy.args[0][2]['projectId'], 'some-project-id', 'project ID is correct');
  t.deepEqual(needleSpy.args[0][3], {json: true, rejectUnauthorized: true}, 'request options are correct');

  config['allowUnknownCA'] = true;
  await transmitter.transmitEvents('http://host/method', 'some-project-id', 'some-agent-id');
  t.deepEqual(needleSpy.args[1][3], {json: true, rejectUnauthorized: false}, 'request options are correct');

  t.ok(nock.isDone(), 'two transmissions sent');

  nock.cleanAll();
});

test('Trasmitter prints success on transmitted events', async function(t) {
  nock('http://host')
  .post('/method')
  .reply(200, {});

  state.addEvent({foo: 'bar'});
  spy.resetHistory();

  await transmitter.transmitEvents('http://host/method', 'some-project-id', 'some-agent-id')
    .then(() => {
      const calls = spy.getCalls();
      t.equal(calls[0].args[0], 'agent:some-agent-id transmitting 1 events to http://host/method with project ID some-project-id.', 'printing count of transmitted events');
      t.equal(calls[1].args[0], 'Successfully transmitted events.', 'printing count of transmitted events');
      t.end();
      nock.cleanAll();
    });
});

test('Transmitter prints errors on non-OK http responses', async function(t) {
  nock('http://host')
  .post('/method')
  .reply(404, (uri, requestBody) => {});

  state.addEvent({foo: 'bar'});
  spy.resetHistory();

  await transmitter.transmitEvents('http://host/method', 'some-project-id', 'some-agent-id')
    .then(() => {
      const calls = spy.getCalls();
      t.equal(calls[0].args[0], 'agent:some-agent-id transmitting 1 events to http://host/method with project ID some-project-id.', 'printing count of transmitted events');
      t.equal(calls[1].args[0], 'Unexpected response for events transmission: 404 : {"type":"Buffer","data":[]}', 'printing unexpected http responses');
      t.end();
      nock.cleanAll();
    });
});

test('Transmitter prints errors on errors', async function(t) {
  nock('http://host')
  .post('/method')
  .reply(404, (uri, requestBody) => {throw new Error('network is down!');});

  state.addEvent({foo: 'bar'});
  spy.resetHistory();

  await transmitter.transmitEvents('http://host/method', 'some-project-id', 'some-agent-id')
    .then(() => {
      const calls = spy.getCalls();
      t.equal(calls[0].args[0], 'agent:some-agent-id transmitting 1 events to http://host/method with project ID some-project-id.', 'printing count of transmitted events');
      t.equal(calls[1].args[0], 'Error transmitting events: Error: network is down!', 'printing errors from needle');
      t.end();
      nock.cleanAll();
    });
});
