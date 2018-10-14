const test = require('tap').test;
const sleep = require('sleep-promise');
const proxyquire =  require('proxyquire');
const nock = require('nock');

const sinon = require('sinon');
const spy = sinon.spy();
const debugMock = (loggerType) => (msg) => {spy(msg);};
const transmitter = proxyquire('../lib/transmitter', {'debug': debugMock});

test('Transmitter prints nothing for no events', async function (t) {
  await transmitter.transmitEvents('http://host/method', 'projectId');
  t.equal(spy.getCalls().length, 0, 'no debug messages for no events');
});

test('Transmitter transmits nothingfor no events', async function (t) {
  nock('http://host')
  .post('/method')
  .reply(200, {});

  await transmitter.transmitEvents('http://host/method', 'projectId');
  t.ok(!nock.isDone(), 'no transmission sent');
  nock.cleanAll();
});

test('Trasmitter prints success on transmitted events', async function(t) {
  nock('http://host')
  .post('/method')
  .reply(200, {});

  transmitter.addEvent({foo: 'bar'});
  spy.resetHistory();

  await transmitter.transmitEvents('http://host/method', 'projectId')
    .then(() => {
      const calls = spy.getCalls();
      t.equal(calls[0].args[0], 'Transmitting 1 events.', 'printing count of transmitted events');
      t.equal(calls[1].args[0], 'Successfully transmitted events.', 'printing count of transmitted events');
      t.end();
      nock.cleanAll();
    });
});

test('Transmitter prints errors on non-OK http responses', async function(t) {
  nock('http://host')
  .post('/method')
  .reply(404, (uri, requestBody) => {});

  transmitter.addEvent({foo: 'bar'});
  spy.resetHistory();

  await transmitter.transmitEvents('http://host/method', 'projectId')
    .then(() => {
      const calls = spy.getCalls();
      t.equal(calls[0].args[0], 'Transmitting 1 events.', 'printing count of transmitted events');
      t.equal(calls[1].args[0], 'Unexpected response for events transmission: 404 : {"type":"Buffer","data":[]}', 'printing unexpected http responses');
      t.end();
      nock.cleanAll();
    });
});

test('Transmitter prints errors on errors', async function(t) {
  nock('http://host')
  .post('/method')
  .reply(404, (uri, requestBody) => {throw new Error('network is down!');});

  transmitter.addEvent({foo: 'bar'});
  spy.resetHistory();

  await transmitter.transmitEvents('http://host/method', 'projectId')
    .then(() => {
      const calls = spy.getCalls();
      t.equal(calls[0].args[0], 'Transmitting 1 events.', 'printing count of transmitted events');
      t.equal(calls[1].args[0], 'Error transmitting events: Error: network is down!', 'printing errors from needle');
      t.end();
      nock.cleanAll();
    });
});
