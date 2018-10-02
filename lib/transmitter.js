var needle = require('needle');

var eventsToSend = [];
function start(url, projectId) {
  var INERVAL_TIMEOUT = 60000; // 60 seconds
  setInterval(() => {
    transmitData();
    eventsToSend = [];
  }, INERVAL_TIMEOUT);

  function transmitData() {
    if (eventsToSend.length === 0) {
      return;
    }
    needle.post(
      url,
      {projectId, eventsToSend},
      {json: true}
    );
  }
}

function addEvent(event) {
  eventsToSend.push(event);
  var message = {
    event,
    message: 'Event was added',
  };
  console.log(JSON.stringify(message));
}

module.exports = {start,addEvent};
