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
  console.log('Method was called',  event);
}

module.exports = {start,addEvent};
