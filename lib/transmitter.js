var needle = require('needle');

var eventsToSend = [];
function start(projectId) {
  setInterval(() => {
    transmitData();
    eventsToSend = [];
  }, 60000);

  function transmitData() {
    if (eventsToSend.length === 0) {
      return;
    }
    needle.post(
      'https://homebase.dev.snyk.io/beacon',
      {projectId, eventsToSend},
      {json: true}
    );
  }
}

function addEvent(event) {
  eventsToSend.push(event);
}

module.exports = {start,addEvent};
