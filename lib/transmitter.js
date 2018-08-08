var needle = require('needle');

var eventsToSend = [];
function start(projectId) {
    setInterval(() => {
        console.log('Interval was called!')
        transmitData();
        eventsToSend = [];
    }, 15000)

    function transmitData() {
        console.log('transmitting data...');
        if (eventsToSend.length === 0) {
            console.log('no events to send...');
            return;
        }
        needle.post(
            'http://localhost:5000/events',
            {projectId, eventsToSend},
            {json: true}
        );
    }    
}

function addEvent(event) {
    console.log('adding event', event);
    eventsToSend.push(event);
}

module.exports = {start,addEvent};