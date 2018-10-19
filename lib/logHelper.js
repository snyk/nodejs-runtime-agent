function response(debug, logContext, response) {
  if (!response) {
    return;
  }

  if (response.statusCode !== 200) {
    debug(`Unexpected response for ${logContext} transmission: ` +
      `${response.statusCode} : ${JSON.stringify(response.body)}`);
    return;
  }

  debug(`Successfully transmitted ${logContext}.`);
}

function error(debug, logContext, error) {
  debug(`Error transmitting ${logContext}: ${error}`);
}

module.exports = {response, error};
