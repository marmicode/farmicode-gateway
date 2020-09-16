const expressWinston = require('express-winston');
const winston = require('winston');
const TcpTransport = require('winston-tcp');

const pluginName = 'logger';

class SplunkTransport extends TcpTransport {
  write(entry, callback) {
    super.write(`${entry}\n`, callback);
  }
}

module.exports = {
  version: '0.1.0',
  schema: {
    $id: `${pluginName}-plugin-schema`,
  },
  init: (pluginContext) =>
    pluginContext.registerPolicy({
      name: pluginName,
      schema: {
        $id: `${pluginName}-policy-schema`,
      },
      policy: () => {
        const logger = expressWinston.logger({
          transports: [
            new winston.transports.Console({
              json: true,
              colorize: true,
            }),
            new SplunkTransport({
              host: 'localhost',
              port: 514,
              json: true,
            }),
          ],
          requestWhitelist: [
            'headers.content-length',
            'headers.user-agent',
            'method',
            'query',
            'url',
            'user.id',
          ],
          dynamicMeta: (_, res) => {
            return {
              responseContentLength: res.getHeader('Content-Length'),
            };
          },
          /* This causes the metadata to be stored at the root of the log entry. */
          metaField: null,
        });

        return async (req, res, next) => {
          logger(req, res, next);
        };
      },
    }),
};
