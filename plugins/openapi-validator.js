const fs = require('fs');
const { PassThrough } = require('stream');
const yaml = require('yamljs');
const { OpenApiValidator } = require('express-openapi-validate');
const { json } = require('express');
const { promisify } = require('util');

module.exports = {
  version: '0.1.0',
  schema: {
    $id: 'openapi-validator',
  },
  init: (pluginContext) =>
    pluginContext.registerPolicy({
      name: 'openapi-validator',
      schema: {
        $id: 'openapi-validator',
        type: 'object',
        properties: {
          openapiPath: {
            type: 'string',
          },
        },
        required: ['openapiPath'],
      },
      policy: ({ basePath, openapiPath }) => {
        const openapiSpecification = yaml.parse(
          fs.readFileSync(openapiPath, 'utf-8')
        );

        const openapiValidator = new OpenApiValidator(openapiSpecification);

        return async (req, res, next) => {
          /* Remove base path. */
          const path = basePath ? req.path.replace(basePath, '') : req.path;

          /* Backup request stream. */
          req.egContext.requestStream = new PassThrough();
          req.pipe(req.egContext.requestStream);

          await promisify(json())(req, res);

          try {
            await promisify(
              openapiValidator.validate(req.method.toLowerCase(), path)
            )(req, res);
            next();
          } catch (err) {
            res.status(400);
            res.send({
              error: 'validation-error',
              ...err.data[0],
            });
          }
        };
      },
    }),
};
