const jwkToPem = require('jwk-to-pem');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { promisify, callbackify } = require('util');
const uuid = require('uuid');
const { ExtractJwt, Strategy: JwtStrategy } = require('passport-jwt');
const {
  applyMetadata,
  getOpenapiSpecification,
  getOpenidInfo,
} = require('./lib/openapi-utils');

const pluginName = 'openapi-openid-connect';

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
        type: 'object',
        properties: {
          algorithms: {
            type: 'array',
            items: {
              type: 'string',
            },
          },
          audience: {
            type: 'string',
          },
          openapiSpecPath: {
            type: 'string',
          },
        },
        required: ['audience', 'openapiSpecPath'],
      },
      policy: ({ algorithms = ['RS256'], audience, openapiSpecPath }) => {
        const specPromise = getOpenapiSpecification(openapiSpecPath);

        const openidSchemesMapPromise = specPromise.then(async (spec) => {
          return new Map(
            await Promise.all(
              Object.entries(spec.apiDoc.components?.securitySchemes ?? [])
                /* Filter "openIdConnect" security schemes only. */
                .filter(([_, scheme]) => scheme.type === 'openIdConnect')
                /* Get JWKs. */
                .map(([schemeId, scheme]) =>
                  getOpenidInfo(scheme.openIdConnectUrl).then((openidInfo) => [
                    schemeId,
                    { ...scheme, ...openidInfo },
                  ])
                )
            )
          );
        });

        return async (req, res, next) => {
          const spec = await specPromise;

          const openidSchemesMap = await openidSchemesMapPromise;

          /* Add openapi metadata to request. */
          await applyMetadata({ spec, req, res });

          const securitySchemeList = req.openapi.schema.security ?? [];

          /* Find the first openidConnect scheme. */
          const schemeInfo = securitySchemeList
            .map((scheme) => {
              const name = Object.keys(scheme)[0];
              return {
                name,
                requiredScopes: scheme[name],
              };
            })
            .find(({ name }) => openidSchemesMap.has(name));

          /* Skip policy if no openidConnect security schemes are defined for this route. */
          if (schemeInfo == null) {
            next();
            return;
          }

          const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);

          if (token == null) {
            res.sendStatus(401);
            return;
          }

          /* Get kid from token. */
          const { kid } = jwt.decode(token, { complete: true })?.header;

          const requiredScopes = schemeInfo.requiredScopes;

          const { issuer, jwks } = openidSchemesMap.get(schemeInfo.name);

          const jwk = jwks.find((jwk) => jwk.kid === kid);

          /* Key not found. */
          if (jwk == null) {
            res.sendStatus(401);
            return;
          }

          const strategy = new JwtStrategy(
            {
              algorithms,
              jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
              secretOrKey: jwkToPem(jwk),
              issuer,
              audience,
            },
            /* Using an object with claims property
             * containing JWT claims as the user object. */
            callbackify(async (claims) => {
              const tokenScopes = claims.scopes?.split(' ');
              if (
                !requiredScopes.every((scope) => tokenScopes?.includes(scope))
              ) {
                throw new Error(
                  `some required scopes are missing: ${requiredScopes}`
                );
              }

              /* Return `{claims}` as the user object to passport. */
              return { claims };
            })
          );

          /* Making sure passport strategy doesn't collide with another instance with a different configuration. */
          const strategyId = `openid-connect-${uuid.v4()}`;

          passport.use(strategyId, strategy);

          try {
            await promisify(
              passport.authenticate(strategyId, {
                session: false,
              })
            )(req, res);
            next();
          } catch {
            res.status(403);
            res.send({
              errors: [
                {
                  errorCode: 'missing-scopes',
                  requiredScopes,
                },
              ],
            });
          }
        };
      },
    }),
};
