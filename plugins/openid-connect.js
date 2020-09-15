const axios = require('axios');
const jwkToPem = require('jwk-to-pem');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const uuid = require('uuid');
const { ExtractJwt, Strategy: JwtStrategy } = require('passport-jwt');

module.exports = {
  version: '0.1.0',
  schema: {
    $id: 'openid-connect',
  },
  init: (pluginContext) =>
    pluginContext.registerPolicy({
      name: 'openid-connect',
      schema: {
        $id: 'openid-connect',
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
          openidProvider: {
            type: 'string',
          },
        },
        required: ['audience', 'algorithms', 'openidProvider'],
      },
      policy: ({ algorithms, audience, openidProvider }) => {
        const jwksPromise = getJwks(openidProvider);

        /* This is inspired from express-gateway's JWT policy and adapted to work with openid-connect discovery.
         * We are not using getCommonAuthCallback because we don't want to use express-gateways users db
         * as we want the gateway to be stateless. */
        return async (req, res, next) => {
          const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
          if (token == null) {
            next();
            return;
          }

          const jwks = await jwksPromise;

          /* Get kid from token. */
          const { kid } = jwt.decode(token, { complete: true })?.header;

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
              issuer: openidProvider,
              audience,
            },
            /* Using an object with claims property
             * containing JWT claims as the user object. */
            (claims, done) => done(null, { claims })
          );

          /* Making sure passport strategy doesn't collide with another instance with a different configuration. */
          const strategyId = `openid-connect-${uuid.v4()}`;

          passport.use(strategyId, strategy);

          passport.authenticate(strategyId, {
            session: false,
          })(req, res, next);
        };
      },
    }),
};

async function getJwks(openidProvider) {
  const response = await axios.get(
    `${openidProvider.replace(/\/$/, '')}/.well-known/openid-configuration`
  );
  const jwksUri = response.data.jwks_uri;
  const jwksResponse = await axios.get(jwksUri);
  return jwksResponse.data.keys;
}
