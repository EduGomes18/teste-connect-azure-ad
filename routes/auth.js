const router = require('express-promise-router')();
const graph = require('../graph');
const adal = require('adal-node');


const AuthenticationContext = adal.AuthenticationContext;
/* GET auth callback. */
router.get('/signin',
  async function (req, res) {
    const urlParameters = {
      scopes: process.env.OAUTH_SCOPES.split(','),
      redirectUri: process.env.OAUTH_REDIRECT_URI
    };

    try {
      const authUrl = await req.app.locals
        .msalClient.getAuthCodeUrl(urlParameters);
      res.redirect(authUrl);
    }
    catch (error) {
      console.log(`Error: ${error}`);
      req.flash('error_msg', {
        message: 'Error getting auth URL',
        debug: JSON.stringify(error, Object.getOwnPropertyNames(error))
      });
      res.redirect('/');
    }
  }
);

router.get('/callback',
  async function(req, res) {
    const tokenRequest = {
      code: req.query.code,
      scopes: process.env.OAUTH_SCOPES.split(','),
      redirectUri: process.env.OAUTH_REDIRECT_URI
    };

    try {
      const response = await req.app.locals
        .msalClient.acquireTokenByCode(tokenRequest);

      // Save the user's homeAccountId in their session
      req.session.userId = response.account.homeAccountId;
      const user = await graph.getUserDetails(
        req.app.locals.msalClient,
        req.session.userId
      );

      // Add the user to user storage
      req.app.locals.users[req.session.userId] = {
        displayName: user.displayName,
        email: user.mail || user.userPrincipalName,
        timeZone: user.mailboxSettings.timeZone
      };
    } catch(error) {
      req.flash('error_msg', {
        message: 'Error completing authentication',
        debug: JSON.stringify(error, Object.getOwnPropertyNames(error))
      });
    }

    res.redirect('/');
  }
);

router.get('/signout',
  async function(req, res) {
    // Sign out
    if (req.session.userId) {
      // Look up the user's account in the cache
      const accounts = await req.app.locals.msalClient
        .getTokenCache()
        .getAllAccounts();

      const userAccount = accounts.find(a => a.homeAccountId === req.session.userId);

      // Remove the account
      if (userAccount) {
        req.app.locals.msalClient
          .getTokenCache()
          .removeAccount(userAccount);
      }
    }

    // Destroy the user's session
    req.session.destroy(function (err) {
      res.redirect('/');
    });
  }
);

router.get('/getUsers', async function (req, res) {

   const params = {
      tenant : process.env.OAUTH_TENANT_ID,
      authorityHostUrl : 'https://login.windows.net',
      clientId : process.env.OAUTH_APP_ID,
      clientSecret : process.env.OAUTH_APP_SECRET
    };

    var authorityUrl = params.authorityHostUrl + '/' + params.tenant;

    var resource = '00000002-0000-0000-c000-000000000000';
    var context = new AuthenticationContext(authorityUrl);

    context.acquireTokenWithClientCredentials(resource, params.clientId, params.clientSecret, function(err, tokenResponse) {
      if (err) {
        res.send(err.stack)
      } else {
        res.send(tokenResponse)
      }
    });

    // TODO =>
    // VER O ENDPOINT QUE TRAZ O USUARIO DELETADO OU INATIVADO

    // https://developer.microsoft.com/en-us/graph/graph-explorer

    // https://graph.microsoft.com/v1.0/users?

    // https://www.youtube.com/watch?v=0abYhJYNRT4

    // https://www.youtube.com/watch?v=rC1bunenaq4

    // https://github.com/AzureAD/azure-activedirectory-library-for-nodejs/blob/master/sample/client-credentials-sample.js
  
  });

module.exports = router;