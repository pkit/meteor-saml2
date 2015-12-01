Saml2 = {};

var Fiber = Npm.require('fibers');
var Url = Npm.require('url');
var xml2js = Npm.require('xml2js');
var bodyParser = Npm.require("body-parser");
var XmlDom = Npm.require('xmldom');
var XmlCrypto = Npm.require('xml-crypto');

WebApp.connectHandlers.use(bodyParser.urlencoded({ extended: true })).use(function (req, res, next) {
  // Need to create a Fiber since we're using synchronous http calls and nothing
  // else is wrapping this in a fiber automatically
  Fiber(function () {
    middleware(req, res, next);
  }).run();
});

Saml2.isCallbackRequest = function (req) {
  var config = ServiceConfiguration.configurations.findOne({service: 'saml2'});
  return !!(config && req.url === config.path && req.method === 'POST');
};

Saml2.certToPEM = function (cert) {
  if (cert.indexOf("BEGIN CERTIFICATE") === -1 && cert.indexOf("END CERTIFICATE") === -1) {
    cert = cert.match(/.{1,64}/g).join('\n');
    cert = "-----BEGIN CERTIFICATE-----\n" + cert;
    cert = cert + "\n-----END CERTIFICATE-----\n";
    return cert;
  } else {
    return cert;
  }
};

Saml2.validate = function (xml) {
  var doc = new XmlDom.DOMParser().parseFromString(xml);
  var signature = XmlCrypto.xpath(doc,
    "/*/*[local-name(.)='Signature'" +
    " and " +
    "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var signed = new XmlCrypto.SignedXml(null, {
    idAttribute: 'AssertionID'
  });

  var config = ServiceConfiguration.configurations.findOne({service: 'saml2'});

  signed.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>"
    },
    getKey: function (keyInfo) {
      return Saml2.certToPEM(config.cert);
    }
  };

  signed.loadSignature(signature.toString());
  return signed.checkSignature(xml);
};

Saml2.getData = function (xml, cb, req, res) {
  if (!Saml2.validate(xml)) {
    Log.warn('Error in SAML2 validation: ' + xml);
    throw new Error('Filed to validate SAML2 callback response');
  }

  var parser = new xml2js.Parser({tagNameProcessors: [xml2js.processors.stripPrefix], attrkey: "@", charKey: "#"});
  parser.parseString(xml, function (err, result) {
    if (err) {
      throw err;
    } else {
      cb(result, req, res);
    }
  });
};

var middleware = function (req, res, next) {
  // Make sure to catch any exceptions because otherwise we'd crash
  // the runner
  try {
    if (!Saml2.isCallbackRequest(req)) {
      // not a saml2 request. pass to next middleware.
      next();
      return;
    }

    // parse out query string from referer and attach it as if was passed in request
    var url = Url.parse(req.headers.referer, true);
    req.query = url.query;

    // check if user authorized access
    if (!req.query.error) {
      var SamlResponse = req.body.SAMLResponse;
      var string;
      try {
        string = new Buffer(SamlResponse, 'base64').toString('binary');
      } catch (e) {
        Log.warn('Unable to base64 decode SamlResponse: ' + SamlResponse);
        throw e;
      }
      Saml2.getData(string, Saml2.parseData, req, res);
    }

  } catch (err) {
    // if we got thrown an error, save it off, it will get passed to
    // the appropriate login call (if any) and reported there.
    //
    // The other option would be to display it in the popup tab that
    // is still open at this point, ignoring the 'close' or 'redirect'
    // we were passed. But then the developer wouldn't be able to
    // style the error or react to it in any way.
    if (req.query.state && err instanceof Error) {
      try { // catch any exceptions to avoid crashing runner
        OAuth._storePendingCredential(OAuth._credentialTokenFromQuery(req.query), err);
      } catch (err) {
        // Ignore the error and just give up. If we failed to store the
        // error, then the login will just fail with a generic error.
        Log.warn("Error in OAuth Server while storing pending login result.\n" +
          err.stack || err.message);
      }
    }

    // close the popup. because nobody likes them just hanging
    // there.  when someone sees this multiple times they might
    // think to check server logs (we hope?)
    // Catch errors because any exception here will crash the runner.
    try {
      OAuth._endOfLoginResponse(res, {
        query: req.query,
        loginStyle: OAuth._loginStyleFromQuery(req.query),
        error: err
      });
    } catch (err) {
      Log.warn("Error generating end of login response\n" +
        (err && (err.stack || err.message)));
    }
  }
};

Saml2.parseData = function (data, req, res) {
  var assertion = data['Response']['Assertion'][0];
  var identity = {id: assertion['Subject'][0]['NameID'][0]['_']};
  var attrs = assertion['AttributeStatement'][0]['Attribute'];
  var attrLen = attrs.length;
  for (var i = 0; i < attrLen; i++) {
    var key = attrs[i]['@']['Name'];
    identity[key] = attrs[i]['AttributeValue'][0]['_'];
  }
  var fullName = identity.givenName + ' ' + identity.sn;
  var oauthResult = {
    serviceData: {
      id: identity.id,
      email: identity.mail.toLowerCase(),
      name: fullName,
      photo: identity.photo,
      username: identity.mail.toLowerCase()
    },
    options: {profile: {name: fullName}}
  };

  var credentialSecret = Random.secret();
  var credentialToken = OAuth._credentialTokenFromQuery(req.query);

  // Store the login result so it can be retrieved in another
  // browser tab by the result handler
  OAuth._storePendingCredential(credentialToken, {
    serviceName: 'saml2',
    serviceData: oauthResult.serviceData,
    options: oauthResult.options
  }, credentialSecret);

  // Either close the window, redirect, or render nothing
  // if all else fails
  OAuth._renderOauthResults(res, req.query, credentialSecret);
};

Saml2.retrieveCredential = function (credentialToken, credentialSecret) {
  return OAuth.retrieveCredential(credentialToken, credentialSecret);
};