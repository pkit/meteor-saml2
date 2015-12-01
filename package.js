Package.describe({
  summary: "SAML2 simple flow",
  version: "0.0.1"
});

Npm.depends({
  "body-parser": "1.13.1",
  "xml2js": "0.4.8",
  "xmldom": "0.1.19",
  "xml-crypto": "0.8.1"
});

Package.onUse(function(api) {
  api.versionsFrom('1.1.0.2');
  api.use(['meteor', 'webapp'], 'server');
  api.use('oauth2', ['client', 'server']);
  api.use('oauth', ['client', 'server']);
  api.use('http', ['server']);
  api.use('templating', 'client');
  api.use('underscore', 'server');
  api.use('random', ['client', 'server']);
  api.use('service-configuration', ['client', 'server']);
  api.use('logging', ['server']);

  api.export('Saml2');

  api.addFiles(
    ['saml2_configure.html', 'saml2_configure.js'],
    'client');

  api.addFiles('saml2_server.js', 'server');
  api.addFiles('saml2_client.js', 'client');
});

