Template.configureLoginServiceDialogForSaml2.helpers({
  siteUrl: function () {
    return Meteor.absoluteUrl();
  }
});

Template.configureLoginServiceDialogForSaml2.fields = function () {
  return [
    {property: 'entryPoint', label: 'Entry Point'},
    {property: 'issuer', label: 'Issuer'},
    {property: 'path', label: 'Path'},
    {property: 'cert', label: 'X.509 Certificate'}
  ];
};