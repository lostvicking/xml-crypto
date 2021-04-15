var select = require("xpath").select,
  dom = require("xmldom").DOMParser,
  SignedXml = require("../lib/signed-xml.js").SignedXml,
  FileKeyInfo = require("../lib/signed-xml.js").FileKeyInfo,
  fs = require("fs"),
  crypto = require("crypto");

module.exports = {
  "signer inserts signature after a reference node with InclusiveNamespaces": function (
    test
  ) {
    var xml = '<root><response Id="_0">xml-crypto</response></root>';
    var sig = new SignedXml();

    sig.signingKey = fs.readFileSync("./test/static/client.pem");

    sig.addReference(
      "//*[local-name(.)='response']",
      ["http://www.w3.org/2001/10/xml-exc-c14n#"],
      "http://www.w3.org/2001/04/xmlenc#sha256",
      "",
      "",
      ["ds", "saml", "xs", "xsi"],
      false
    );

    sig.computeSignature(xml, {
      location: {
        reference: "/root/response",
        action: "after",
      },
    });

    console.log("check out the signature: " + sig.getSignedXml());

    var doc = new dom().parseFromString(sig.getSignedXml());
    var referenceNode = select("/root/response", doc)[0];

    test.strictEqual(
      referenceNode.nextSibling.localName,
      "Signature",
      "the signature should be inserted after to root/name"
    );

    var sig2 = new SignedXml();
    sig2.keyInfoProvider = new FileKeyInfo("./test/static/client.pem");
    sig2.loadSignature(sig.getSignatureXml());
    var res = sig2.checkSignature(xml);
    console.log("validation errors:", sig2.validationErrors);

    test.done();
  },
};
