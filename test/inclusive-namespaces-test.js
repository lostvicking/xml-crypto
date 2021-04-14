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
      "http://www.w3.org/2000/09/xmldsig#sha1",
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

    sig.keyInfoProvider = new FileKeyInfo("./test/static/client.pem");
    var res = sig.checkSignature(sig.getSignedXml());
    console.log(sig.validationErrors);

    test.done();
  },

  // "verify signature with InclusiveNamespaces": function (test) {
  //   var doc = new dom().parseFromString(xml);
  //   var node = select(
  //     "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
  //     doc
  //   )[0];

  //   var sig = new SignedXml();
  //   sig.keyInfoProvider = new FileKeyInfo("./test/static/client_public.pem");
  //   sig.loadSignature(node);
  //   var res = sig.checkSignature(xml);
  //   console.log(sig.validationErrors);
  //   test.done();
  // },
};
