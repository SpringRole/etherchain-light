var express = require('express');
var router = express.Router();
var async = require('async');
var utils = require("ethereumjs-util");
var Web3=require("web3");
var web3=new Web3();
router.get('/verify', function(req, res, next) {  
  res.render('verifySignature');
});

router.post('/verify', function(req, res, next) {
  var ethereumAddress = req.body.ethereumAddress;
  var message = req.body.message;
  var signature = req.body.signature;
 // console.log(web3.sha3(message));
  if (!ethereumAddress) {
    res.render('verifySignature', { result: { error: "Invalid Ethereum Address"}, message: message, signature: signature, ethereumAddress: ethereumAddress });
    return;
  }
  if (!message) {
    res.render('verifySignature', { result: { error: "Invalid Message"}, message: message, signature: signature, ethereumAddress: ethereumAddress });
    return;
  }
  if (!signature) {
    res.render('verifySignature', { result: { error: "Invalid Signature"}, message: message, signature: signature, ethereumAddress: ethereumAddress });
    return;
  }
  
  try {
              var r = utils.toBuffer(signature.slice(0,66))
              var s = utils.toBuffer('0x' + signature.slice(66,130))
              var v = utils.bufferToInt(utils.toBuffer('0x' + signature.slice(130,132)))
              var m = utils.toBuffer(web3.sha3('\x19Ethereum Signed Message:\n' + message.length + message));
              var pub = utils.ecrecover(m, v, r, s)
              var adr = '0x' + utils.pubToAddress(pub).toString('hex');
             // console.log(adr);
    if (ethereumAddress === adr) {
      res.render('verifySignature', { result: { ok: "Signature is valid!"}, message: message, signature: signature, ethereumAddress: ethereumAddress });
      return;
    } else {
      res.render('verifySignature', { result: { error: "Signature is not valid!"}, message: message, signature: signature, ethereumAddress: ethereumAddress });
      return;
    }
  } catch (e) {
    res.render('verifySignature', { result: { error: "Error during signature verification: " + e}, message: message, signature: signature, ethereumAddress: ethereumAddress });
    return;
  }
});

module.exports = router;