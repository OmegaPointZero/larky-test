const crypto = require('crypto');

module.exports = (function(app){
    app.get('/', (req,res) => {
        res.render('home.ejs', {vault:process.env.VAULT_ID})
    })

    app.post('/request', AuthenticateRequest, (req,res)=>{
      var body = req.body;
      var obj = {
        "Status":"Success!",
        "Message":`Processed transaction for card ending in ${res.locals.cardNumber.slice(res.locals.cardNumber.length-4,)}`
      }
      res.send(obj)
    });

    function AuthenticateRequest(req,res,next){
        var body = req.body;
        var num = body['ccnum']
        var ciphertext = Buffer.from(body['encrypted'])
        var key = Buffer.from(body['key'])
        var nonce = Buffer.from(body['iv'])
        var tag = Buffer.from(body['tag'])
        let decipher = crypto.createDecipheriv('AES-256-GCM', key, nonce)
        try {
          decipher.setAuthTag(tag)
        } catch (err) {
          console.log('Error setting auth tag:')
          console.log(err)
          throw err.code
        }
        try {
          let str = decipher.update(ciphertext)
          str += decipher.final('base64')
          if(num==str){
            res.locals.cardNumber = str;
            return next();
          } else {
            res.status(418).send('What are you doing? The decryption worked, but it didn\'t match the value of ccnum in the body.')
          }
        } catch (error) {
          console.log('There was an issue decrypting the ciphertext:')
          console.log(error)
          throw error.code
        }
    }


})
