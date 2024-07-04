
process.env.NODE_ENV = 'test'

var assert = require('assert')
var connect = require('connect')
var http = require('http')
var session = require('cookie-session')
var bodyParser = require('body-parser')
var cookieParser = require('cookie-parser')
var querystring = require('querystring')
var request = require('supertest')

var csurf = require('..')

describe('csurf', function () {
  it('should work in req.body', function (done) {
    var server = createServer()

    // See https://github.com/ladjs/supertest
    request(server)
      .get('/')
      .expect(200, function (err, res) {
        if (err) return done(err)
        var token = res.text

        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .send('_csrf=' + encodeURIComponent(token)) // req.body._csrf = csrf token
          .expect(200, done)
      })
  })

  it('should work in req.query', function (done) {
    var server = createServer()

    request(server)
      .get('/')
      .expect(200, function (err, res) {
        if (err) return done(err)
        var token = res.text

        request(server)
          .post('/?_csrf=' + encodeURIComponent(token)) // req.query._csrf = csrf token
          .set('Cookie', cookies(res))
          .expect(200, done)
      })
  })

  it('should work in csrf-token header', function (done) {
    var server = createServer()

    request(server)
      .get('/')
      .expect(200, function (err, res) {
        if (err) return done(err)
        var token = res.text

        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .set('csrf-token', token) // req.headers['csrf-token'] = csrf token
          .expect(200, done)
      })
  })

  it('should work in xsrf-token header', function (done) {
    var server = createServer()

    request(server)
      .get('/')
      .expect(200, function (err, res) {
        if (err) return done(err)
        var token = res.text

        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .set('xsrf-token', token) // req.headers['xsrf-token'] = csrf token
          .expect(200, done)
      })
  })

  it('should work in x-csrf-token header', function (done) {
    var server = createServer()

    request(server)
      .get('/')
      .expect(200, function (err, res) {
        if (err) return done(err)
        var token = res.text

        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .set('x-csrf-token', token) // req.headers['x-csrf-token'] = csrf token
          .expect(200, done)
      })
  })

  it('should work in x-xsrf-token header', function (done) {
    var server = createServer()

    request(server)
      .get('/')
      .expect(200, function (err, res) {
        if (err) return done(err)
        var token = res.text

        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .set('x-xsrf-token', token) // req.headers['x-xsrf-token'] = csrf token
          .expect(200, done)
      })
  })

  it('should fail with an invalid token', function (done) {
    var server = createServer()

    request(server)
      .get('/')
      .expect(200, function (err, res) {
        if (err) return done(err)
        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .set('X-CSRF-Token', '42')
          .expect(403, done) // 403是csurf()中间件在验证csrf token失败时返回的状态码
      })
  })

  it('should fail with no token', function (done) {
    var server = createServer()

    request(server)
      .get('/')
      .expect(200, function (err, res) {
        if (err) return done(err)
        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .expect(403, done)
      })
  })

  it('should provide error code on invalid token error', function (done) {
    var app = connect()
    app.use(session({ keys: ['a', 'b'] }))
    app.use(csurf())

    app.use(function (req, res) {
      res.end(req.csrfToken() || 'none')
    })

    app.use(function (err, req, res, next) {
      // 'EBADCSRFTOKEN'是csurf()中间件在验证csrf token失败时返回的code
      if (err.code !== 'EBADCSRFTOKEN') return next(err)
      res.statusCode = 403
      res.end('session has expired or form tampered with')
    })

    request(app)
      .get('/')
      .expect(200, function (err, res) {
        if (err) return done(err)
        request(app)
          .post('/')
          .set('Cookie', cookies(res))
          .set('X-CSRF-Token', String(res.text + 'p'))
          .expect(403, 'session has expired or form tampered with', done)
      })
  })

  it('should error without session secret storage', function (done) {
    var app = connect()

    app.use(csurf())

    // 没有通过cookie-parser或者cookie-session来保存csrf token的secret时
    request(app)
      .get('/')
      .expect(500, /misconfigured csrf/, done)
  })

  // 上面的测试用例调用createServer()时，没有传入opts，所以缺省是通过cookie-session来保存csrf token的secret
  // 下面的测试用例传入了opts.cookie，所以是通过cookie-parser来保存csrf token的secret
  describe('with "cookie" option', function () {
    describe('when true', function () {
      it('should store secret in "_csrf" cookie', function (done) {
        var server = createServer({ cookie: true })

        request(server)
          .get('/')
          .expect(200, function (err, res) {
            if (err) return done(err)
            // '_csrf'是getCookieOptions()缺省所使用的cookie name
            var data = cookie(res, '_csrf')
            var token = res.text

            assert.ok(Boolean(data))
            // data的格式是: '_csrf=csrf token; path=/'
            assert.ok(/; *path=\/(?:;|$)/i.test(data))

            request(server)
              .post('/')
              .set('Cookie', cookies(res))
              .set('X-CSRF-Token', token)
              .expect(200, done)
          })
      })

      it('should append cookie to existing Set-Cookie header', function (done) {
        var app = connect()

        app.use(cookieParser('keyboard cat'))
        app.use(function (req, res, next) {
          res.setHeader('Set-Cookie', 'foo=bar')
          next()
        })
        app.use(csurf({ cookie: true }))
        app.use(function (req, res) {
          res.end(req.csrfToken() || 'none')
        })

        request(app)
          .get('/')
          .expect(200, function (err, res) {
            if (err) return done(err)
            var token = res.text

            assert.ok(Boolean(cookie(res, '_csrf')))
            assert.ok(Boolean(cookie(res, 'foo')))

            request(app)
              .post('/')
              .set('Cookie', cookies(res))
              .set('X-CSRF-Token', token)
              .expect(200, done)
          })
      })
    })

    describe('when an object', function () {
      it('should configure the cookie name with "key"', function (done) {
        var server = createServer({ cookie: { key: '_customcsrf' } })

        request(server)
          .get('/')
          .expect(200, function (err, res) {
            if (err) return done(err)
            var data = cookie(res, '_customcsrf')
            var token = res.text

            assert.ok(Boolean(data))
            assert.ok(/; *path=\/(?:;|$)/i.test(data))

            request(server)
              .post('/')
              .set('Cookie', cookies(res))
              .set('X-CSRF-Token', token)
              .expect(200, done)
          })
      })

      it('should keep default cookie name when "key: undefined"', function (done) {
        var server = createServer({ cookie: { key: undefined } })

        request(server)
          .get('/')
          .expect(200, function (err, res) {
            if (err) return done(err)
            var data = cookie(res, '_csrf')
            var token = res.text

            assert.ok(Boolean(data))
            assert.ok(/; *path=\/(?:;|$)/i.test(data))

            request(server)
              .post('/')
              .set('Cookie', cookies(res))
              .set('X-CSRF-Token', token)
              .expect(200, done)
          })
      })

      describe('when "signed": true', function () {
        it('should enable signing', function (done) {
          var server = createServer({ cookie: { signed: true } })

          request(server)
            .get('/')
            .expect(200, function (err, res) {
              if (err) return done(err)
              var data = cookie(res, '_csrf')
              var token = res.text

              assert.ok(Boolean(data))
              // data的格式是: '_csrf=s%3A2vTcscla_jdIVzO0--Q7p50-.G62O5BkLVs3s3EOjlhwH4brF6nOWKhPSI80iM0MG%2FkM; Path=/'
              // cookie签名是在setSecret()函数中实现的
              assert.ok(/^_csrf=s%3A/i.test(data))

              request(server)
                .post('/')
                .set('Cookie', cookies(res))
                .set('X-CSRF-Token', token)
                .expect(200, done)
            })
        })

        it('should error without cookieParser', function (done) {
          var app = connect()

          app.use(csurf({ cookie: { signed: true } }))

          request(app)
            .get('/')
            .expect(500, /misconfigured csrf/, done)
        })

        it('should error when cookieParser is missing secret', function (done) {
          var app = connect()

          // 调用csurf()传入的options.cookie.signed为true，但是调用cookieParser()时没有传入secret，导致verifyConfiguration从req.secret取不到值
          app.use(cookieParser())
          app.use(csurf({ cookie: { signed: true } }))

          request(app)
            .get('/')
            .expect(500, /misconfigured csrf/, done)
        })
      })
    })
  })

  describe('with "ignoreMethods" option', function () {
    it('should reject invalid value', function () {
      assert.throws(createServer.bind(null, { ignoreMethods: 'tj' }), /option ignoreMethods/)
    })

    it('should not check token on given methods', function (done) {
      var server = createServer({ ignoreMethods: ['GET', 'POST'] })

      request(server)
        .get('/')
        .expect(200, function (err, res) {
          if (err) return done(err)
          var cookie = cookies(res)
          request(server)
            .post('/')
            .set('Cookie', cookie)
            .expect(200, function (err, res) {
              if (err) return done(err)
              request(server)
                .put('/') // put没有在ignoreMethods中，所以需要csrf token
                .set('Cookie', cookie)
                .expect(403, done)
            })
        })
    })
  })

  // 下面的测试用例传入opts.sessionKey，所以是通过session来保存csrf token的secret
  describe('with "sessionKey" option', function () {
    it('should use the specified sessionKey', function (done) {
      var app = connect()
      var sess = {}

      app.use(function (req, res, next) {
        req.mySession = sess
        next()
      })
      app.use(bodyParser.urlencoded({ extended: false }))
      app.use(csurf({ sessionKey: 'mySession' }))
      app.use(function (req, res, next) {
        res.end(req.csrfToken() || 'none')
      })

      request(app)
        .get('/')
        .expect(200, function (err, res) {
          if (err) return done(err)
          var token = res.text

          request(app)
            .post('/')
            .send('_csrf=' + encodeURIComponent(token))
            .expect(200, done)
        })
    })
  })

  describe('req.csrfToken()', function () {
    it('should return same token for each call', function (done) {
      var app = connect()
      app.use(session({ keys: ['a', 'b'] }))
      app.use(csurf())
      app.use(function (req, res) {
        var token1 = req.csrfToken()
        var token2 = req.csrfToken()
        res.end(String(token1 === token2))
      })

      request(app)
        .get('/')
        .expect(200, 'true', done)
    })

    it('should error when secret storage missing', function (done) {
      var app = connect()

      app.use(session({ keys: ['a', 'b'] }))
      app.use(csurf())
      app.use(function (req, res) {
        // See https://github.com/expressjs/cookie-session?tab=readme-ov-file#destroying-a-session
        req.session = null
        res.setHeader('x-run', 'true')
        res.end(req.csrfToken())
      })

      request(app)
        .get('/')
        .expect('x-run', 'true')
        .expect(500, /misconfigured csrf/, done)
    })
  })

  describe('when using session storage', function () {
    var app
    before(function () {
      app = connect()
      app.use(session({ keys: ['a', 'b'] }))
      app.use(csurf())
      app.use('/break', function (req, res, next) {
        // break session
        req.session = null
        next()
      })
      app.use('/new', function (req, res, next) {
        // regenerate session
        // req.csrfToken()这种情况下会重新生成一个csrf token
        req.session = { hit: 1 }
        next()
      })
      app.use(function (req, res) {
        res.end(req.csrfToken() || 'none')
      })
    })

    it('should work with a valid token', function (done) {
      request(app)
        .get('/')
        .expect(200, function (err, res) {
          if (err) return done(err)
          var token = res.text
          request(app)
            .post('/')
            .set('Cookie', cookies(res))
            .set('X-CSRF-Token', token)
            .expect(200, done)
        })
    })

    it('should provide a valid token when session regenerated', function (done) {
      request(app)
        .get('/new')
        .expect(200, function (err, res) {
          if (err) return done(err)
          var token = res.text
          request(app)
            .post('/')
            .set('Cookie', cookies(res))
            .set('X-CSRF-Token', token)
            .expect(200, done)
        })
    })

    it('should error if session missing', function (done) {
      request(app)
        .get('/break')
        .expect(500, /misconfigured csrf/, done)
    })
  })
})

function cookie (res, name) {
  return res.headers['set-cookie'].filter(function (cookies) {
    return cookies.split('=')[0] === name
  })[0]
}

function cookies (res) {
  // res.headers['set-cookie'】返回一个数组，每个元素是一个cookie。
  // 假如 res.headers['set-cookie'】是:
  // [
  // 'express:sess=eyJjc3JmU2VjcmV0IjoiMkJJeER5NllWVEtwRUFyYmZpMjRXa0J0In0=; path=/; httponly',
  // 'express:sess.sig=4P-6WyiyKzMk7SkOlLAiD4n9Dx4; path=/; httponly'
  // ]
  // 则返回:
  // 'express:sess=eyJjc3JmU2VjcmV0IjoiMkJJeER5NllWVEtwRUFyYmZpMjRXa0J0In0=;express:sess.sig=4P-6WyiyKzMk7SkOlLAiD4n9Dx4'
  return res.headers['set-cookie'].map(function (cookies) {
    return cookies.split(';')[0]
  }).join(';')
}

// 这个opts会原样传给csurf()
function createServer (opts) {
  // See https://github.com/senchalabs/connect
  var app = connect()

  // 使用中间件cookie-parser还是cookie-session来保存csrf token的secret, 取决于opts.cookie
  if (!opts || (opts && !opts.cookie)) {
    app.use(session({ keys: ['a', 'b'] }))
  } else if (opts && opts.cookie) {
    app.use(cookieParser('keyboard cat'))
  }

  app.use(function (req, res, next) {
    // 继续出req中的query string并复制给req.query
    var index = req.url.indexOf('?') + 1

    if (index) {
      req.query = querystring.parse(req.url.substring(index))
    }

    next()
  })

  app.use(bodyParser.urlencoded({ extended: false }))
  app.use(csurf(opts))

  app.use(function (req, res) {
    // 把csrf token作为response body直接返回
    res.end(req.csrfToken() || 'none')
  })

  return http.createServer(app)
}
