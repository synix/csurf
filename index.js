/*!
 * csurf
 * Copyright(c) 2011 Sencha Inc.
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2014-2016 Douglas Christopher Wilson
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 * @private
 */

var Cookie = require('cookie')
var createError = require('http-errors')
var sign = require('cookie-signature').sign
var Tokens = require('csrf')

/**
 * Module exports.
 * @public
 */

module.exports = csurf

/**
 * CSRF protection middleware.
 *
 * This middleware adds a `req.csrfToken()` function to make a token
 * which should be added to requests which mutate
 * state, within a hidden form field, query-string etc. This
 * token is validated against the visitor's session.
 *
 * @param {Object} options
 * @return {Function} middleware
 * @public
 */

function csurf (options) {
  // csurf()函数返回一个中间件，这个中间件有2个作用
  // 1. 将csrfToken()函数挂到req对象上，用于生成csrf token
  //    - 生成的csrf token后需要调用方进行设置，这个中间件会通过options.value函数从请求中获取csrf token
  //    - csrf token内部包含了salt和secret两部分，这个secret(验证时会用到)存储在session和cookie中是可配置的(options.sessionKey和options.cookie)
  // 2. 验证请求中的csrf token是否有效
  //   - 验证请求时需要csrf token和secret两个值

  var opts = options || {}

  // get cookie options
  var cookie = getCookieOptions(opts.cookie)

  // get session options
  var sessionKey = opts.sessionKey || 'session'

  // get value getter
  // value是一个函数，接收req作为入参，用于获取请求req中的csrf token
  var value = opts.value || defaultValue

  // token repo
  // See https://github.com/pillarjs/csrf
  // 这里假定传入csurf()的options参数包括Tokens构造函数所需的saltLength和secretLength可选字段
  var tokens = new Tokens(opts)

  // ignored methods
  // 这里假定传入csurf()的options参数包括ignoreMethods可选字段
  var ignoreMethods = opts.ignoreMethods === undefined
    ? ['GET', 'HEAD', 'OPTIONS']
    : opts.ignoreMethods

  // 从上面的代码可以看出，options参数是一个对象，至少支持cookie(支持key/path/signed)、sessionKey、value、saltLength/secretLength(依赖于csrf库)、ignoreMethods这些字段
  if (!Array.isArray(ignoreMethods)) {
    throw new TypeError('option ignoreMethods must be an array')
  }

  // generate lookup
  // 通过数组生成一个对象，对象的key是数组的元素，值是true
  var ignoreMethod = getIgnoredMethods(ignoreMethods)

  return function csrf (req, res, next) {
    // validate the configuration against request
    if (!verifyConfiguration(req, sessionKey, cookie)) {
      return next(new Error('misconfigured csrf'))
    }

    // get the secret from the request
    var secret = getSecret(req, sessionKey, cookie)

    // 这就是csrf token
    var token

    // lazy-load token getter
    req.csrfToken = function csrfToken () {
      var sec = !cookie
        ? getSecret(req, sessionKey, cookie)
        : secret

      // use cached token if secret has not changed
      if (token && sec === secret) {
        return token
      }

      // generate & set new secret
      if (sec === undefined) {
        sec = tokens.secretSync()
        setSecret(req, res, sessionKey, sec, cookie)
      }

      // update changed secret
      secret = sec

      // create new token
      // 这就是唯一实际创建csrf token的地方
      // See https://github.com/pillarjs/csrf?tab=readme-ov-file#tokenscreatesecret
      token = tokens.create(secret)

      // 说明挂在req上的csrfToken()函数是一个csrf token getter，只有在调用req.csrfToken()时才会实际生成csrf token
      return token
    }

    // generate & set secret
    if (!secret) {
      // 如果req中没有secret，那么生成一个secret并设置到cookie或者session中
      secret = tokens.secretSync()
      setSecret(req, res, sessionKey, secret, cookie)
    }

    // verify the incoming token
    // 如果请求方法不在ignoreMethods中，那么验证请求中的csrf token是否有效
    // See https://github.com/pillarjs/csrf?tab=readme-ov-file#tokensverifysecret-token
    if (!ignoreMethod[req.method] && !tokens.verify(secret, value(req))) {
      return next(createError(403, 'invalid csrf token', {
        code: 'EBADCSRFTOKEN'
      }))
    }

    next()
  }
}

/**
 * Default value function, checking the `req.body`
 * and `req.query` for the CSRF token.
 *
 * @param {IncomingMessage} req
 * @return {String}
 * @api private
 */

function defaultValue (req) {
  return (req.body && req.body._csrf) ||
    (req.query && req.query._csrf) ||
    (req.headers['csrf-token']) ||
    (req.headers['xsrf-token']) ||
    (req.headers['x-csrf-token']) ||
    (req.headers['x-xsrf-token'])
}

/**
 * Get options for cookie.
 *
 * @param {boolean|object} [options]
 * @returns {object}
 * @api private
 */

function getCookieOptions (options) {
  // 假定传给中间件csurf()函数的options参数，其cookie字段是boolean或者object类型
  if (options !== true && typeof options !== 'object') {
    return undefined
  }

  var opts = Object.create(null)

  // key和path在cookie字段中是必须的，所以这里给它们赋上默认值, key默认为'_csrf', path默认为'/'
  // 可能会被options.cookie里的key和path值所覆盖
  // defaults
  opts.key = '_csrf'

  // See https://github.com/jshttp/cookie?tab=readme-ov-file#path
  opts.path = '/'

  if (options && typeof options === 'object') {
    for (var prop in options) {
      var val = options[prop]

      // 过滤掉options.cookie里里值为undefined的key
      if (val !== undefined) {
        opts[prop] = val
      }
    }
  }

  return opts
}

/**
 * Get a lookup of ignored methods.
 *
 * @param {array} methods
 * @returns {object}
 * @api private
 */

function getIgnoredMethods (methods) {
  var obj = Object.create(null)

  for (var i = 0; i < methods.length; i++) {
    var method = methods[i].toUpperCase()
    obj[method] = true
  }

  return obj
}

/**
 * Get the token secret from the request.
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @param {Object} [cookie]
 * @api private
 */

function getSecret (req, sessionKey, cookie) {
  // get the bag & key
  var bag = getSecretBag(req, sessionKey, cookie)
  // 如果使用的cookie，那么secret的key就是cookie.key, 否则使用的就是session，key固定为'csrfSecret'(见setSecret()函数的实现)
  var key = cookie ? cookie.key : 'csrfSecret'

  if (!bag) {
    throw new Error('misconfigured csrf')
  }

  // return secret from bag
  return bag[key]
}

/**
 * Get the token secret bag from the request.
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @param {Object} [cookie]
 * @api private
 */

function getSecretBag (req, sessionKey, cookie) {
  // 这里预期是从cookie或者session中能取到并返回一个对象，这个对象的cookie.key字段下有secret值
  if (cookie) {
    // 这里的逻辑依赖于中间件cookie-parser(https://github.com/expressjs/cookie-parser)
    // cookie.signed表示cookie-parser中间件是否使用了secret进行cookie签名，签名与否会决定cookie data暴露在req.cookies还是req.signedCookies上

    // get secret from cookie
    var cookieKey = cookie.signed
      ? 'signedCookies'
      : 'cookies'

    return req[cookieKey]
  } else {
    // get secret from session
    // 这里的逻辑依赖于中间件express-session或者cookie-session
    // sessionKey默认为'session', 也就是说默认情况下，这里的逻辑依赖于express-session中间件(https://github.com/expressjs/session?tab=readme-ov-file#reqsession)
    return req[sessionKey]
  }
}

/**
 * Set a cookie on the HTTP response.
 *
 * @param {OutgoingMessage} res
 * @param {string} name
 * @param {string} val
 * @param {Object} [options]
 * @api private
 */

function setCookie (res, name, val, options) {
  // 说明传入给csurf()函数的options.cookie是提供给Cookie.serialize()函数的
  // See https://github.com/jshttp/cookie?tab=readme-ov-file#cookieserializename-value-options
  var data = Cookie.serialize(name, val, options)

  var prev = res.getHeader('set-cookie') || []
  var header = Array.isArray(prev) ? prev.concat(data)
    : [prev, data]

  res.setHeader('set-cookie', header)
}

/**
 * Set the token secret on the request.
 *
 * @param {IncomingMessage} req
 * @param {OutgoingMessage} res
 * @param {string} sessionKey
 * @param {string} val
 * @param {Object} [cookie]
 * @api private
 */

function setSecret (req, res, sessionKey, val, cookie) {
  if (cookie) {
    // set secret on cookie
    var value = val

    if (cookie.signed) {
      // req.secret是cookie-parser中间件设置的，用于给cookie签名
      value = 's:' + sign(val, req.secret)
    }

    setCookie(res, cookie.key, value, cookie)
  } else {
    // set secret on session
    req[sessionKey].csrfSecret = val
  }
}

/**
 * Verify the configuration against the request.
 * @private
 */

function verifyConfiguration (req, sessionKey, cookie) {
  // 确保cookie或者sessionKey有secret所驻留的对象
  if (!getSecretBag(req, sessionKey, cookie)) {
    return false
  }

  // 确保cookie是签名时，req.secret有值. See https://github.com/expressjs/cookie-parser
  if (cookie && cookie.signed && !req.secret) {
    return false
  }

  return true
}
