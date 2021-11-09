const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require('../users/users-model')
const jwt = require('jsonwebtoken')

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (!token) {
    next({status: 401, message: 'Token required' })
  }
  jwt.verify(token, JWT_SECRET, (err,decodedToken) => {
    if (err) {
      next({ status: 401, message: 'Token invalid'})
    } else {
      req.decodedToken = decodedToken
      next()
    }
  })
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
  if (role_name === req.decodedToken.role_name) {
    next()
  } else {
    next({ status: 403, message: "This is not for you" })
  }
}


const checkUsernameExists = async (req, res, next) => {
  try {
    const [user] = await User.findBy({ username: req.body.username })
    if (user) {
      req.user = user
      next()
    } else {
      next({ status: 401, message: 'Invalid credentials' })
    }
  } catch (err) {
    next(err)
  }
  
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
}


const validateRoleName = (req, res, next) => {
  if (!req.body.role_name || !req.body.role_name.trim()) {
    req.role_name = 'student'
    next()
  } else if (req.body.role_name.trim() === 'admin'){
      next({status: 422, message: 'Role name can not be admin'})
  } else if (req.body.role_name.trim().length > 32) {
    next({ status: 422, message: 'Role name can not be longer than 32 chars' })
  } else {
    req.role_name = req.body.role_name.trim()
    next()
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
