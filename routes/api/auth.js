const express = require('express')
const router = express.Router()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const config = require('config')
const { check, validationResult } = require('express-validator')

const auth = require('../../middleware/auth')
const User = require('../../models/User')

// @route   GET api/auth
// @desc    Check user registration
// @access  Private
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password')
        res.json(user)
    } catch(err) {
        console.error(err.message)
        res.status(500).send('Server Error')
    }
    res.send('Auth Route')
})

// @route   GET api/auth
// @desc    Authenticate user and get token
// @access  Public
router.post('/', [
    check('email', 'Please include a valid email').isEmail(),
    check(
        'password',
        'Password is required.'
    ).exists() 
    ], 
    async (req, res) => {
        const errors = validationResult(req)
        if(!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array() })
        }

        const { email, password } = req.body

        try {
            let user = await User.findOne({ email })

            if (!user) {
                res.status(400).json({ errors: [{ msg: 'Invalid credentials' }]})
            }

            const isMatch = await bcrypt.compare(password, user.password)
            
            if(!isMatch) {
                res.status(400).json({ errors: [{ msg: 'Invalid credentials' }]})
            }
            
            const payload = {
                user: {
                    id: user.id
                }
            }

            jwt.sign(
                payload, 
                config.get('jwtToken'),
                { expiresIn: 3600 }, 
                (err, token) => {
                    if (err) throw err 
                    res.json({ token })
                }
            )
        } catch(err) {
            console.error(err.message)
            res.status(500).send('SERVER ERROR')
        }
    }
)


module.exports = router