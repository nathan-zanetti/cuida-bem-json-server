const jsonServer = require('json-server')
const jwt = require('jsonwebtoken')
const fs = require('fs')
const path = require('path')

const server = jsonServer.create()
const router = jsonServer.router(path.join(__dirname, '..', 'db.json'))
const middlewares = jsonServer.defaults()

// Configure secret via ENV in Vercel: JWT_SECRET
const SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_SECRET'
const expiresIn = '1h'

server.use(middlewares)
server.use(jsonServer.bodyParser)

// Helper para carregar DB
function readDb() {
  const dbPath = path.join(__dirname, '..', 'db.json')
  return JSON.parse(fs.readFileSync(dbPath, 'utf-8'))
}
function writeDb(data) {
  const dbPath = path.join(__dirname, '..', 'db.json')
  fs.writeFileSync(dbPath, JSON.stringify(data, null, 2))
}

// Rota de login
server.post('/api/login', (req, res) => {
  const { email, password } = req.body
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' })

  const db = readDb()
  const users = db.users || []
  const user = users.find(u => u.email === email && u.password === password)
  if (!user) return res.status(401).json({ error: 'Invalid credentials' })

  const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn })
  res.json({ accessToken: token, user: { id: user.id, email: user.email, name: user.name } })
})

// Rota de register (cria usuário)
server.post('/api/register', (req, res) => {
  const { email, password, name } = req.body
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' })

  const db = readDb()
  db.users = db.users || []
  if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'User already exists' })

  const id = Date.now()
  const newUser = { id, email, password, name: name || '' }
  db.users.push(newUser)
  writeDb(db)

  const token = jwt.sign({ id, email }, SECRET, { expiresIn })
  res.status(201).json({ accessToken: token, user: { id, email, name } })
})

// Middleware para verificar token
function verifyTokenFromHeader(req, res, next) {
  const authHeader = req.headers.authorization
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'No token provided' })
  const token = authHeader.split(' ')[1]
  try {
    const decoded = jwt.verify(token, SECRET)
    req.user = decoded
    return next()
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

// Proteger operações que modificam dados (POST/PUT/PATCH/DELETE sob /api)
// GET continua público (ajuste conforme necessidade)
server.use((req, res, next) => {
  if (req.path.startsWith('/api') && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    return verifyTokenFromHeader(req, res, next)
  }
  next()
})

// Monta router em /api
server.use('/api', router)

// Exports — Vercel aceita uma função de request handler
module.exports = server