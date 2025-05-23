require('dotenv').config();
const express = require('express');
const sql = require('mssql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');

const app = express();
app.use(express.json());
app.use(cors());

const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_DATABASE,
    port: parseInt(process.env.DB_PORT, 10),
    options: {
        encrypt: false,
        trustServerCertificate: true
    }
};

const JWT_SECRET = process.env.JWT_SECRET || 'secreto_super_seguro';

// Probar conexión
sql.connect(dbConfig).then(pool => {
    if (pool.connected) {
        console.log('Conexión exitosa a SQL Server');
    }
}).catch(err => {
    console.error('Error de conexión a SQL Server:', err);
});

app.get('/', (req, res) => {
    res.send('API funcionando');
});

// Middleware para proteger rutas con JWT
function autenticarJWT(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
}

// Endpoint de login
app.post('/login', async (req, res) => {
    const { Correo, Contraseña } = req.body;
    if (!Correo || !Contraseña) {
        return res.status(400).json({ error: 'Correo y contraseña requeridos' });
    }
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('Correo', sql.NVarChar, Correo)
            .query('SELECT IdUsuario, Nombre, Correo, ContrasenaHash FROM UsuariosVidal WHERE Correo = @Correo');
        if (result.recordset.length === 0) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }
        const usuario = result.recordset[0];
        const esValida = await bcrypt.compare(Contraseña, usuario.ContrasenaHash);
        if (!esValida) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }
        // Generar token
        const token = jwt.sign({ IdUsuario: usuario.IdUsuario, Correo: usuario.Correo }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Obtener todos los usuarios (protegido)
app.get('/usuarios', autenticarJWT, async (req, res) => {
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request().query('SELECT IdUsuario, Nombre, Correo FROM UsuariosVidal');
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Obtener un usuario por ID (protegido)
app.get('/usuarios/:id', autenticarJWT, async (req, res) => {
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('IdUsuario', sql.Int, req.params.id)
            .query('SELECT IdUsuario, Nombre, Correo FROM UsuariosVidal WHERE IdUsuario = @IdUsuario');
        if (result.recordset.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        res.json(result.recordset[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Crear un nuevo usuario (hash automático)
app.post('/usuarios', async (req, res) => {
    const { Nombre, Correo, Contraseña } = req.body;
    if (!Nombre || !Correo || !Contraseña) {
        return res.status(400).json({ error: 'Faltan campos requeridos' });
    }
    try {
        const hash = await bcrypt.hash(Contraseña, 10);
        const pool = await sql.connect(dbConfig);
        await pool.request()
            .input('Nombre', sql.NVarChar, Nombre)
            .input('Correo', sql.NVarChar, Correo)
            .input('ContrasenaHash', sql.NVarChar, hash)
            .query('INSERT INTO UsuariosVidal (Nombre, Correo, ContrasenaHash) VALUES (@Nombre, @Correo, @ContrasenaHash)');
        res.status(201).json({ mensaje: 'Usuario creado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Actualizar un usuario (hash automático si se manda contraseña)
app.put('/usuarios/:id', autenticarJWT, async (req, res) => {
    const { Nombre, Correo, Contraseña } = req.body;
    try {
        let hash = undefined;
        if (Contraseña) {
            hash = await bcrypt.hash(Contraseña, 10);
        }
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('IdUsuario', sql.Int, req.params.id)
            .input('Nombre', sql.NVarChar, Nombre)
            .input('Correo', sql.NVarChar, Correo)
            .input('ContrasenaHash', sql.NVarChar, hash)
            .query(`UPDATE UsuariosVidal SET Nombre = @Nombre, Correo = @Correo${hash ? ', ContrasenaHash = @ContrasenaHash' : ''} WHERE IdUsuario = @IdUsuario`);
        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        res.json({ mensaje: 'Usuario actualizado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Eliminar un usuario (protegido)
app.delete('/usuarios/:id', autenticarJWT, async (req, res) => {
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('IdUsuario', sql.Int, req.params.id)
            .query('DELETE FROM UsuariosVidal WHERE IdUsuario = @IdUsuario');
        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        res.json({ mensaje: 'Usuario eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'API UsuariosVidal',
    version: '1.0.0',
    description: 'Documentación básica de la API de gestión de usuarios (M3: Práctica Final) - Mauricio Perea',
  },
  servers: [
    { url: 'http://localhost:3000', description: 'Servidor local' }
  ],
};

const swaggerOptions = {
  swaggerDefinition,
  apis: [__filename],
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Iniciar sesión y obtener un token JWT
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - Correo
 *               - Contraseña
 *             properties:
 *               Correo:
 *                 type: string
 *                 example: juan@correo.com
 *               Contraseña:
 *                 type: string
 *                 example: 123456
 *     responses:
 *       200:
 *         description: Token JWT generado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       401:
 *         description: Credenciales inválidas
 */

/**
 * @swagger
 * /usuarios:
 *   get:
 *     summary: Obtener todos los usuarios
 *     tags: [Usuarios]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de usuarios
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/UsuarioSimple'
 *       401:
 *         description: Token requerido
 *   post:
 *     summary: Crear un nuevo usuario
 *     tags: [Usuarios]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - Nombre
 *               - Correo
 *               - Contraseña
 *             properties:
 *               Nombre:
 *                 type: string
 *                 example: Juan
 *               Correo:
 *                 type: string
 *                 example: juan@correo.com
 *               Contraseña:
 *                 type: string
 *                 example: 123456
 *     responses:
 *       201:
 *         description: Usuario creado
 *       400:
 *         description: Faltan campos requeridos
 */

/**
 * @swagger
 * /usuarios/{id}:
 *   get:
 *     summary: Obtener un usuario por ID
 *     tags: [Usuarios]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: integer
 *         required: true
 *         description: ID del usuario
 *     responses:
 *       200:
 *         description: Usuario encontrado
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UsuarioSimple'
 *       404:
 *         description: Usuario no encontrado
 *   put:
 *     summary: Actualizar un usuario
 *     tags: [Usuarios]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: integer
 *         required: true
 *         description: ID del usuario
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               Nombre:
 *                 type: string
 *                 example: Juan Actualizado
 *               Correo:
 *                 type: string
 *                 example: juan@correo.com
 *               Contraseña:
 *                 type: string
 *                 example: nueva123
 *     responses:
 *       200:
 *         description: Usuario actualizado
 *       404:
 *         description: Usuario no encontrado
 *   delete:
 *     summary: Eliminar un usuario
 *     tags: [Usuarios]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: integer
 *         required: true
 *         description: ID del usuario
 *     responses:
 *       200:
 *         description: Usuario eliminado
 *       404:
 *         description: Usuario no encontrado
 */

/**
 * @swagger
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 *   schemas:
 *     UsuarioSimple:
 *       type: object
 *       properties:
 *         IdUsuario:
 *           type: integer
 *           example: 1
 *         Nombre:
 *           type: string
 *           example: Juan
 *         Correo:
 *           type: string
 *           example: juan@correo.com
 */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
}); 