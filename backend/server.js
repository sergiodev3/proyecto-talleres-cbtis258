import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { testConnection } from './database/config-db.js';



// Configuración de variables de entorno
// Solo cargar variables de .env si NO estamos en producción
if (process.env.NODE_ENV !== 'production') {
    dotenv.config();
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Crear aplicación Express
const app = express();

// CONFÍA EN EL PROXY DE RAILWAY (Y OTROS PROXIES)
// Esta línea es crucial para que express-rate-limit funcione en producción.
app.set('trust proxy', 1);



// Configuración de seguridad con Helmet
app.use(helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            scriptSrc: ["'self'"],
            connectSrc: ["'self'"],
        },
    },
}));


// --- INICIO DE CONFIGURACIÓN DE CORS DEFINITIVA ---

// Lista de orígenes permitidos
const allowedOrigins = [
    // URL de producción del Frontend (desde variable de entorno)
    process.env.FRONTEND_URL,

    // URLs de desarrollo local
    'http://127.0.0.1:5500',
    'http://localhost:5500',
    'http://127.0.0.1:5501',
    'http://localhost:5501'
];

const corsOptions = {
    origin: function (origin, callback) {
        // Permitir solicitudes sin 'origin' (como Postman o apps móviles)
        if (!origin) {
            return callback(null, true);
        }

        // Si el origen de la petición está en nuestra lista, permitirlo
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            // Si no está en la lista, rechazarlo
            callback(new Error('El acceso desde este origen no está permitido por la política de CORS.'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-requested-with'],
    exposedHeaders: ['Content-Range', 'X-Content-Range']
};

app.use(cors(corsOptions));

// Rate limiting - Protección contra ataques de fuerza bruta
// Configuración más permisiva para fase de pruebas beta
const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutos
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 1000, // 1000 requests por ventana (muy permisivo para beta)
    message: {
        error: 'Demasiadas solicitudes desde esta IP. Intenta de nuevo más tarde.',
        retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000) / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for health check
        return req.path === '/api/health';
    }
});

// Rate limiting para autenticación
// Configuración permisiva para beta testing - ajustar después del testing
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: parseInt(process.env.AUTH_RATE_LIMIT) || 50, // 50 intentos por defecto (permisivo para beta)
    message: {
        error: 'Demasiados intentos de autenticación. Intenta de nuevo en 15 minutos.',
        retryAfter: 900
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true, // No contar requests exitosos
    skip: (req) => {
        // Permitir bypass con variable de entorno para testing
        return process.env.DISABLE_RATE_LIMIT === 'true';
    }
});

app.use('/api/', limiter);
app.use('/api/auth/', authLimiter);

// Middleware para parsing de JSON con límite de tamaño
app.use(express.json({ 
    limit: '10mb',
    verify: (req, res, buf) => {
        try {
            JSON.parse(buf);
        } catch (e) {
            res.status(400).json({ error: 'JSON inválido' });
            throw new Error('JSON inválido');
        }
    }
}));

app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Middleware para logging de requests en desarrollo
if (process.env.NODE_ENV === 'development') {
    app.use((req, res, next) => {
        console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - IP: ${req.ip}`);
        next();
    });
}

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        service: 'Talleres CBTIS 258 API',
        version: process.env.npm_package_version || '1.0.0',
        environment: process.env.NODE_ENV || 'development'
    });
});

// Importar y usar rutas
import authRoutes from './routes/auth.js';
import tallerRoutes from './routes/talleres.js';
import avisosRoutes from './routes/avisos.js';
import calendarioRoutes from './routes/calendario.js';
import adminRoutes from './routes/admin.js';
import informacionEmergenciaRoutes from './routes/informacionEmergencia.js';

app.use('/api/auth', authRoutes);
app.use('/api/talleres', tallerRoutes);
app.use('/api/avisos', avisosRoutes);
app.use('/api/calendario', calendarioRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/informacion-emergencia', informacionEmergenciaRoutes);

// Middleware de manejo de errores global
app.use((err, req, res, next) => {
    console.error('Error stack:', err.stack);
    
    // Error de validación
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            error: 'Error de validación',
            details: err.details || err.message
        });
    }
    
    // Error de JWT
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            error: 'Token inválido',
            message: 'Por favor, inicia sesión nuevamente'
        });
    }
    
    // Error de JWT expirado
    if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
            error: 'Token expirado',
            message: 'Tu sesión ha expirado. Por favor, inicia sesión nuevamente'
        });
    }
    
    // Error de base de datos
    if (err.code === '23505') { // Unique violation
        return res.status(409).json({
            error: 'Conflicto de datos',
            message: 'Ya existe un registro con estos datos'
        });
    }
    
    if (err.code === '23503') { // Foreign key violation
        return res.status(400).json({
            error: 'Error de referencia',
            message: 'No se puede completar la operación debido a referencias existentes'
        });
    }
    
    // Error por defecto
    const statusCode = err.statusCode || err.status || 500;
    const message = process.env.NODE_ENV === 'production' 
        ? 'Error interno del servidor' 
        : err.message || 'Error interno del servidor';
    
    res.status(statusCode).json({
        error: 'Error del servidor',
        message,
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// Middleware para rutas no encontradas (usar sin path para evitar errores con path-to-regexp)
// Se registra sin especificar path para que Express lo aplique a cualquier ruta no manejada.
app.use((req, res) => {
    res.status(404).json({
        error: 'Ruta no encontrada',
        message: `La ruta ${req.originalUrl} no existe en este servidor`,
        availableRoutes: [
            'GET /api/health',
            'POST /api/auth/login',
            'POST /api/auth/register',
            'GET /api/talleres',
            'GET /api/talleres/categoria/:categoria',
            'GET /api/avisos/importantes',
            'GET /api/calendario/eventos-hoy'
        ]
    });
});

// Manejo de cierre graceful
process.on('SIGTERM', () => {
    console.log('🔴 SIGTERM recibido. Cerrando servidor...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('\n🔴 SIGINT recibido. Cerrando servidor...');
    process.exit(0);
});

// Iniciar servidor
const PORT = process.env.PORT || 5000;

// Función para inicializar el servidor
const startServer = async () => {
    try {
        // Verificar conexión a la base de datos
        const dbConnected = await testConnection();
        
        if (!dbConnected) {
            console.error('❌ No se pudo conectar a la base de datos. Deteniendo servidor...');
            process.exit(1);
        }

        // Iniciar el servidor HTTP
        app.listen(PORT, () => {
            console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
            console.log(`🌍 Entorno: ${process.env.NODE_ENV || 'development'}`);
            console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
            console.log(`🔒 CORS configurado para desarrollo (permitiendo Live Server)`);
            console.log(`✅ Sistema listo para recibir requests`);
        });

    } catch (error) {
        console.error('❌ Error al inicializar servidor:', error);
        process.exit(1);
    }
};

// Inicializar servidor
startServer();

export default app;
