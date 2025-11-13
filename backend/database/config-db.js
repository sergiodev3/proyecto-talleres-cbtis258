import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

/**
 * Configuración del pool de conexiones PostgreSQL
 * 
 * Fundamentos de esta configuración:
 * - Pool de conexiones: Reutiliza conexiones DB para mejor performance
 * - Timeouts configurables: Evita conexiones colgadas
 * - SSL automático en producción: Seguridad en deployment
 * - Manejo de errores robusto: Reconexión automática y logging
 */

const poolConfig = {
    // URL de conexión desde variables de entorno
    connectionString: process.env.DATABASE_URL,
    
    // Configuración del pool
    max: 20, // Máximo 20 conexiones concurrentes
    min: 2,  // Mínimo 2 conexiones mantenidas
    idleTimeoutMillis: 30000, // Tiempo antes de cerrar conexión inactiva (30s)
    connectionTimeoutMillis: 2000, // Timeout para obtener conexión (2s)
    acquireTimeoutMillis: 60000, // Timeout máximo para obtener conexión (60s)
    
    // SSL automático en producción
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    
    // Configuración adicional
    allowExitOnIdle: false, // No permitir que el proceso termine si hay conexiones idle
    
    // Configuración de queries
    statement_timeout: 30000, // 30 segundos máximo por query
    query_timeout: 30000,     // 30 segundos máximo por query
    
    // Configuración de aplicación
    application_name: 'talleres_cbtis258_api'
};

// Crear el pool de conexiones
const pool = new Pool(poolConfig);

/**
 * Manejo de eventos del pool para monitoring y debugging
 */

// Evento cuando se conecta un nuevo cliente
pool.on('connect', (client) => {
    if (process.env.NODE_ENV === 'development') {
        console.log('🔗 Nueva conexión establecida con la base de datos');
    }
});

// Evento cuando se libera un cliente
pool.on('release', (err, client) => {
    if (err) {
        console.error('❌ Error al liberar cliente de base de datos:', err.message);
    }
});

// Evento de error en el pool
pool.on('error', (err, client) => {
    console.error('❌ Error inesperado en el pool de base de datos:', err.message);
    // En producción, aquí implementarías notificaciones de alertas
});

// Evento cuando se remueve un cliente
pool.on('remove', (client) => {
    if (process.env.NODE_ENV === 'development') {
        console.log('🗑️ Cliente removido del pool de base de datos');
    }
});

/**
 * Función para probar la conexión a la base de datos
 * @returns {Promise<boolean>} True si la conexión es exitosa
 */
export const testConnection = async () => {
    let client;
    try {
        console.log('🔄 Probando conexión a la base de datos...');
        
        client = await pool.connect();
        
        // Ejecutar query simple para verificar conexión
        const result = await client.query('SELECT NOW() as current_time, version() as db_version');
        
        console.log('✅ Conexión a base de datos exitosa');
        console.log(`📅 Fecha servidor DB: ${result.rows[0].current_time}`);
        console.log(`🗄️ Versión PostgreSQL: ${result.rows[0].db_version.split(',')[0]}`);
        
        return true;
        
    } catch (error) {
        console.error('❌ Error al conectar con la base de datos:');
        console.error(`   Mensaje: ${error.message}`);
        console.error(`   Código: ${error.code}`);
        
        if (error.code === 'ECONNREFUSED') {
            console.error('   💡 Sugerencia: Verifica que PostgreSQL esté corriendo');
        } else if (error.code === '3D000') {
            console.error('   💡 Sugerencia: Verifica que la base de datos existe');
        } else if (error.code === '28P01') {
            console.error('   💡 Sugerencia: Verifica las credenciales de la base de datos');
        }
        
        return false;
        
    } finally {
        if (client) {
            client.release();
        }
    }
};

/**
 * Función para ejecutar queries con manejo de errores mejorado
 * @param {string} text - Query SQL
 * @param {Array} params - Parámetros del query
 * @returns {Promise<Object>} Resultado del query
 */
export const query = async (text, params = []) => {
    const start = Date.now();
    let client;
    
    try {
        client = await pool.connect();
        
        if (process.env.NODE_ENV === 'development') {
            console.log('🔍 Ejecutando query:', text.replace(/\s+/g, ' ').trim().substring(0, 100) + '...');
        }
        
        const result = await client.query(text, params);
        
        const duration = Date.now() - start;
        if (process.env.NODE_ENV === 'development') {
            console.log(`⚡ Query ejecutado en ${duration}ms, ${result.rowCount} filas afectadas`);
        }
        
        // Log queries lentos (más de 1 segundo)
        if (duration > 1000) {
            console.warn(`⚠️ Query lento detectado (${duration}ms):`, text.substring(0, 200));
        }
        
        return result;
        
    } catch (error) {
        const duration = Date.now() - start;
        console.error(`❌ Error en query (${duration}ms):`, error.message);
        console.error('📝 Query:', text);
        console.error('📥 Parámetros:', params);
        
        // Re-throw el error para que lo maneje el controlador
        throw error;
        
    } finally {
        if (client) {
            client.release();
        }
    }
};

/**
 * Función para ejecutar transacciones
 * @param {Function} callback - Función que recibe el cliente y ejecuta queries
 * @returns {Promise<any>} Resultado de la transacción
 */
export const transaction = async (callback) => {
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');
        
        if (process.env.NODE_ENV === 'development') {
            console.log('🔄 Iniciando transacción...');
        }
        
        const result = await callback(client);
        
        await client.query('COMMIT');
        
        if (process.env.NODE_ENV === 'development') {
            console.log('✅ Transacción completada exitosamente');
        }
        
        return result;
        
    } catch (error) {
        await client.query('ROLLBACK');
        
        console.error('❌ Error en transacción, haciendo rollback:', error.message);
        throw error;
        
    } finally {
        client.release();
    }
};

/**
 * Función para obtener estadísticas del pool
 * @returns {Object} Estadísticas actuales del pool
 */
export const getPoolStats = () => {
    return {
        totalCount: pool.totalCount,     // Total de clientes en el pool
        idleCount: pool.idleCount,       // Clientes inactivos
        waitingCount: pool.waitingCount, // Requests esperando conexión
        maxConnections: poolConfig.max,   // Máximo configurado
        activeConnections: pool.totalCount - pool.idleCount // Conexiones activas
    };
};

/**
 * Función para cerrar todas las conexiones del pool
 * Útil para testing y cierre graceful de la aplicación
 */
export const closePool = async () => {
    try {
        console.log('🔄 Cerrando pool de conexiones...');
        await pool.end();
        console.log('✅ Pool de conexiones cerrado correctamente');
    } catch (error) {
        console.error('❌ Error al cerrar pool de conexiones:', error.message);
        throw error;
    }
};

// Exportar el pool para uso directo si es necesario
export default pool;

// Manejar cierre graceful del proceso
process.on('SIGTERM', closePool);
process.on('SIGINT', closePool);
