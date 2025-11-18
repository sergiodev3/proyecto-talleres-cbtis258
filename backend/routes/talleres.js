import express from 'express';
import TallerController from '../controllers/tallerController.js';
import { 
    authenticateToken, 
    authorize, 
    authorizeInstructorTaller,
    authorizeAlumnoAccess
} from '../middlewares/auth.js';
import { 
    validateUUIDParam,
    validateSearchQuery,
    sanitizeRequest
} from '../middlewares/validation.js';

const router = express.Router();

/**
 * Rutas de talleres
 * 
 * Fundamentos:
 * - Endpoints públicos para consultar talleres
 * - Endpoints protegidos según tipo de usuario
 * - Validación de parámetros UUID
 * - Control de acceso granular por taller
 */

// @route   GET /api/talleres
// @desc    Obtener todos los talleres (público para ver talleres disponibles)
// @access  Public
router.get('/', validateSearchQuery, TallerController.getTalleres);

// @route   GET /api/talleres/categoria/:categoria
// @desc    Obtener talleres por categoría
// @access  Public
router.get('/categoria/:categoria', TallerController.getTalleresByCategoria);

// @route   GET /api/talleres/disponibles
// @desc    Obtener talleres disponibles para inscripción (alumno)
// @access  Private - Alumno
router.get('/disponibles', 
    authenticateToken, 
    authorizeAlumnoAccess, 
    TallerController.getTalleresDisponibles
);

// @route   GET /api/talleres/mis-inscripciones
// @desc    Obtener inscripciones del alumno autenticado
// @access  Private - Alumno
router.get('/mis-inscripciones', 
    authenticateToken, 
    authorizeAlumnoAccess,
    TallerController.getMisInscripciones
);

// @route   GET /api/talleres/mis-talleres
// @desc    Obtener talleres del instructor autenticado
// @access  Private - Instructor
router.get('/mis-talleres', 
    authenticateToken, 
    authorize('instructor'), 
    TallerController.getMisTalleres
);

// @route   GET /api/talleres/estadisticas
// @desc    Obtener estadísticas de talleres
// @access  Private - Admin/Instructor
router.get('/estadisticas', 
    authenticateToken, 
    authorize('admin', 'instructor'), 
    TallerController.getEstadisticas
);

// @route   GET /api/talleres/:id
// @desc    Obtener taller por ID
// @access  Public
router.get('/:id', 
    validateUUIDParam('id'), 
    TallerController.getTallerById
);

// @route   POST /api/talleres
// @desc    Crear nuevo taller
// @access  Private - Admin
router.post('/', 
    authenticateToken, 
    authorize('admin'), 
    sanitizeRequest,
    TallerController.createTaller
);

// @route   PUT /api/talleres/:id
// @desc    Actualizar taller
// @access  Private - Admin o Instructor asignado
router.put('/:id', 
    validateUUIDParam('id'),
    authenticateToken, 
    authorize('admin', 'instructor'), 
    sanitizeRequest,
    TallerController.updateTaller
);

// @route   DELETE /api/talleres/:id
// @desc    Eliminar taller
// @access  Private - Admin
router.delete('/:id', 
    validateUUIDParam('id'),
    authenticateToken, 
    authorize('admin'), 
    TallerController.deleteTaller
);

// @route   GET /api/talleres/:id/alumnos
// @desc    Obtener alumnos inscritos en un taller
// @access  Private - Admin, Instructor del taller
router.get('/:id/alumnos', 
    validateUUIDParam('id'),
    authenticateToken, 
    authorize('admin', 'instructor'),
    validateSearchQuery,
    TallerController.getAlumnosInscritos
);

// @route   POST /api/talleres/:id/inscripcion
// @desc    Inscribirse a un taller
// @access  Private - Alumno
router.post('/:id/inscripcion', 
    validateUUIDParam('id'),
    authenticateToken, 
    authorizeAlumnoAccess,
    sanitizeRequest,
    TallerController.inscribirseATaller
);

// @route   GET /api/talleres/:id/cupo
// @desc    Verificar cupo disponible de un taller
// @access  Public
router.get('/:id/cupo', 
    validateUUIDParam('id'),
    TallerController.verificarCupo
);

export default router;