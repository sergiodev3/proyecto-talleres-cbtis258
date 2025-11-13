# 🏫 Sistema de Gestión de Talleres - CBTis 258

Sistema web integral para la gestión de talleres extracurriculares del Centro de Bachillerato Tecnológico industrial y de servicios No. 258 "Mariano Escobedo". Permite a los alumnos inscribirse a talleres culturales, deportivos y cívicos, mientras que los instructores pueden administrar sus talleres, eventos y alumnos inscritos.

## 📋 Tabla de Contenidos

- [Características](#-características)
- [Tecnologías](#-tecnologías)
- [Requisitos Previos](#-requisitos-previos)
- [Instalación](#-instalación)
- [Configuración](#-configuración)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [API Endpoints](#-api-endpoints)
- [Uso](#-uso)
- [Capturas de Pantalla](#-capturas-de-pantalla)
- [Contribución](#-contribución)
- [Licencia](#-licencia)

## ✨ Características

### Para Alumnos
- 📝 Registro e inicio de sesión seguro
- 🔍 Búsqueda y exploración de talleres por categoría (Culturales, Deportes, Cívicos)
- ✅ Inscripción a talleres disponibles
- 📅 Visualización de calendario de eventos
- 📢 Recepción de avisos importantes
- 👤 Gestión de perfil personal

### Para Instructores
- 📊 Dashboard personalizado con estadísticas
- 📅 Calendario interactivo para gestión de eventos
- 👥 Visualización de alumnos inscritos
- 📢 Publicación de avisos para sus talleres
- 📝 Gestión completa de perfil (incluyendo contactos de emergencia)
- 🎯 Gestión de fechas importantes por taller

### Para Administradores
- 👤 Gestión completa de usuarios (alumnos, instructores, admins)
- 🎨 CRUD completo de talleres
- 📊 Dashboard con estadísticas en tiempo real
- 👨‍🏫 Asignación de instructores a talleres
- 🔐 Control de acceso y permisos
- 📈 Reportes de inscripciones

## 🛠 Tecnologías

### Backend
- **Node.js** (v18+) - Entorno de ejecución
- **Express.js** - Framework web
- **PostgreSQL** (v14+) - Base de datos
- **JWT** - Autenticación y autorización
- **bcryptjs** - Hash de contraseñas
- **dotenv** - Variables de entorno
- **cors** - Manejo de CORS
- **helmet** - Seguridad HTTP
- **express-rate-limit** - Rate limiting

### Frontend
- **HTML5 / CSS3** - Estructura y estilos
- **JavaScript (ES6+)** - Lógica del cliente
- **Bootstrap 3** - Framework CSS
- **Light Bootstrap Dashboard** - Template de dashboard
- **Axios** - Cliente HTTP
- **FullCalendar 5** - Calendario interactivo
- **Font Awesome** - Iconos

## 📦 Requisitos Previos

Antes de comenzar, asegúrate de tener instalado:

- [Node.js](https://nodejs.org/) (v18 o superior)
- [PostgreSQL](https://www.postgresql.org/) (v14 o superior)
- [Git](https://git-scm.com/)
- Editor de código (recomendado: [VS Code](https://code.visualstudio.com/))

## 🚀 Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/sergiodev3/proyecto-talleres-cbtis258.git
cd proyecto-talleres-cbtis258
```

### 2. Configurar la Base de Datos

```bash
# Conectarse a PostgreSQL
psql -U postgres

# Crear la base de datos
CREATE DATABASE talleres_cbtis258;

# Salir de psql
\q

# Ejecutar el script de esquema
psql -U postgres -d talleres_cbtis258 -f backend/database/schema.sql

# Ejecutar script de actualización de instructor (si es necesario)
psql -U postgres -d talleres_cbtis258 -f backend/database/add-instructor-fields.sql
```

### 3. Configurar el Backend

```bash
cd backend

# Instalar dependencias
npm install

# Crear archivo .env
cp .env.example .env

# Editar .env con tus configuraciones
nano .env
```

### 4. Configurar el Frontend

```bash
cd ../frontend

# Verificar que API_BASE_URL apunte al backend correcto
# Editar en cada archivo HTML si es necesario
# Por defecto: http://localhost:5000/api
```

### 5. Iniciar la Aplicación

**Backend:**
```bash
cd backend
npm run dev
```

**Frontend:**
- Usar Live Server de VS Code o cualquier servidor HTTP
- Abrir `index.html` en el navegador

## ⚙️ Configuración

### Variables de Entorno (.env)

Crea un archivo `.env` en la carpeta `backend` con el siguiente contenido:

```env
# Server
PORT=5000
NODE_ENV=development

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=talleres_cbtis258
DB_USER=postgres
DB_PASSWORD=tu_password

# JWT
JWT_SECRET=tu_secret_key_muy_segura_y_larga_aqui
JWT_EXPIRES_IN=7d

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

### Configuración de la Base de Datos

El esquema incluye las siguientes tablas principales:
- `usuarios` - Información de autenticación
- `perfiles_alumno` - Datos de alumnos
- `perfiles_instructor` - Datos de instructores
- `talleres` - Información de talleres
- `inscripciones` - Relación alumno-taller
- `fechas_importantes` - Eventos del calendario
- `avisos` - Notificaciones importantes

## 📁 Estructura del Proyecto

```
proyecto-talleres-cbtis258/
├── backend/
│   ├── controllers/          # Lógica de negocio
│   │   ├── authController.js
│   │   ├── calendarioController.js
│   │   └── ...
│   ├── database/            # Scripts de BD
│   │   ├── config-db.js
│   │   ├── schema.sql
│   │   └── add-instructor-fields.sql
│   ├── middlewares/         # Middleware de Express
│   │   ├── auth.js
│   │   └── validation.js
│   ├── models/             # Modelos de datos
│   │   ├── User.js
│   │   ├── Calendario.js
│   │   └── ...
│   ├── routes/             # Rutas de API
│   │   ├── admin.js
│   │   ├── auth.js
│   │   ├── calendario.js
│   │   └── talleres.js
│   ├── .env.example        # Ejemplo de variables de entorno
│   ├── .gitignore
│   ├── package.json
│   └── server.js           # Punto de entrada
│
├── frontend/
│   ├── assets/             # Recursos estáticos
│   │   ├── css/
│   │   ├── js/
│   │   ├── img/
│   │   └── fonts/
│   ├── css/                # Estilos personalizados
│   ├── images/             # Imágenes
│   ├── js/                 # Scripts personalizados
│   ├── index.html          # Página principal
│   ├── login.html          # Inicio de sesión
│   ├── register.html       # Registro de alumno
│   ├── dashboard-user.html # Dashboard de alumno
│   ├── dashboard-instructor.html # Dashboard de instructor
│   ├── dashboard-admin-system.html # Dashboard de admin
│   └── ...
│
├── .gitignore
└── README.md
```

## 🔌 API Endpoints

### Autenticación
```
POST   /api/auth/login              - Iniciar sesión
POST   /api/auth/register           - Registrar alumno
GET    /api/auth/verify             - Verificar token
GET    /api/auth/profile            - Obtener perfil
PUT    /api/auth/profile            - Actualizar perfil
PUT    /api/auth/change-password    - Cambiar contraseña
```

### Talleres
```
GET    /api/talleres                - Listar talleres (público)
GET    /api/talleres/categoria/:cat - Talleres por categoría
GET    /api/talleres/mis-talleres   - Talleres del instructor
GET    /api/talleres/:id            - Detalle de taller
```

### Calendario
```
GET    /api/calendario/rango        - Eventos en rango de fechas
GET    /api/calendario/mis-fechas   - Fechas del instructor
POST   /api/calendario              - Crear evento
PUT    /api/calendario/:id          - Actualizar evento
DELETE /api/calendario/:id          - Eliminar evento
```

### Administración (requiere rol admin)
```
GET    /api/admin/dashboard         - Estadísticas generales
GET    /api/admin/usuarios          - Listar usuarios
POST   /api/admin/usuarios/instructor - Crear instructor
PUT    /api/admin/usuarios/:id/status - Cambiar estado usuario
GET    /api/admin/talleres          - Gestión de talleres
POST   /api/admin/talleres          - Crear taller
PUT    /api/admin/talleres/:id      - Actualizar taller
DELETE /api/admin/talleres/:id      - Eliminar taller
```

## 📖 Uso

### Primer Uso

1. **Crear usuario administrador inicial:**
   - Ejecutar script SQL para insertar primer admin manualmente
   - O usar el endpoint de registro modificando temporalmente el tipo de usuario

2. **Como Administrador:**
   - Acceder a `dashboard-admin-system.html`
   - Crear talleres desde la sección "Gestión de Talleres"
   - Crear instructores y asignarlos a talleres
   - Monitorear inscripciones y estadísticas

3. **Como Instructor:**
   - Acceder a `dashboard-instructor.html`
   - Completar perfil con información de contacto
   - Gestionar calendario de eventos del taller
   - Ver alumnos inscritos

4. **Como Alumno:**
   - Registrarse desde `register.html`
   - Explorar talleres disponibles
   - Inscribirse a talleres de interés
   - Ver calendario de eventos

## 🖼 Capturas de Pantalla

### Página Principal
![Home](docs/screenshots/home.png)

### Dashboard de Instructor con Calendario
![Instructor Dashboard](docs/screenshots/instructor-calendar.png)

### Dashboard de Administrador
![Admin Dashboard](docs/screenshots/admin-dashboard.png)

## 🤝 Contribución

Las contribuciones son bienvenidas. Por favor, sigue estos pasos:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add: nueva característica increíble'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

### Convenciones de Commits

- `Add:` Nueva característica
- `Fix:` Corrección de bug
- `Update:` Actualización de funcionalidad existente
- `Refactor:` Refactorización de código
- `Docs:` Cambios en documentación
- `Style:` Cambios de formato, no afectan funcionalidad

## 🔐 Seguridad

- Las contraseñas se hashean con bcrypt (12 salt rounds)
- Autenticación basada en JWT
- Rate limiting en endpoints sensibles
- Validación de entrada en todos los endpoints
- Protección CSRF y XSS mediante Helmet
- CORS configurado apropiadamente
- Manejo seguro de variables de entorno

## 📝 Licencia

Este proyecto es parte de un proyecto académico del CBTis 258. Todos los derechos reservados.

## 👥 Autores

- **Sergio** - [sergiodev3](https://github.com/sergiodev3)

## 🙏 Agradecimientos

- Centro de Bachillerato Tecnológico industrial y de servicios No. 258 "Mariano Escobedo"
- Creative Tim por el template Light Bootstrap Dashboard
- Comunidad de Open Source por las librerías utilizadas

## 📞 Contacto

Para preguntas o soporte:
- GitHub: [@sergiodev3](https://github.com/sergiodev3)
- Proyecto: [https://github.com/sergiodev3/proyecto-talleres-cbtis258](https://github.com/sergiodev3/proyecto-talleres-cbtis258)

---

⭐ Si este proyecto te fue útil, considera darle una estrella en GitHub!
