import 'dotenv/config'
import express from 'express';

import userRouter from './routes/user.route.js'
import petRouter from './routes/pet.route.js'
import publicRouter from './routes/public.route.js'

const app = express();

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

app.use('/', publicRouter)
app.use('/api/v1/users', userRouter)
app.use('/api/v1/pets', petRouter)

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => console.log('Servidor andando en ' + PORT))
function startSearch() {
    // Mostrar notificación de carga
    document.getElementById('loadingNotification').style.display = 'flex';
    
    // Simular una búsqueda (por ejemplo, usando setTimeout)
    setTimeout(() => {
        // Aquí iría el código real de búsqueda
        alert('Búsqueda completada');
        
        // Ocultar notificación de carga
        document.getElementById('loadingNotification').style.display = 'none';
    }, 2000); // Simula una búsqueda que dura 2 segundos
}
