
# 🚀 SEAVAULT - Seguridad y Cifrado de Archivos 🔒

[![GitHub license](https://img.shields.io/github/license/XenaMVPs/SEAVAULT)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/XenaMVPs/SEAVAULT?style=social)](https://github.com/XenaMVPs/SEAVAULT/stargazers)

🔐 **SEAVAULT** es una herramienta avanzada para **detección, cifrado y protección de archivos sensibles**, diseñada por [CupDev](https://github.com/Cuppdev) y [XenaDev](https://github.com/XenaMVPs). 🚀

## 🛡️ Características Clave

✅ **Detección Inteligente**: Escanea archivos en busca de datos sensibles como contraseñas, claves API, tokens, etc.  
✅ **Cifrado AES-256-GCM**: Protección fuerte y segura contra accesos no autorizados.  
✅ **Monitoreo en Tiempo Real**: Protege automáticamente directorios seleccionados.  
✅ **Evita Recifrado**: Reconoce archivos ya protegidos y evita cifrados innecesarios.  
✅ **Logs Detallados**: Registro completo de eventos y actividad del sistema.  
✅ **Multi-Plataforma**: Funciona en Windows, Linux y macOS.  

---

## 📦 Instalación

1️⃣ Clona el repositorio:

```bash
git clone https://github.com/XenaMVPs/SEAVAULT.git
cd SEAVAULT
```

2️⃣ Instala dependencias necesarias (Node.js 16+ recomendado):

```bash
npm install
```

3️⃣ Configura el archivo `.env`:

```bash
cp .env.example .env
nano .env  # O usa tu editor favorito
```

✍️ **Modifica la passphrase y otros parámetros según tus necesidades.**

---

## 🚀 Uso

### 🔍 Escanear y cifrar archivos sensibles en un directorio:

```bash
node vault_core.js scan /ruta/del/directorio
```

### 🔐 Cifrar un archivo manualmente:

```bash
node vault_core.js encrypt /ruta/del/archivo.txt
```

### 🔓 Descifrar un archivo:

```bash
node vault_core.js decrypt /ruta/del/archivo.txt.enc
```

### 📡 Monitorear cambios en un directorio en tiempo real:

```bash
node vault_core.js monitor /ruta/del/directorio
```

---

## 🛠️ Configuración Personalizada

Puedes editar el archivo `.env` para personalizar las opciones:

```ini
VAULT_PASSPHRASE="TuClaveSegura"
MONITOR_DIRECTORIES="/ruta/a/proteger"
LOG_FILE="logs/vault.log"
DELETE_ORIGINAL_AFTER_ENCRYPT=false
```

💡 **Recomendado**: Usa una passphrase fuerte y mantén `.env` fuera del control de versiones (`.gitignore` ya lo protege).

---

## 🎯 Roadmap y Mejoras Futuras

✅ Implementación de PBKDF2 para fortalecimiento de clave 🔑  
✅ Soporte para múltiples directorios en monitoreo 🏆  
🚧 Integración con notificaciones en Telegram y Discord 📢  
🚧 Cifrado en la nube con opciones de backup automático ☁️  

💡 **¿Tienes ideas?** ¡Cualquier sugerencia es bienvenida en los [issues](https://github.com/XenaMVPs/SEAVAULT/issues)! 🎯

---

## 💜 Créditos y Reconocimientos

🔹 **SEAVAULT** es un proyecto de [CupDev](https://github.com/Cuppdev) y [XenaDev](https://github.com/XenaMVPs).  
🔹 Creado con pasión por la seguridad y la innovación.  
🔹 Código abierto con amor ❤️, porque **la privacidad importa**.  

📢 **Síguenos en GitHub y apoya con una ⭐!**  

