// vault_core.js

/********************************************************************
 * UNIFICADO: (BRUTAL)
 * - Detección asíncrona y concurrente de datos sensibles (streaming).
 * - Cifrado AES-256-GCM (autenticado) con PBKDF2.
 * - Backup antes de cifrar (opcional).
 * - Filtrado de binarios y prevención de recifrado.
 * - Logging avanzado y estadísticas.
 * - Config desde vault_config.json (si existe) + defaults.
 * - CLI para scan/encrypt/decrypt.
 ********************************************************************/

const fs = require('fs');
const fsPromises = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const stream = require('stream');

// pipeline asíncrono (para streams)
const pipeline = promisify(stream.pipeline);

/*---------------------------------------------------
 *  1) CONFIGURACIONES, LOGGER Y VARIABLES GLOBALES
 *--------------------------------------------------*/

/**
 * Logger avanzado para manejar registros con niveles y
 * opcionalmente escribir en un archivo.
 */
class Logger {
  constructor(logFile = null) {
    this.logFile = logFile;
  }
  _log(level, message) {
    const timestamp = new Date().toISOString();
    const logMsg = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
    console.log(logMsg);
    if (this.logFile) {
      fs.appendFile(this.logFile, logMsg + "\n", (err) => {
        if (err) console.error("Error escribiendo en archivo de log:", err);
      });
    }
  }
  info(message) {
    this._log("info", message);
  }
  debug(message) {
    this._log("debug", message);
  }
  warn(message) {
    this._log("warn", message);
  }
  error(message) {
    this._log("error", message);
  }
}

/**
 * Config por defecto (puede ser sobreescrita por vault_config.json).
 */
const defaultConfig = {
  passphrase: "TU-PASSPHRASE-AQUÍ",           // Cámbiala en producción
  sensitiveKeywords: ["password", "api_key", "secret", "credentials"],
  backup: true,                               // Realiza backup antes de cifrar
  backupExtension: ".bak",                    // Extensión para backup
  concurrentLimit: 5,                         // Límite de concurrencia en el escaneo
  logFile: null,                              // Ruta al archivo de log (null => solo consola)
  deleteOriginalAfterEncrypt: false           // Eliminar el archivo original tras cifrar
};

let config = { ...defaultConfig };
let logger = new Logger(config.logFile);

/**
 * Variable global para la passphrase derivada (AES-256-GCM).
 * En modo GCM, generamos la clave en cada cifrado, derivándola de la passphrase + salt.
 * Pero podemos guardar la passphrase base en config y derivarla cada vez.
 * (En CBC se hacía un hash único, aquí usaremos PBKDF2 en cada cifrado).
 */

/*---------------------------------------------------
 *  2) CARGAR CONFIGURACIÓN (vault_config.json)
 *--------------------------------------------------*/
async function loadConfig() {
  try {
    const configPath = path.join(__dirname, 'vault_config.json');
    const data = await fsPromises.readFile(configPath, 'utf8');
    const fileConfig = JSON.parse(data);
    config = Object.assign({}, defaultConfig, fileConfig);
    logger = new Logger(config.logFile);
    logger.info("Configuración cargada desde vault_config.json");
  } catch (err) {
    logger.warn("No se encontró vault_config.json o error al cargarlo. Usando configuración por defecto.");
  }

  // También, si prefieres, podrías sobreescribir con variables de entorno:
  if (process.env.VAULT_PASSPHRASE) {
    config.passphrase = process.env.VAULT_PASSPHRASE;
    logger.info("Usando passphrase desde variable de entorno VAULT_PASSPHRASE.");
  }
  if (process.env.CONCURRENCY_LIMIT) {
    config.concurrentLimit = parseInt(process.env.CONCURRENCY_LIMIT, 10);
  }
  if (process.env.DELETE_ORIGINAL === 'true') {
    config.deleteOriginalAfterEncrypt = true;
  }
}

/*---------------------------------------------------
 *  3) DETECCIÓN DE BINARIOS
 *--------------------------------------------------*/

/**
 * Determina si un archivo es binario en base a un primer chunk.
 */
const BIN_THRESHOLD = 0.3;   // 30% bytes no imprimibles => binario
const BIN_CHUNK_SIZE = 512;  // Tamaño de muestra

async function isBinaryFile(filepath) {
  try {
    const fd = await fsPromises.open(filepath, 'r');
    const buffer = Buffer.alloc(BIN_CHUNK_SIZE);
    const { bytesRead } = await fd.read(buffer, 0, BIN_CHUNK_SIZE, 0);
    await fd.close();

    let nonPrintable = 0;
    for (let i = 0; i < bytesRead; i++) {
      const code = buffer[i];
      const printable = (code >= 32 && code <= 126) || [9, 10, 13].includes(code);
      if (!printable) nonPrintable++;
    }
    const ratio = nonPrintable / bytesRead;
    return ratio > BIN_THRESHOLD;
  } catch (error) {
    logger.warn(`No se pudo determinar si es binario. Asumiendo NO binario: ${filepath}`);
    return false;
  }
}

/*---------------------------------------------------
 *  4) DETECCIÓN DE DATOS SENSIBLES (STREAMING)
 *--------------------------------------------------*/

/**
 * Construye un único regex que matchee cualquiera de las keywords.
 */
function buildKeywordRegex(keywords) {
  const escaped = keywords.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const pattern = `(${escaped.join('|')})`;
  return new RegExp(pattern, 'i');
}

/**
 * Lee un archivo por streaming y detecta si contiene palabras sensibles.
 * - Se detiene en cuanto encuentra un match.
 * - Ignora archivos .enc y binarios.
 */
async function containsSensitiveData(filepath) {
  try {
    // Evitar re-cifrado si es .enc
    if (filepath.endsWith('.enc')) {
      return false;
    }
    // Si es binario, no lo analizamos
    if (await isBinaryFile(filepath)) {
      return false;
    }
    const regex = buildKeywordRegex(config.sensitiveKeywords);

    return await new Promise((resolve, reject) => {
      const readStream = fs.createReadStream(filepath, { encoding: 'utf8' });
      let leftover = '';

      readStream.on('data', chunk => {
        const text = leftover + chunk;
        if (regex.test(text)) {
          readStream.destroy();
          return resolve(true);
        }
        // Retenemos un trozo para no partir keywords
        const maxLen = config.sensitiveKeywords.reduce((max, k) => Math.max(max, k.length), 0);
        leftover = text.slice(-maxLen);
      });
      readStream.on('error', err => reject(err));
      readStream.on('end', () => resolve(false));
    });
  } catch (error) {
    logger.error(`Error analizando datos sensibles en ${filepath}`, error);
    return false;
  }
}

/*---------------------------------------------------
 *  5) DERIVACIÓN DE CLAVE (PBKDF2)
 *--------------------------------------------------*/
const PBKDF2_ITERATIONS = 100_000; // Ajusta según seguridad vs rendimiento

async function deriveKey(passphrase, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(passphrase, salt, PBKDF2_ITERATIONS, 32, 'sha512', (err, derived) => {
      if (err) return reject(err);
      resolve(derived);
    });
  });
}

/*---------------------------------------------------
 *  6) CIFRADO Y DESCIFRADO (AES-256-GCM)
 *--------------------------------------------------*/

const AES_MODE = 'aes-256-gcm';

/**
 * Realiza backup antes de cifrar (si config.backup = true).
 */
async function backupFile(filepath) {
  if (!config.backup) return;
  try {
    const backupPath = filepath + config.backupExtension;
    await fsPromises.copyFile(filepath, backupPath);
    logger.info(`Backup realizado: ${backupPath}`);
  } catch (err) {
    logger.error(`Error al crear backup de ${filepath}`, err);
  }
}

/**
 * Cifra un archivo con AES-256-GCM (streaming).
 * Estructura final del archivo cifrado:
 *   [salt(16b)] [iv(12b)] [ciphertext(...)] [authTag(16b)]
 */
async function encryptFile(filepath) {
  // Evitamos re-cifrar .enc
  if (filepath.endsWith('.enc')) {
    logger.info(`Archivo ya cifrado (ext .enc), saltando: ${filepath}`);
    return;
  }
  // Comprobamos si tiene datos sensibles
  const hasSensitive = await containsSensitiveData(filepath);
  if (!hasSensitive) {
    logger.info(`No se detectaron datos sensibles en: ${filepath}`);
    return;
  }
  // Hacemos backup si procede
  await backupFile(filepath);

  const passphrase = config.passphrase || 'DEFAULT-PASSPHRASE';
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);

  let derived;
  try {
    derived = await deriveKey(passphrase, salt);
  } catch (error) {
    logger.error(`Fallo derivando clave PBKDF2. No se cifró: ${filepath}`, error);
    return;
  }

  const cipher = crypto.createCipheriv(AES_MODE, derived, iv);
  const outputFilePath = filepath + '.enc';

  try {
    // 1) Abre archivo de salida para escribir salt + iv
    const outStream = fs.createWriteStream(outputFilePath, { flags: 'w' });
    outStream.write(salt); // 16 bytes
    outStream.write(iv);   // 12 bytes

    // 2) pipeline: leer -> cifrar -> escribir
    await pipeline(
      fs.createReadStream(filepath),
      cipher,
      outStream
    );

    // 3) Añadimos el authTag al final
    const authTag = cipher.getAuthTag(); // 16 bytes
    const appendStream = fs.createWriteStream(outputFilePath, { flags: 'a' });
    appendStream.write(authTag);
    appendStream.end();

    logger.info(`Archivo cifrado con éxito: ${outputFilePath}`);

    if (config.deleteOriginalAfterEncrypt) {
      await fsPromises.unlink(filepath);
      logger.info(`Archivo original eliminado: ${filepath}`);
    }
  } catch (error) {
    logger.error(`Error cifrando: ${filepath}`, error);
  }
}

/**
 * Descifra un archivo con AES-256-GCM (streaming).
 * Debe tener la estructura:
 *   [salt(16b)] [iv(12b)] [ciphertext(...)] [authTag(16b)]
 */
async function decryptFile(filepath) {
  // Verificamos que sea un archivo .enc
  if (!filepath.endsWith('.enc')) {
    logger.warn(`El archivo no tiene extensión .enc (¿está cifrado con GCM?): ${filepath}`);
  }

  // Leemos todo el contenido en binario
  let fileBuffer;
  try {
    fileBuffer = await fsPromises.readFile(filepath);
  } catch (error) {
    logger.error(`No se pudo leer archivo cifrado: ${filepath}`, error);
    return;
  }

  if (fileBuffer.length < 16 + 12 + 16) {
    logger.error(`El archivo cifrado es demasiado pequeño o corrupto: ${filepath}`);
    return;
  }

  // Extraemos salt, iv, authTag
  const salt = fileBuffer.slice(0, 16);
  const iv = fileBuffer.slice(16, 28);
  const authTag = fileBuffer.slice(fileBuffer.length - 16);
  const ciphertext = fileBuffer.slice(28, fileBuffer.length - 16);

  const passphrase = config.passphrase || 'DEFAULT-PASSPHRASE';

  let derived;
  try {
    derived = await deriveKey(passphrase, salt);
  } catch (error) {
    logger.error(`Fallo derivando clave PBKDF2 para descifrar: ${filepath}`, error);
    return;
  }

  const decipher = crypto.createDecipheriv(AES_MODE, derived, iv);
  decipher.setAuthTag(authTag);

  // Generamos nombre de salida (quitamos .enc)
  const outputFilePath = filepath.replace(/\.enc$/, '');

  try {
    const outStream = fs.createWriteStream(outputFilePath, { flags: 'w' });
    // pipeline: ciphertext -> decipher -> out
    await pipeline(
      stream.Readable.from(ciphertext),
      decipher,
      outStream
    );
    logger.info(`Archivo descifrado con éxito: ${outputFilePath}`);
  } catch (error) {
    logger.error(`Error descifrando: ${filepath}`, error);
  }
}

/*---------------------------------------------------
 *  7) ESCANEO RECURSIVO CON CONCURRENCIA LIMITADA
 *--------------------------------------------------*/

/**
 * Estadísticas globales (opcional).
 */
const STATS = {
  filesScanned: 0,
  filesEncrypted: 0,
  directoriesScanned: 0
};

/**
 * Cola de tareas en paralelo (similar a BFS) con un límite de concurrencia.
 */
class TaskQueue {
  constructor(concurrency) {
    this.concurrency = concurrency;
    this.running = 0;
    this.queue = [];
    this.resolveIdle = () => {};
  }

  enqueue(task) {
    return new Promise((resolve, reject) => {
      this.queue.push({ task, resolve, reject });
      process.nextTick(() => this.dequeue());
    });
  }

  async dequeue() {
    if (this.running >= this.concurrency || this.queue.length === 0) {
      return;
    }
    const { task, resolve, reject } = this.queue.shift();
    this.running++;
    try {
      const result = await task();
      resolve(result);
    } catch (err) {
      reject(err);
    } finally {
      this.running--;
      if (this.queue.length > 0) {
        this.dequeue();
      } else if (this.running === 0) {
        this.resolveIdle();
      }
    }
  }

  async waitForIdle() {
    if (this.running === 0 && this.queue.length === 0) {
      return;
    }
    return new Promise(resolve => {
      this.resolveIdle = resolve;
    });
  }
}

/**
 * Escanea un directorio recursivamente, y cifra archivos con datos sensibles.
 */
async function scanAndEncryptDirectory(rootDirectory) {
  const queue = new TaskQueue(config.concurrentLimit);

  async function processDirectory(dirPath) {
    STATS.directoriesScanned++;
    let dirItems;
    try {
      dirItems = await fsPromises.readdir(dirPath, { withFileTypes: true });
    } catch (error) {
      logger.error(`Error leyendo directorio: ${dirPath}`, error);
      return;
    }

    for (const item of dirItems) {
      const fullPath = path.join(dirPath, item.name);
      if (item.isDirectory()) {
        await queue.enqueue(() => processDirectory(fullPath));
      } else if (item.isFile()) {
        await queue.enqueue(async () => {
          STATS.filesScanned++;
          // encryptFile() internamente hace backup y verifica datos sensibles
          await encryptFile(fullPath);
          // Si en encryptFile detecta datos sensibles => lo cifra => stats
          // Podrías incrementar STATS.filesEncrypted si quieres
          // tras verificar si se cifró. De momento lo dejamos en encryptFile.
        });
      }
    }
  }

  await queue.enqueue(() => processDirectory(rootDirectory));
  await queue.waitForIdle();

  logger.info('======================');
  logger.info('Proceso finalizado');
  logger.info(`Directorios escaneados: ${STATS.directoriesScanned}`);
  logger.info(`Archivos escaneados: ${STATS.filesScanned}`);
  logger.info(`Archivos cifrados (ver logs).`);
  logger.info('======================');
}

/*---------------------------------------------------
 *  8) CLI PRINCIPAL
 *--------------------------------------------------*/

/**
 * CLI: node vault_core.js <command> [args]
 *   - scan <directorio>
 *   - encrypt <archivo>
 *   - decrypt <archivo>
 */
async function main() {
  await loadConfig();
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log("Uso: node vault_core.js <command> [options]");
    console.log("Comandos:");
    console.log("  scan <directorio>   Escanea y cifra archivos en el directorio");
    console.log("  encrypt <archivo>   Cifra un archivo específico");
    console.log("  decrypt <archivo>   Descifra un archivo específico");
    process.exit(1);
  }

  const command = args[0];
  switch (command) {
    case 'scan':
      if (args.length < 2) {
        logger.error("Se requiere el directorio a escanear");
        process.exit(1);
      }
      await scanAndEncryptDirectory(args[1]);
      break;

    case 'encrypt':
      if (args.length < 2) {
        logger.error("Se requiere el archivo a cifrar");
        process.exit(1);
      }
      await loadConfig(); // Aseguramos config actual
      await encryptFile(args[1]);
      break;

    case 'decrypt':
      if (args.length < 2) {
        logger.error("Se requiere el archivo a descifrar (.enc)");
        process.exit(1);
      }
      await loadConfig();
      await decryptFile(args[1]);
      break;

    default:
      logger.error(`Comando desconocido: ${command}`);
      process.exit(1);
  }
}

if (require.main === module) {
  main();
}

/*---------------------------------------------------
 *  9) EXPORTACIONES
 *--------------------------------------------------*/
module.exports = {
  loadConfig,
  containsSensitiveData,
  encryptFile,
  decryptFile,
  scanAndEncryptDirectory,
  logger,
  STATS
};
