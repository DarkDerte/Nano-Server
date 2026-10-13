# Nano-Server

Nano-Server es un servidor HTTP ligero escrito en Rust para publicar sitios estáticos desde una carpeta. Lee su configuración del formato INI mínimo `config.ini` y sirve cada archivo con un tipo de contenido según su extensión.

## Empezar

```sh
cargo run
```

Por defecto, Nano-Server lee `config.ini` desde el directorio actual. Para usar otro fichero de configuración, define `NANO_SERVER_CONFIG`:

```sh
NANO_SERVER_CONFIG=/ruta/al/config.ini cargo run
```

En PowerShell:

```powershell
$env:NANO_SERVER_CONFIG = "C:\sitio\config.ini"
cargo run
```

## Configuración

```ini
[server]
address = 127.0.0.1:8080
cache_max_age_seconds = 3600
access_log = logs/access.log
# Optional: set both to enable HTTPS with TLS 1.3 only.
# tls_cert = certs/fullchain.pem
# tls_key = certs/privkey.pem

[site localhost]
document_root = public
index_file = index.html
not_found_page = 404.html

[site demo.local]
document_root = public-demo
index_file = index.html
not_found_page = 404.html

[redirect localhost]
/welcome = 302 /

[mime]
wasm = application/wasm
md = text/markdown; charset=utf-8
```

`[server]` define las opciones globales. Cada bloque `[site dominio]` define un sitio virtual seleccionado por el encabezado `Host`. Los valores no llevan comillas, las líneas vacías se ignoran y `#` o `;` al inicio de línea indican comentarios. Las rutas relativas se resuelven desde la carpeta que contiene `config.ini`; cada `document_root` debe existir al iniciar el servidor. Las URL de directorio sirven el `index_file` del sitio. `not_found_page` es opcional; usa `not_found_page = none` para desactivarla. Si el host solicitado no está configurado, se sirve el primer sitio como predeterminado.

`access_log` es opcional; define un archivo de registro adicional además de la consola. Las carpetas intermedias se crean al cargar la configuración. Usa `access_log = none` para desactivarlo.

Para activar HTTPS, configura `tls_cert` y `tls_key` con rutas a un certificado PEM y su clave privada PEM. Deben definirse ambos; con TLS activado, el servidor acepta únicamente TLS 1.3 y usa `https://`. El certificado debe ser válido para todos los dominios servidos, ya que se configura un solo par certificado/clave. Los cambios de certificado requieren reiniciar el proceso.

Un bloque `[redirect dominio]` añade redirecciones exactas para ese sitio. Por ejemplo, `/old = /new` devuelve `301`; `/temporary = 302 /new` devuelve `302`. El destino puede ser una ruta del mismo sitio o una URL `http://`/`https://`.

El bloque opcional `[mime]` permite añadir o sustituir tipos MIME por extensión, sin el punto. Por ejemplo, `wasm = application/wasm`. Las extensiones conocidas tienen tipos predeterminados y estas reglas los sobrescriben.

Coloca cada sitio en su propia carpeta. El ejemplo `localhost` se sirve desde `public/`, y `demo.local` desde `public-demo/`. Para probar el segundo sitio localmente, envía el encabezado `Host: demo.local` (por ejemplo, `curl -H "Host: demo.local" http://127.0.0.1:8080/`). También se aceptan `HEAD`; las rutas desconocidas devuelven `404` y otros métodos `405`. Las conexiones atienden una solicitud y luego se cierran.

Nano-Server escribe una línea de registro por solicitud en la salida estándar, con dirección remota, método, ruta, código HTTP y duración.

Las solicitudes tienen un límite de 8 KiB para la línea inicial, 8 KiB por línea de cabecera y 32 KiB para todas las cabeceras. El servidor cierra conexiones que tardan más de cinco segundos en leer o escribir. Las solicitudes malformadas o que exceden esos límites reciben `400 Bad Request` cuando es posible responder.

Los archivos estáticos admiten solicitudes de un solo rango de bytes, como `Range: bytes=0-1023` o `Range: bytes=-500`. Un rango válido devuelve `206 Partial Content`; uno que no se puede satisfacer devuelve `416`. Para las respuestas parciales se envía el contenido sin comprimir.

## Recarga de configuración

Nano-Server vuelve a leer `config.ini` al recibir cada nueva conexión. Los cambios válidos en los sitios, sus carpetas, índices y páginas 404 se aplican a las solicitudes siguientes. Si el fichero contiene errores o apunta a una carpeta inexistente, conserva la última configuración válida y deja el error en la salida estándar. Los cambios en `address` requieren reiniciar el servidor porque cambian el socket de escucha. El parser propio reconoce únicamente las opciones documentadas aquí y no añade bibliotecas para leer la configuración.

## Compresión y caché

Los archivos de texto, HTML, CSS, JavaScript, JSON y SVG se comprimen con gzip cuando el cliente lo admite y la versión comprimida ocupa menos. Cada archivo estático incluye un `ETag` y `Cache-Control`; los clientes pueden enviar `If-None-Match` para recibir `304 Not Modified` sin descargar el contenido otra vez. `cache_max_age_seconds` configura el tiempo de caché (por defecto, una hora). Las respuestas varían según `Accept-Encoding`.


## Compilaci�n para diferentes arquitecturas

Nano-Server es portable y puede compilarse para m�ltiples arquitecturas usando Rust.

### Targets preinstalados

Puedes listar los targets disponibles: 

```powershell
rustup target list --installed
```

### Compilar para un target espec�fico

```sh
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
```

Los binarios se generar�n en `target/<target>/release/`.

### Instalar target nuevo

```sh
rustup target add <target>
```

### Notas de cross-compilation

- Para Linux `musl`, el proyecto ya tiene configuraci�n con `rust-lld`.
- En Windows se usa `crt-static` para generar binarios autocontenidos.
- Dependencias (`ring`, `rustls`) son compatibles multiplataforma. No hay dependencias nativas que bloqueen la compilaci�n cruzada en la mayor�a de targets comunes.
- Para targets no nativos (ej. compilar Linux desde Windows), puede requerirse un linker adicional; en este entorno ya hay targets Linux instalados.
