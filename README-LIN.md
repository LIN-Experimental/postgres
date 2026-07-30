# PostgreSQL con autenticación LIN

Este árbol es PostgreSQL con un método de autenticación adicional, `lin`, que
verifica las contraseñas contra una API REST del tenant en lugar de contra
`pg_authid`. Toda su configuración viene de variables de entorno, de modo que
se pueda desplegar con lo que ofrecen Docker, Kubernetes o cualquier plataforma
capaz de inyectarlas.

La imagen de Docker incluye además **pgvector**, compilado contra este mismo
árbol.

El resto del código es PostgreSQL sin modificar; consulta `README.md` para la
documentación general del proyecto.

- [Compilar](#compilar)
- [Generar la imagen de Docker](#generar-la-imagen-de-docker)
- [pgvector](#pgvector)
- [Ejecutar el contenedor](#ejecutar-el-contenedor)
- [Configurar `pg_hba.conf` a mano](#configurar-pg_hbaconf-a-mano)
- [Contrato de la API](#contrato-de-la-api)
- [Probarlo de punta a punta](#probarlo-de-punta-a-punta)
- [Problemas comunes](#problemas-comunes)
- [Archivos que componen el método](#archivos-que-componen-el-método)

---

## Compilar

`lin` necesita **libcurl** para hablar HTTP. Sin ella el método no se compila y
`pg_hba.conf` rechaza la palabra `lin` con *"not supported by this build"*, así
que `--with-libcurl` no es opcional aquí.

### Si trabajas en Windows

Este checkout tiene `core.autocrlf=true`, así que **todos los archivos de texto
están en CRLF**. Eso rompe cualquier compilación en Linux de forma bastante
opaca: `./configure` falla con `not found` (código 127), porque el kernel lee el
shebang como `#!/bin/sh\r` e intenta ejecutar un intérprete que no existe.

La ruta cómoda en Windows es **compilar dentro de la imagen de Docker**, que
normaliza los finales de línea por su cuenta. Salta a
[Generar la imagen](#generar-la-imagen-de-docker).

Si prefieres compilar en WSL, normaliza primero:

```bash
grep -rlI --null -e "$(printf '\r')" . | xargs -0 -r sed -i 's/\r$//'
chmod +x configure config/install-sh config/missing config/mkinstalldirs
```

### Linux, con autoconf

Dependencias en Debian/Ubuntu:

```bash
sudo apt-get install -y build-essential bison flex perl pkg-config \
    libcurl4-openssl-dev libssl-dev libicu-dev libreadline-dev zlib1g-dev
```

Compilar e instalar:

```bash
./configure --prefix=/usr/local/pgsql \
            --with-libcurl \
            --with-openssl \
            --with-icu \
            --with-readline \
            --with-zlib

make -j"$(nproc)" world-bin      # todo excepto la documentación
sudo make install-world-bin
```

`world-bin` incluye `contrib`. Si no lo necesitas, `make -j"$(nproc)"` y
`make install` bastan y son más rápidos.

Para comprobar que salió con soporte LIN:

```bash
/usr/local/pgsql/bin/pg_config --configure | grep -o -- --with-libcurl
```

### Linux, con meson

```bash
meson setup build -Dlibcurl=enabled -Dssl=openssl --prefix=/usr/local/pgsql
ninja -C build
sudo ninja -C build install
```

En plataformas sin `epoll` ni `kqueue` (Windows, por ejemplo) usa
`-Dlibcurl=auto` en lugar de `enabled`: con `enabled` meson aborta porque el
flujo OAuth *del cliente* no está soportado ahí, mientras que con `auto` detecta
libcurl, habilita `lin` y simplemente deja OAuth fuera.

> La ruta de meson está cableada en `meson.build` pero **no la he ejecutado**;
> en este entorno no hay meson instalado. La de autoconf sí está probada: es
> exactamente la que corre el `Dockerfile`.

### Iterar sobre el método

Después de la primera compilación completa, para recompilar solo el backend:

```bash
make -j"$(nproc)" -C src/backend && sudo make -C src/backend install
```

Los archivos del método son `src/backend/libpq/auth-lin.c` y
`src/include/libpq/lin.h`; hay una lista completa
[al final](#archivos-que-componen-el-método).

---

## Generar la imagen de Docker

Desde la raíz del repositorio:

```bash
docker build -t linplatform/postgres .
```

Eso es todo. El `Dockerfile` es multi-etapa: compila PostgreSQL en
`debian:bookworm-slim` con las dependencias de desarrollo, compila pgvector
contra ese resultado y copia solo lo instalado a una imagen de runtime. Detalles
que conviene saber:

- **Tarda varios minutos** la primera vez (compila PostgreSQL entero). Las capas
  de `apt-get` quedan en caché, así que las siguientes veces empieza directo en
  `configure`.
- **Normaliza CRLF y restaura los bits de ejecución** después del `COPY`, así
  que funciona desde un checkout de Windows sin tocar tu árbol de trabajo.
- **`.dockerignore` excluye `.git`**, que ocupa bastante más que el código.
- La imagen resultante ronda los **266 MB** e instala `ca-certificates`, que no
  es opcional: libcurl lo necesita para verificar el certificado TLS de
  `LIN_AUTH_ENDPOINT`.
- La etapa de pgvector **clona desde GitHub**, así que el build necesita salida a
  internet (igual que ya la necesita para `apt-get`).

Comprobar la imagen:

```bash
docker run --rm linplatform/postgres postgres --version
docker run --rm linplatform/postgres pg_config --configure
```

Para fijar otra versión de pgvector:

```bash
docker build --build-arg PGVECTOR_VERSION=v0.8.5 -t linplatform/postgres .
```

Para publicarla en un registry:

```bash
docker tag linplatform/postgres linplatform/postgres:20devel
docker push linplatform/postgres:20devel
```

---

## Ejecutar el contenedor

```bash
docker run -d --name pg -p 5432:5432 \
  -e LIN_TENANT=empresa-001 \
  -e LIN_AUTH_ENDPOINT=https://auth.miempresa.com/api/auth/login \
  -e LIN_HTTP_TIMEOUT=5000 \
  -v pgdata:/var/lib/postgresql/data \
  linplatform/postgres
```

### Variables de entorno

| Variable | Obligatoria | Descripción |
|---|---|---|
| `LIN_TENANT` | sí | Tenant dueño de esta instancia. **Nunca** viene del cliente. |
| `LIN_AUTH_ENDPOINT` | sí | URL de la API de login. Solo `http` y `https`; no se siguen redirecciones. |
| `LIN_HTTP_TIMEOUT` | no | Espera máxima en milisegundos. Por defecto `5000`. |
| `LIN_CACHE_TTL` | no | **Segundos** que se reutiliza una autenticación aceptada. Por defecto `20`; `0` la desactiva; máximo `300`. |
| `POSTGRES_USER` | no | Superusuario a crear. Por defecto `postgres`. |
| `POSTGRES_PASSWORD` | no | Contraseña del superusuario, si no usas LIN. |
| `POSTGRES_HOST_AUTH_METHOD` | no | Método para conexiones host cuando LIN no está configurado. |
| `PGDATA` | no | Por defecto `/var/lib/postgresql/data`. |

Las cuatro primeras **se leen una sola vez, al arrancar el servidor**, y los
valores se reutilizan durante toda la vida del proceso. Cambiarlas exige
reiniciar, no basta con recargar la configuración.

### Caché de autenticación

Sin un pooler, cada conexión paga un viaje HTTP completo antes de poder hacer
nada. Por eso una autenticación **aceptada** se guarda en memoria compartida
durante `LIN_CACHE_TTL` segundos y la reutilizan todos los backends: una ráfaga
de conexiones del mismo usuario cuesta una sola petición. También permite que
las conexiones sigan funcionando durante una caída breve de la API.

Solo se cachean las aceptaciones. Un rechazo se vuelve a consultar siempre, así
que los intentos de fuerza bruta siempre llegan al servicio y un usuario que
acaba de corregir su contraseña entra de inmediato. El rol devuelto por la API
se guarda junto a la entrada, así que una respuesta reutilizada mapea igual que
la original.

Las entradas se indexan por un HMAC-SHA256 del tenant, el usuario y la
contraseña, bajo una clave generada aleatoriamente al arrancar. **La caché nunca
guarda la contraseña**, y su contenido no significa nada fuera de la vida del
cluster que lo produjo.

> **El coste es latencia de revocación.** Durante hasta `LIN_CACHE_TTL`
> segundos, una credencial que la API ya aceptó sigue funcionando aunque la
> hayas deshabilitado, y un mapeo de rol sigue aplicándose aunque lo hayas
> cambiado. Si tu despliegue no puede aceptar esa ventana, pon
> `LIN_CACHE_TTL=0`.

Si `pg_hba.conf` usa `lin` y falta `LIN_TENANT` o `LIN_AUTH_ENDPOINT`, el
servidor **registra el error y no arranca**, en lugar de fallar en cada
conexión.

### Qué hace el entrypoint

En el primer arranque crea el cluster y, si `LIN_TENANT` y `LIN_AUTH_ENDPOINT`
están presentes, configura `pg_hba.conf` para autenticar las conexiones host con
`lin`. En arranques posteriores reutiliza el cluster existente sin tocarlo.

Sin esas variables pide `POSTGRES_PASSWORD` (y usa `scram-sha-256`) o
`POSTGRES_HOST_AUTH_METHOD=trust`. El socket local siempre queda en `trust`, que
es como puedes entrar a crear roles.

### Con docker compose

```yaml
services:
  postgres:
    image: linplatform/postgres
    environment:
      LIN_TENANT: empresa-001
      LIN_AUTH_ENDPOINT: https://auth.miempresa.com/api/auth/login
      LIN_HTTP_TIMEOUT: "5000"
    ports: ["5432:5432"]
    volumes: ["pgdata:/var/lib/postgresql/data"]

volumes:
  pgdata:
```

---

## pgvector

La imagen trae **pgvector 0.8.6** ya compilado. Es una extensión, así que se
habilita por base de datos:

```sql
CREATE EXTENSION vector;
```

```sql
CREATE TABLE docs (id bigserial PRIMARY KEY, embedding vector(3));
INSERT INTO docs (embedding) VALUES ('[1,2,3]'), ('[4,5,6]'), ('[1,1,1]');

SELECT id, embedding <-> '[3,1,2]' AS distancia
  FROM docs
 ORDER BY embedding <-> '[3,1,2]'
 LIMIT 5;

CREATE INDEX ON docs USING hnsw (embedding vector_l2_ops);
```

Están disponibles los tipos `vector`, `halfvec`, `sparsevec` y `bit`, los
operadores de distancia (`<->` L2, `<=>` cosine, `<#>` producto interno) y los
índices **HNSW** e **IVFFlat**. La documentación completa está en
<https://github.com/pgvector/pgvector>.

### Dos cosas sobre esta compilación

**Se compila desde fuente contra este árbol**, no desde un paquete. pgvector
declara soporte para las versiones estables de PostgreSQL, y esto es 20devel
(rama master), así que la compatibilidad no está garantizada de antemano: 0.8.6
compila limpio hoy, pero un cambio futuro en las APIs internas de master podría
romperla. Si eso pasa, el `Dockerfile` fallará de forma visible en la etapa
`pgvector` en lugar de producir una imagen rota.

**Se compila con `OPTFLAGS=""`**, que desactiva el `-march=native` que pgvector
usa por defecto. Con el valor por defecto, el `vector.so` quedaría optimizado
para la CPU exacta de la máquina que construyó la imagen y moriría con `SIGILL`
al ejecutarse en hardware más antiguo. Es el compromiso habitual: la imagen es
portable, a costa de no usar instrucciones vectoriales específicas del
procesador. Si vas a desplegar en un parque de máquinas homogéneo y quieres ese
rendimiento extra, quita `OPTFLAGS=""` de la etapa `pgvector` del `Dockerfile`.

### Si compilas sin Docker

```bash
git clone --branch v0.8.6 --depth 1 https://github.com/pgvector/pgvector.git
cd pgvector
make OPTFLAGS="" PG_CONFIG=/usr/local/pgsql/bin/pg_config
sudo make OPTFLAGS="" PG_CONFIG=/usr/local/pgsql/bin/pg_config install
```

---

## Configurar `pg_hba.conf` a mano

`lin` se usa como cualquier otro método y no acepta opciones, porque toda su
configuración está en el entorno:

```
# TYPE  DATABASE  USER  ADDRESS       METHOD
hostssl all       all   0.0.0.0/0     lin
```

Usa **`hostssl`, no `host`**, en producción: como `password`, `ldap` o `pam`,
`lin` recibe la contraseña del cliente en claro.

`initdb` también lo acepta directamente:

```bash
initdb -D /ruta/datos --auth-local=trust --auth-host=lin
```

### El rol tiene que existir

`lin` verifica la contraseña, pero **no crea roles**, igual que LDAP o PAM. La
API se consulta primero y, si acepta, PostgreSQL exige que el rol exista:

```
FATAL:  role "alex" does not exist
```

Tienes dos formas de resolverlo.

**Aprovisionar un rol por usuario.** No necesita contraseña, la valida la API:

```sql
CREATE ROLE app_users NOLOGIN;              -- aquí viven los permisos
GRANT SELECT ON tabla TO app_users;
CREATE ROLE alex LOGIN IN ROLE app_users;   -- cáscara vacía por usuario
```

**Dejar que la API devuelva el rol**, y mantener solo un puñado de roles reales.
Ver [Mapeo de roles](#mapeo-de-roles).

---

## Contrato de la API

### Petición

```http
POST ${LIN_AUTH_ENDPOINT}
Content-Type: application/json
Accept: application/json
```

```json
{
    "tenant": "empresa-001",
    "username": "alex",
    "password": "..."
}
```

- `tenant` es siempre el valor de `LIN_TENANT`. Un cliente no puede
  autenticarse contra otro tenant.
- `username` es el rol que el cliente pidió en el paquete de arranque.
- `password` es la contraseña que envió el cliente.

### Respuesta

Un código **fuera del rango `2xx`** rechaza la conexión. Un `2xx` no basta por
sí solo: si el cuerpo trae un campo `authenticated` de primer nivel, ese campo
tiene la última palabra.

```json
{
    "authenticated": true,
    "role": "app_writer"
}
```

| Campo | Efecto |
|---|---|
| `authenticated: true` | Credenciales aceptadas. |
| `authenticated: false` | Rechazado, aunque el código HTTP sea 200. |
| `authenticated` ausente | Manda el código HTTP; un cuerpo vacío es válido. |
| `role: "<nombre>"` | La conexión asume ese rol. Ver abajo. |
| `role` ausente o `null` | El cliente conserva el rol que pidió. |

Se rechaza, en lugar de interpretarse, cualquier cosa ambigua: un
`authenticated` que no sea booleano (incluidos `null`, `1` y la cadena
`"true"`), un `role` que no sea cadena, un `role` vacío o de más de 63 bytes, un
cuerpo que no sea JSON válido, y un cuerpo de más de 8 kB. El motivo concreto
queda en el log del servidor.

Solo se miran los campos de **primer nivel**; un `role` anidado dentro de otro
objeto se ignora.

### Mapeo de roles

Cuando la respuesta trae `role`, la conexión asume ese rol en lugar del que pidió
el cliente. Así puedes mapear muchos usuarios finales sobre unos pocos roles de
base de datos, sin mantener un rol por persona. **El rol nombrado tiene que
existir**; no se crea al vuelo.

El usuario final sigue siendo la identidad autenticada, así que la auditoría no
se pierde:

```sql
SELECT current_user, system_user;
--  current_user | system_user
-- --------------+-------------
--  app_writer   | lin:alex
```

Esa distinción está disponible en triggers y políticas RLS.

> **Cuidado.** La respuesta puede nombrar *cualquier* rol, incluido un
> superusuario. Tu servicio de autenticación pasa a formar parte del perímetro
> de seguridad de la base de datos: sírvelo por `https` y revisa qué roles es
> capaz de nombrar.

---

## Probarlo de punta a punta

`docker/mock-auth-api.py` es una API falsa para probar sin un servicio real.
Trae tres usuarios: `alex`/`secreto123` → rol `app_writer`,
`maria`/`otra456` → rol `app_reader`, y `sinrol`/`nada789` sin mapeo.

```bash
docker network create linnet

# La API falsa
docker run -d --name lin-mock --network linnet \
  -v "$PWD/docker/mock-auth-api.py:/mock.py:ro" \
  python:3.12-alpine python /mock.py

# PostgreSQL apuntando a ella
docker run -d --name linpg --network linnet \
  -e LIN_TENANT=empresa-001 \
  -e LIN_AUTH_ENDPOINT=http://lin-mock:8080/api/auth/login \
  linplatform/postgres

# Los roles que la API va a devolver
docker exec linpg psql -U postgres \
  -c 'CREATE ROLE app_writer LOGIN' \
  -c 'CREATE ROLE app_reader LOGIN'

# Autenticar. "alex" no existe como rol y aun así entra, como app_writer
docker exec -e PGPASSWORD=secreto123 linpg \
  psql -h 127.0.0.1 -U alex -d postgres -c 'SELECT current_user, system_user'
```

```
 current_user | system_user
--------------+-------------
 app_writer   | lin:alex
```

Con contraseña incorrecta:

```bash
docker exec -e PGPASSWORD=mala linpg psql -h 127.0.0.1 -U alex -d postgres -c 'SELECT 1'
# FATAL:  LIN authentication failed for user "alex"
```

Y el motivo detallado, en el log del servidor:

```bash
docker logs linpg 2>&1 | grep -A1 "LIN authentication failed"
```

Para ver el mapeo en el log, arranca con `-c log_connections=all`:

```
LOG:  connection authenticated: identity="alex" method=lin (...pg_hba.conf:121)
LOG:  connection mapped: user="alex" role="app_writer" method=lin
```

Limpieza:

```bash
docker rm -f linpg lin-mock && docker network rm linnet
```

En Windows, si el bind mount de `-v` da problemas, ejecuta el script dentro del
contenedor pasándolo codificado:

```bash
B64=$(base64 -w0 docker/mock-auth-api.py)
docker run -d --name lin-mock --network linnet -e SRC="$B64" python:3.12-alpine \
  sh -c 'echo "$SRC" | base64 -d > /mock.py && exec python /mock.py'
```

---

## Problemas comunes

### Al compilar

| Síntoma | Causa |
|---|---|
| `./configure: not found` (código 127) | Finales de línea CRLF. Ver [Si trabajas en Windows](#si-trabajas-en-windows). |
| `invalid authentication method "lin": not supported by this build` | Compilado sin `--with-libcurl`. |
| `header file <curl/curl.h> is required for --with-libcurl` | Falta `libcurl4-openssl-dev`. |
| `client-side OAuth is not supported on this platform` | `-Dlibcurl=enabled` en una plataforma sin epoll/kqueue. Usa `auto`. |

### Al arrancar

| Mensaje | Qué hacer |
|---|---|
| `environment variable "LIN_TENANT" is not set` | Define `LIN_TENANT`. El servidor no arranca porque `pg_hba.conf` usa `lin`. |
| `environment variable "LIN_AUTH_ENDPOINT" is not set` | Define `LIN_AUTH_ENDPOINT`. |
| `invalid value for environment variable "LIN_HTTP_TIMEOUT"` | Tiene que ser un entero positivo de milisegundos. |
| `invalid value for environment variable "LIN_CACHE_TTL"` | Segundos entre 0 y 300. Si pusiste `20000` pensando en milisegundos, es esto. |

### Al conectar

Todos los fallos llegan al cliente como `FATAL: LIN authentication failed for
user "..."`. El motivo real está en el `DETAIL` del log del servidor:

| DETAIL | Qué significa |
|---|---|
| `rejected ... with HTTP status 401: ...` | La API rechazó las credenciales. |
| `returned "authenticated": false` | La API respondió 2xx pero negó el acceso en el cuerpo. |
| `The "authenticated" field ... is not a boolean` | Tu API devuelve `"true"`, `1` o `null` en vez del booleano. |
| `Could not reach the LIN authentication endpoint ...` | DNS, red, TLS o timeout. El texto de libcurl viene incluido. |
| `The "role" field ... is not a string` | Tu API devuelve el rol con un tipo distinto de cadena. |
| `returned a body that is not valid JSON` | El cuerpo de una respuesta 2xx no se pudo parsear. |
| `returned more than 8192 bytes` | Respuesta demasiado grande; recórtala. |

Y dos que **no** son fallos de LIN:

| Mensaje | Qué significa |
|---|---|
| `role "alex" does not exist` | La API aceptó, pero el rol no está en la base de datos. Ver [El rol tiene que existir](#el-rol-tiene-que-existir). |
| `no pg_hba.conf entry for host ...` | Falta la línea `lin` para esa dirección. |

Para ver qué se está enviando exactamente, sube el detalle del log:

```bash
docker exec linpg psql -U postgres -c "ALTER SYSTEM SET log_connections = 'all'" \
  -c 'SELECT pg_reload_conf()'
```

---

## Archivos que componen el método

| Archivo | Papel |
|---|---|
| `src/backend/libpq/auth-lin.c` | Configuración por entorno, llamada HTTP y parseo de la respuesta. |
| `src/include/libpq/lin.h` | Nombres de las variables, contrato y `USE_LIN_AUTH`. |
| `src/backend/libpq/auth.c` | `CheckLINAuth()`: pide la contraseña y despacha. |
| `src/backend/libpq/hba.c` | Reconoce `lin` en `pg_hba.conf`. |
| `src/include/libpq/hba.h` | `uaLIN` en el enum de métodos. |
| `src/backend/postmaster/postmaster.c` | Valida el entorno al arrancar. |
| `src/backend/utils/init/postinit.c` | Aplica el rol mapeado. |
| `src/include/libpq/libpq-be.h` | Campo `Port.mapped_role`. |
| `src/bin/initdb/initdb.c` | Acepta `--auth-host=lin`. |
| `doc/src/sgml/client-auth.sgml` | Documentación de referencia. |
| `Dockerfile`, `docker/` | Imagen, entrypoint y API falsa de pruebas. |

pgvector no vive en este árbol: la etapa `pgvector` del `Dockerfile` lo clona y
lo compila contra la instalación resultante.

La documentación de referencia completa está en la sección *LIN Authentication*
de `doc/src/sgml/client-auth.sgml`.
