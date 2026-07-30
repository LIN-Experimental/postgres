PostgreSQL para LIN Cloud
=========================

Este repositorio es un **fork de PostgreSQL** (rama de desarrollo, `20devel`)
con dos añadidos:

* **Autenticación contra LIN Cloud.** Un método de autenticación nuevo,
  `lin`, que verifica las contraseñas contra la API REST de LIN Cloud en lugar
  de contra `pg_authid`. Se configura íntegramente con variables de entorno, de
  modo que una instancia se pueda desplegar con lo que ya ofrecen Docker,
  Kubernetes o cualquier plataforma capaz de inyectarlas. La API puede además
  devolver el rol que debe asumir la conexión, lo que permite mapear muchos
  usuarios finales sobre unos pocos roles de base de datos sin mantener un rol
  por persona.

* **pgvector.** La imagen de Docker incluye
  [pgvector](https://github.com/pgvector/pgvector) compilado contra este mismo
  árbol, con los tipos `vector`, `halfvec` y `sparsevec`, los operadores de
  distancia y los índices HNSW e IVFFlat. La extensión no forma parte del código
  fuente de este repositorio: se compila desde su propio origen durante la
  construcción de la imagen.

Todo lo demás es PostgreSQL sin modificar.

Cómo empezar
------------

**[README-LIN.md](README-LIN.md)** es la guía práctica: cómo compilar el
proyecto, cómo generar la imagen de Docker `linplatform/postgres`, las
variables de entorno, el contrato de la API de autenticación, cómo usar
pgvector y una tabla de problemas comunes.

En resumen:

```bash
docker build -t linplatform/postgres .

docker run -d --name pg -p 5432:5432 \
  -e LIN_TENANT=empresa-001 \
  -e LIN_AUTH_ENDPOINT=https://auth.miempresa.com/api/auth/login \
  linplatform/postgres
```

La documentación de referencia del método `lin` está en la sección *LIN
Authentication* de `doc/src/sgml/client-auth.sgml`, junto al resto de los
métodos de autenticación de PostgreSQL.

Sobre PostgreSQL
----------------

PostgreSQL es un sistema gestor de bases de datos objeto-relacional avanzado
que soporta un subconjunto extendido del estándar SQL, incluyendo
transacciones, claves ajenas, subconsultas, disparadores, y tipos y funciones
definidos por el usuario. Esta distribución contiene también los bindings para
el lenguaje C.

La información de copyright y licencia está en el archivo COPYRIGHT.

La documentación general de esta versión de PostgreSQL está en
<https://www.postgresql.org/docs/devel/>. En particular, la información sobre
cómo compilar PostgreSQL desde el código fuente está en
<https://www.postgresql.org/docs/devel/installation.html>.

La última versión de este software, y del software relacionado, puede
obtenerse en <https://www.postgresql.org/download/>. Para más información,
consulta el sitio web en <https://www.postgresql.org/>.
