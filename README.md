lila-pwned
==========

Webservice to query https://haveibeenpwned.com/ database dumps.

Usage
-----

Import a database dump:

```
cargo run --release -- --source pwned-passwords-sha1-ordered-by-hash-v8.txt
```

For local testing, `test.txt` contains the single password `test`.

Serve:

```
cargo run --release -- --bind 127.0.0.1:1337
```

HTTP API
--------

### `GET /`

```
curl http://localhost:1337/?sha1=a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
```

name | type | description
--- | --- | ---
sha1 | string | Hash of the password to look up

* `200 OK`

  ```javascript
  {
    "n": 86495 // seen in 86495 leaks
  }
  ```

### `GET /status`

```
curl http://localhost:1337/status
```

* `200 OK`

  ```
  pwned count=847223402u
  ```

License
-------

lila-pwned is licensed under the GNU Affero General Public License,
version 3 or any later version, at your option.
