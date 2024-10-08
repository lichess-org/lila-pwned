lila-pwned
==========

Webservice to query https://haveibeenpwned.com/ database dumps.

Usage
-----

Download a database dump using [haveibeenpwned-downloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)
and import it:

```
haveibeenpwned-downloader pwned-passwords-sha1-ordered-by-hash-v8 -p 64
cargo run --release -- --source pwned-passwords-sha1-ordered-by-hash-v8.txt --compact
```

For local testing, `test.txt` contains the single password `test`.

Serve:

```
cargo run --release -- --bind 127.0.0.1:1337 --upstream-update
```

With the `--upstream-update` flag, entries are slowly but continuously updated
from the upstream API (about 1 month for a full update cycle).

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
