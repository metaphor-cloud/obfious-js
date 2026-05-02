# Changelog

## 0.4.0 - Obfious Protocol v2.7

- When `protect()` is called with a `user` argument and `privateKey` is set, the validate
  request now includes an `encryptedUserMac` field alongside `encryptedUser`. The MAC is
  `HMAC-SHA256(secret, tokenHex + "." + encryptedUser)` and lets the server verify the tag
  was produced by a legitimate proxy before inserting it. Backward compatible: the server
  accepts requests without the MAC (existing deployments require no changes).

## 0.3.0 - Obfious Protocol v2.6

- `includePaths` and `excludePaths` accept method-qualified entries of the form
  `"METHOD:/path"` (e.g. `"POST:/api/checkout"`, `"GET:/health"`). The colon
  must appear within the first 8 characters and the prefix must be one of
  `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS` (case-insensitive,
  normalised to uppercase). Anything else is treated as a plain prefix, so
  `"foo:/bar"` still matches the literal path `"foo:/bar"`. Plain entries
  continue to match any request method.
- Exported a `parsePathShorthand(input)` helper that returns
  `{ path, method? }` for callers that need to inspect entries directly.

## 0.2.5 - Obfious Protocol v2.5

Tracks the Obfious Protocol v2.5 release; no public consumer-API changes
in this package.
