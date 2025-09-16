# vc-issuer
Issue WC3 Verifiable Credential.

Get access token
```
curl -X POST http://localhost:8080/oauth2/token \
 -d "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
 -d "pre-authorized_code=PREAUTH-123"

{"access_token":"<access_token>","token_type":"Bearer","expires_in":600,"scope":"credential:issue"}%
```
Issuing a VC
```
curl -X POST http://localhost:8080/credential \
 -H "Authorization: Bearer access_token" \
 -H "Content-Type: application/json" \
 -d '{"format":"jwt_vc_json","types":["VerifiableCredential","UniversityID"]}'

 {"format":"jwt_vc_json","credential":"<credential>"}
```
Use vc-verifier to verify
