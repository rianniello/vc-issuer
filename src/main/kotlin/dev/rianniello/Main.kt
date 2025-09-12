package dev.rianniello

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.http.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.serialization.jackson.*
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import java.time.Instant
import java.util.*

import com.nimbusds.jose.*
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT

fun main() {
    embeddedServer(Netty, port = 8080) { module() }.start(wait = true)
}

fun Application.module() {
    install(ContentNegotiation) {
        jackson { registerKotlinModule() }
    }

    val issuerBase = "https://issuer.example.com" // change to your public base URL
    val credentialType = "UniversityID"           // example credential type
    val accessTokens = mutableMapOf<String, String>() // token -> subjectDid/Jwk/subjectId
    val preAuthCodes = mutableMapOf<String, String>() // preAuthorizedCode -> subject

    // Seed a pre-authorized code for testing (normally you'd generate per user/session)
    preAuthCodes["PREAUTH-123"] = "did:example:holder123" // subject (holder DID or sub identifier)

    // ---------- Signing keys & JWKS ----------
    val rsaJwk: RSAKey = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE)
        .algorithm(JWSAlgorithm.RS256)
        .keyID(UUID.randomUUID().toString())
        .generate()
    val jwkSet = JWKSet(rsaJwk) // contains private; publish public below
    val publicJwkSet = JWKSet(rsaJwk.toPublicJWK())

    routing {
        // --- 1) Issuer metadata (OID4VCI) ---
        get("/.well-known/openid-credential-issuer") {
            // Minimal example; extend as needed
            val metadata = mapOf(
                "credential_issuer" to issuerBase,
                "token_endpoint" to "$issuerBase/oauth2/token",
                "credential_endpoint" to "$issuerBase/credential",
                "jwks_uri" to "$issuerBase/.well-known/jwks.json",
                "credentials_supported" to listOf(
                    mapOf(
                        "format" to "jwt_vc_json",
                        "types" to listOf("VerifiableCredential", credentialType)
                    )
                )
            )
            call.respond(metadata)
        }

        // --- 2) JWKS (public keys) ---
        get("/.well-known/jwks.json") {
            call.respond(publicJwkSet.toJSONObject())
        }

        // --- 3) OAuth2 token endpoint with pre-authorized_code grant (OID4VCI) ---
        post("/oauth2/token") {
            val form = call.receiveParameters()
            val grantType = form["grant_type"]
            val preCode = form["pre-authorized_code"]
            val userPin = form["user_pin"] // optional, if you configured it

            if (grantType != "urn:ietf:params:oauth:grant-type:pre-authorized_code" || preCode == null) {
                call.respond(HttpStatusCode.BadRequest, mapOf("error" to "unsupported_grant_type"))
                return@post
            }

            val subject = preAuthCodes.remove(preCode)
            if (subject == null) {
                call.respond(HttpStatusCode.BadRequest, mapOf("error" to "invalid_grant"))
                return@post
            }
            // (If you require a PIN, verify userPin here)

            val token = "atk_" + UUID.randomUUID()
            accessTokens[token] = subject

            call.respond(
                mapOf(
                    "access_token" to token,
                    "token_type" to "Bearer",
                    "expires_in" to 600,
                    "scope" to "credential:issue"
                )
            )
        }

        // --- 4) Credential endpoint: returns signed JWT-VC (OID4VCI) ---
        post("/credential") {
            // 4a) Check bearer token
            val auth = call.request.headers["Authorization"] ?: ""
            if (!auth.startsWith("Bearer ")) {
                call.respond(HttpStatusCode.Unauthorized, mapOf("error" to "invalid_token"))
                return@post
            }
            val token = auth.removePrefix("Bearer ").trim()
            val subject = accessTokens[token]
            if (subject == null) {
                call.respond(HttpStatusCode.Unauthorized, mapOf("error" to "invalid_token"))
                return@post
            }

            // 4b) (Optional) parse body to respect requested format/type
            val req = runCatching { call.receive<CredentialRequest>() }.getOrNull()

            // 4c) Build a JWT-VC
            val now = Instant.now()
            val exp = now.plusSeconds(60 * 60) // 1 hour
            val jti = UUID.randomUUID().toString()

            // "vc" claim per JWT-VC (W3C VC Data Model)
            val vcClaim = mapOf(
                "@context" to listOf(
                    "https://www.w3.org/2018/credentials/v1"
                ),
                "type" to listOf("VerifiableCredential", credentialType),
                "credentialSubject" to mapOf(
                    "id" to subject,
                    "studentId" to "S1234567",
                    "givenName" to "Ada",
                    "familyName" to "Lovelace",
                    "status" to "active"
                )
            )

            val claims = JWTClaimsSet.Builder()
                .issuer("$issuerBase/issuer") // your logical issuer ID (could be a DID)
                .subject(subject)            // holder binding (can be DID or other subject ID)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(exp))
                .jwtID(jti)
                .claim("nbf", now.epochSecond)
                .claim("vc", vcClaim)
                .build()

            val signer = RSASSASigner(rsaJwk.toPrivateKey())
            val header = JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaJwk.keyID)
                .type(JOSEObjectType("JWT"))
                .build()

            val signedJWT = SignedJWT(header, claims).apply { sign(signer) }
            val jwtVc = signedJWT.serialize()

            // 4d) OID4VCI credential_response
            call.respond(
                mapOf(
                    "format" to (req?.format ?: "jwt_vc_json"),
                    "credential" to jwtVc
                )
            )
        }
    }
}

// ---------- DTOs ----------
data class CredentialRequest(
    val format: String? = null,
    val types: List<String>? = null,
    val proof: Proof? = null
)

data class Proof(
    val proof_type: String? = null,
    val jwt: String? = null
)
