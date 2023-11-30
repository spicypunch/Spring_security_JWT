package com.example.demo.common.authority

import com.example.demo.common.dto.CustomUser
import io.jsonwebtoken.*
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SecurityException
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import java.util.*

const val ACCESS_TOKEN_EXPIRATION_MILLISECONDS: Long = 1000 * 60 * 60 * 24
const val REFRESH_TOKEN_EXPIRATION_MILLISECONDS: Long = 1000 * 60 * 60 * 24 * 15

@Component
class JwtTokenProvider {
    @Value("\${jwt.secret}")
    lateinit var secretKey: String

    private val key by lazy { Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey)) }

    /**
     * Token 생성
     */
    fun createAccessToken(authentication: Authentication): TokenInfo {
        val authorities: String = authentication
                .authorities
                .joinToString(",", transform = GrantedAuthority::getAuthority)

        val now = Date()
        val accessException = Date(now.time + ACCESS_TOKEN_EXPIRATION_MILLISECONDS)

        // Access Token
        val accessToken = Jwts
                .builder()
                .setSubject(authentication.name)
                .claim("auth", authorities)
                .claim("userId", (authentication.principal as CustomUser).userId)
                .setIssuedAt(now)
                .setExpiration(accessException)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact()

        return TokenInfo("Bearer", accessToken)
    }

    /**
     * Token 정보 추출
     */
    fun getAuthentication(token: String): Authentication {
        val claims: Claims = getClaims(token)

        val auth = claims["auth"] ?: throw RuntimeException("잘못된 토큰입니다.")
        val userId = claims["userId"] ?: throw RuntimeException("잘못된 토큰입니다.")

        val authorities: Collection<GrantedAuthority> = (auth as String)
                .split(",")
                .map { SimpleGrantedAuthority(it) }
        val principal: UserDetails = CustomUser(userId.toString().toLong(), claims.subject, "", authorities)

        return UsernamePasswordAuthenticationToken(principal, "", authorities)
    }

    /**
     * Token 검증
     */
    fun validateToken(token: String): Boolean {
        try {
            getClaims(token)
            return true
        } catch (e: Exception) {
            when (e) {
                is SecurityException -> {} // Invalid JWT Token
                is MalformedJwtException -> {} // Invalid JWT Token
                is ExpiredJwtException -> {} // Invalid JWT Token
                is UnsupportedJwtException -> {} // Unsupported JWT Token
                is IllegalArgumentException -> {} // JWT claims string is empty
                else -> {}
            }
            println(e.message)
        }
        return false
    }

    private fun getClaims(token: String): Claims =
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .body

    fun createRefreshToken(userId: Long): String {
        val now = Date()
        val expiration = Date(now.time + REFRESH_TOKEN_EXPIRATION_MILLISECONDS)

        return Jwts
                .builder()
                .setSubject(userId.toString())
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(key)
                .compact()
    }

    fun getRefreshToken(userId: Long): String {
        return createRefreshToken(userId)
    }

    fun validateRefreshToken(token: String): Boolean {
        return try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token)
            true
        } catch (e: Exception) {
            false
        }
    }

    fun extractUserIdFromRefreshToken(token: String): Long {
        val claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).body
        return claims.subject.toLong()
    }
}