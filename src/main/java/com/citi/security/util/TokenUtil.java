package com.citi.security.util;

import java.util.Date;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class TokenUtil {
	// 初始化secret
	@Value("${jwt.secret}")
	private String SECRET;
	// 初始化token 过期时间
	@Value("${jwt.expires_in")
	private Long EXPIRATION;
	@Value("${jwt.cookie}")
	private String AUTH_TOKEN;
	@Value("${jwt.header}")
	private String AUTH_HEADER;

	/**
	 * 从token获取用户名
	 * 
	 * @param token
	 * @return
	 */
	public String getUserNameFromtoken(String token) {
		String username;
		try {
			final Claims claims = getClaimsFormToken(token);
			username = claims.getSubject();

		} catch (Exception e) {
			username = null;
		}
		return username;

	}

	/**
	 * 通过secret 解析出token 中的其中的数据声明
	 * 
	 * @param token
	 * @return
	 */

	private Claims getClaimsFormToken(String token) {
		Claims clamis;
		try {
			clamis = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
		} catch (Exception e) {
			clamis = null;
		}
		return clamis;
	}

	/**
	 * 生成token 其中包含的数据有 数据声明 :通常包含的数据有用户名、token 创建时间和过期时间
	 * 
	 * @param claims
	 * @return
	 */
	public String generateToken(Map<String, Object> claims) {
		return Jwts.builder().setClaims(claims).setExpiration(generateExpirationDate()).signWith(SignatureAlgorithm.HS512, SECRET)
				.compact();
	}

	/**
	 * 生成过期时间
	 * 
	 * @return
	 */
	private Date generateExpirationDate() {
		return new Date(System.currentTimeMillis() + EXPIRATION * 1000);
	}

	private boolean isTokenExpired(String token) {
		final Date expiration = getExpireDateFromToken(token);
		return expiration.before(new Date());
	}

	private Date getExpireDateFromToken(String token) {
		Date expiration;
		try {
			final Claims claims = getClaimsFormToken(token);
			expiration = claims.getExpiration();
		} catch (Exception e) {
			expiration = null;
		}
		return expiration;

	}
	public String getToken(HttpServletRequest request) {
		// 从cookie store中获取token
		Cookie cookie = getCookieValueByName(request, AUTH_TOKEN);
		if (cookie != null) {
			return cookie.getValue();
		}
		//获取请求头
		String header = request.getHeader(AUTH_HEADER);
		if(header!=null&&header.startsWith("Bearer ")) {
			return header.substring(7);
		}
		return null;
	}

	public Cookie getCookieValueByName(HttpServletRequest request, String name) {
		if (request.getCookies() == null) {
			return null;
		}
		for (int i = 0; i < request.getCookies().length; i++) {
			if (request.getCookies()[i].getName().equals(name)) {
				return request.getCookies()[i];
			}
		}
		return null;
	}
}
