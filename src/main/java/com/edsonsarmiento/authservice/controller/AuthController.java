package com.edsonsarmiento.authservice.controller;

import com.edsonsarmiento.authservice.request.AuthRequest;
import com.edsonsarmiento.authservice.request.TokenRefreshRequest;
import com.edsonsarmiento.authservice.response.AuthResponse;
import com.edsonsarmiento.authservice.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest) throws Exception {
        try{
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getEmail(),authRequest.getPassword())
            );
        }catch (BadCredentialsException e){
            throw new BadCredentialsException("Credenciales incorrectas o usuario desactivado", e);
        }
        final UserDetails user = userDetailsService.loadUserByUsername(authRequest.getEmail());
        final String token = jwtUtil.generateToken(user);
        return ResponseEntity.ok(new AuthResponse(token));
    }

    @PostMapping("/token-refresh")
    public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest tokenRefreshRequest) throws Exception {
        String token = tokenRefreshRequest.getToken();

        try {
            String email = jwtUtil.extractUsername(token);
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            if (jwtUtil.validateToken(token, userDetails)) {
                String newToken = jwtUtil.generateToken(userDetails);
                return ResponseEntity.ok(new AuthResponse(newToken));
            }else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token invalido o expirado");
            }

        }catch (ExpiredJwtException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token expirado");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token invalido");
        }
    }
}
