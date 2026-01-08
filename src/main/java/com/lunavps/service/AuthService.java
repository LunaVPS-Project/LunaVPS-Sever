package com.lunavps.service;

import com.lunavps.dto.AuthDto;
import com.lunavps.model.User;
import com.lunavps.model.UserSession;
import com.lunavps.repository.UserRepository;
import com.lunavps.repository.UserSessionRepository;
import com.lunavps.utils.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final UserSessionRepository userSessionRepository;
    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;

    public AuthDto.LoginResponse login(AuthDto.LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        var userDetails = userDetailsService.loadUserByUsername(user.getEmail());

        var accessToken = jwtUtils.generateToken(userDetails);
        var refreshToken = jwtUtils.generateRefreshToken(userDetails);

        saveUserSession(user, refreshToken);

        return AuthDto.LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void saveUserSession(User user, String refreshToken) {
        var validUserSession = new UserSession();
        validUserSession.setUser(user);
        validUserSession.setRefreshToken(refreshToken);
        validUserSession.setExpiredAt(LocalDateTime.now().plusDays(7));
        userSessionRepository.save(validUserSession);
    }

    public AuthDto.LoginResponse refreshToken(AuthDto.RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        UserSession userSession = userSessionRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (userSession.getExpiredAt().isBefore(LocalDateTime.now())) {
            userSessionRepository.delete(userSession);
            throw new RuntimeException("Refresh token expired");
        }

        User user = userSession.getUser();
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());

        if (!jwtUtils.isTokenValid(refreshToken, userDetails)) {
            throw new RuntimeException("Invalid refresh token signature");
        }

        String newAccessToken = jwtUtils.generateToken(userDetails);
        String newRefreshToken = jwtUtils.generateRefreshToken(userDetails);

        userSessionRepository.delete(userSession);
        saveUserSession(user, newRefreshToken);

        return AuthDto.LoginResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();
    }

}
