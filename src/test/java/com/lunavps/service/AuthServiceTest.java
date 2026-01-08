package com.lunavps.service;

import com.lunavps.dto.AuthDto;
import com.lunavps.model.User;
import com.lunavps.model.UserRole;
import com.lunavps.model.UserSession;
import com.lunavps.repository.UserRepository;
import com.lunavps.repository.UserSessionRepository;
import com.lunavps.utils.JwtUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private UserSessionRepository userSessionRepository;
    @Mock
    private JwtUtils jwtUtils;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private CustomUserDetailsService userDetailsService;

    @InjectMocks
    private AuthService authService;

    private User user;
    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        user = new User();
        user.setId(1L);
        user.setEmail("test@example.com");
        user.setPassword("encodedPassword");
        user.setRole(UserRole.USER);
        user.setActive(true);

        userDetails = org.springframework.security.core.userdetails.User
                .withUsername("test@example.com")
                .password("encodedPassword")
                .roles("USER")
                .build();
    }

    @Test
    void login_Success() {
        AuthDto.LoginRequest request = new AuthDto.LoginRequest("test@example.com", "password");

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(user));
        when(userDetailsService.loadUserByUsername(request.getEmail())).thenReturn(userDetails);
        when(jwtUtils.generateToken(userDetails)).thenReturn("accessToken");
        when(jwtUtils.generateRefreshToken(userDetails)).thenReturn("refreshToken");

        AuthDto.LoginResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("accessToken", response.getAccessToken());
        assertEquals("refreshToken", response.getRefreshToken());

        verify(authenticationManager).authenticate(any());
        verify(userSessionRepository).save(any(UserSession.class));
    }

    @Test
    void refreshToken_Success() {
        String refreshToken = "validRefreshToken";
        AuthDto.RefreshTokenRequest request = new AuthDto.RefreshTokenRequest(refreshToken);

        UserSession userSession = new UserSession();
        userSession.setUser(user);
        userSession.setRefreshToken(refreshToken);
        userSession.setExpiredAt(LocalDateTime.now().plusDays(1));

        when(userSessionRepository.findByRefreshToken(refreshToken)).thenReturn(Optional.of(userSession));
        when(userDetailsService.loadUserByUsername(user.getEmail())).thenReturn(userDetails);
        when(jwtUtils.isTokenValid(refreshToken, userDetails)).thenReturn(true);
        when(jwtUtils.generateToken(userDetails)).thenReturn("newAccessToken");
        when(jwtUtils.generateRefreshToken(userDetails)).thenReturn("newRefreshToken");

        AuthDto.LoginResponse response = authService.refreshToken(request);

        assertNotNull(response);
        assertEquals("newAccessToken", response.getAccessToken());
        assertEquals("newRefreshToken", response.getRefreshToken());

        verify(userSessionRepository).delete(userSession);
        verify(userSessionRepository).save(any(UserSession.class));
    }

    @Test
    void login_BadCredentials() {
        AuthDto.LoginRequest request = new AuthDto.LoginRequest("test@example.com", "wrongpassword");

        doThrow(new org.springframework.security.authentication.BadCredentialsException("Bad credentials"))
                .when(authenticationManager).authenticate(any());

        assertThrows(org.springframework.security.authentication.BadCredentialsException.class,
                () -> authService.login(request));

        verify(authenticationManager).authenticate(any());
        verify(userRepository, never()).findByEmail(anyString());
    }

    @Test
    void refreshToken_InvalidToken() {
        String refreshToken = "invalidToken";
        AuthDto.RefreshTokenRequest request = new AuthDto.RefreshTokenRequest(refreshToken);

        when(userSessionRepository.findByRefreshToken(refreshToken)).thenReturn(Optional.empty());

        Exception exception = assertThrows(RuntimeException.class, () -> authService.refreshToken(request));
        assertEquals("Invalid refresh token", exception.getMessage());
    }

    @Test
    void refreshToken_Expired() {
        String refreshToken = "expiredRefreshToken";
        AuthDto.RefreshTokenRequest request = new AuthDto.RefreshTokenRequest(refreshToken);

        UserSession userSession = new UserSession();
        userSession.setUser(user);
        userSession.setRefreshToken(refreshToken);
        userSession.setExpiredAt(LocalDateTime.now().minusDays(1)); // Expired

        when(userSessionRepository.findByRefreshToken(refreshToken)).thenReturn(Optional.of(userSession));

        Exception exception = assertThrows(RuntimeException.class, () -> authService.refreshToken(request));
        assertEquals("Refresh token expired", exception.getMessage());

        verify(userSessionRepository).delete(userSession);
        verify(userSessionRepository, never()).save(any(UserSession.class));
    }
}
