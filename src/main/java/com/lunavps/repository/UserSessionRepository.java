package com.lunavps.repository;

import com.lunavps.model.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    Optional<UserSession> findByRefreshToken(String refreshToken);

    void deleteByUserId(Long userId);
}
