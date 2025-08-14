package com.resourcemanagement.gateway.blacklisteds.repository;

import com.resourcemanagement.gateway.blacklisteds.BlacklistedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, Long> {

    boolean existsByToken(String token);

}