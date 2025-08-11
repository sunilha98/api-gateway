package com.resourcemanagement.gateway.blacklisteds.service;

import com.resourcemanagement.gateway.blacklisteds.repository.BlacklistedTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class BlacklistedTokenService {

    @Autowired
    private BlacklistedTokenRepository repository;

    public boolean isBlacklisted(String token) {
        return repository.existsByToken(token);
    }
}