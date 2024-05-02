package com.chrisbone.jwtoauth2jpa.repo;

import com.chrisbone.jwtoauth2jpa.entity.UserInfoEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserInfoRepo extends JpaRepository<UserInfoEntity, Integer> {

    Optional<UserInfoEntity> findByEmailId(String emailId);
}
