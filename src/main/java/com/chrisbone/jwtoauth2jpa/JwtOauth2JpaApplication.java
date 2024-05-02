package com.chrisbone.jwtoauth2jpa;

import com.chrisbone.jwtoauth2jpa.config.RSAKeyRecord;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RSAKeyRecord.class)
public class JwtOauth2JpaApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtOauth2JpaApplication.class, args);
	}

}
