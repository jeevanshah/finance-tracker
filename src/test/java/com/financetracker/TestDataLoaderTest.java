package com.financetracker;


import com.financetracker.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import com.financetracker.repository.UserRepository;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
public class TestDataLoaderTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    public void testLoadTestData() {
        // Check if the test user is present in the database
        Optional<User> user = userRepository.findByUsername("test@example.com");
        assertThat(user).isPresent();
        assertThat(user.get().getEmail()).isEqualTo("test@example.com");
        assertThat(user.get().getPassword()).isEqualTo("password");
    }
}
