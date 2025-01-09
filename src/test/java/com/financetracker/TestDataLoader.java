package com.financetracker;


import com.financetracker.model.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import com.financetracker.repository.UserRepository;

@Component
public class TestDataLoader implements CommandLineRunner {

    private final UserRepository userRepository;

    public TestDataLoader(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void run(String... args) throws Exception {
        User user = new User();
        user.setEmail("test@example.com");
        user.setPassword("password");
        userRepository.save(user);

        System.out.println("Test user created!");
    }
}
