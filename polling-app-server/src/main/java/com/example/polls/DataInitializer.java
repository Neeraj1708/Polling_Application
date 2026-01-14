package com.example.polls;

import com.example.polls.model.Role;
import com.example.polls.model.RoleName;
import com.example.polls.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        // 1. Check if ROLE_USER exists, if not, create it
        Optional<Role> userRole = roleRepository.findByName(RoleName.ROLE_USER);
        if (userRole.isEmpty()) {
            Role role = new Role();
            role.setName(RoleName.ROLE_USER);
            roleRepository.save(role);
            System.out.println("✅ Inserted ROLE_USER into database.");
        }

        // 2. Check if ROLE_ADMIN exists, if not, create it
        Optional<Role> adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN);
        if (adminRole.isEmpty()) {
            Role role = new Role();
            role.setName(RoleName.ROLE_ADMIN);
            roleRepository.save(role);
            System.out.println("✅ Inserted ROLE_ADMIN into database.");
        }
    }
}