package com.example.social.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserRegistrationService {
    private final UserFindService userFindService;
    private final UserRepository userRepository;

    public void requestRegistration(final String name, final String email){
        boolean exists = userFindService.existsUserByEmail(email);
        if (!exists) {
            final User user = new User(name, email);
            userRepository.save(user);
        }
    }
}
