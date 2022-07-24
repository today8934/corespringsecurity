package io.security.corespringsecurity.service.impl;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.repository.UserRepository;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userService")
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
        log.info("age={}, email={}, password={}, role={}, username={}, id={}",
                account.getAge(),
                account.getEmail(),
                account.getPassword(),
                account.getRole(),
                account.getUsername(),
                account.getId());
    }
}
