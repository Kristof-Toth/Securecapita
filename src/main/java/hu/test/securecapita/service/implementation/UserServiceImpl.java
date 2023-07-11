package hu.test.securecapita.service.implementation;

import hu.test.securecapita.domain.User;
import hu.test.securecapita.dto.UserDTO;
import hu.test.securecapita.dtomapper.UserDTOMapper;
import hu.test.securecapita.repositroy.UserRepositroy;
import hu.test.securecapita.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepositroy<User> userUserRepositroy;

    @Override
    public UserDTO createUser(User user) {
        return UserDTOMapper.fromUser(userUserRepositroy.create(user));
    }
}
