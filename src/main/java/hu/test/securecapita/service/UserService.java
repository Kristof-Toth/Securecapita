package hu.test.securecapita.service;

import hu.test.securecapita.domain.User;
import hu.test.securecapita.dto.UserDTO;

public interface UserService {
    UserDTO createUser(User user);

}
