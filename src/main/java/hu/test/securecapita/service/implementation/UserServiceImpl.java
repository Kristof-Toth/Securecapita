package hu.test.securecapita.service.implementation;

import hu.test.securecapita.domain.Role;
import hu.test.securecapita.domain.User;
import hu.test.securecapita.dto.UserDTO;
import hu.test.securecapita.dtomapper.UserDTOMapper;
import hu.test.securecapita.repositroy.RoleRepository;
import hu.test.securecapita.repositroy.UserRepositroy;
import hu.test.securecapita.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepositroy<User> userRepository;
    private final RoleRepository<Role> roleRepository;

    @Override
    public UserDTO createUser(User user) {
        return mapToUserDTO(userRepository.create(user));
    }

    @Override
    public UserDTO getUserByEmail(String email) {
        return mapToUserDTO(userRepository.getUserByEmail(email));
    }

    @Override
    public void sendVerificationCode(UserDTO user) {
        userRepository.sendVerificationCode(user);
    }

    @Override
    public UserDTO verifyCode(String email, String code) {
        return mapToUserDTO(userRepository.verifyCode(email, code));
    }

    private UserDTO mapToUserDTO(User user){
        return UserDTOMapper.fromUser(user, roleRepository.getRoleByUserId(user.getId()));
    }
}
