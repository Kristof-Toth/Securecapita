package hu.test.securecapita.repositroy;

import hu.test.securecapita.domain.User;
import hu.test.securecapita.dto.UserDTO;
import hu.test.securecapita.form.UpdateForm;

import java.util.Collection;

public interface UserRepositroy<T extends User>  {
    T create(T data);
    Collection<T> list(int page, int pageSize);
    T get(Long id);
    T update(T data);
    Boolean delete(Long id);

    User getUserByEmail(String email);

    void sendVerificationCode(UserDTO user);

    User verifyCode(String email, String code);

    void resetPassword(String email);

    User verifyPasswordKey(String key);

    void renewPassword(String key, String password, String confirmPassword);

    User verifyAccountKey(String key);

    User updateUserDetails(UpdateForm user);

    void updatePassword(Long id, String currentPassword, String newPassword, String confirmNewPassword);
}
