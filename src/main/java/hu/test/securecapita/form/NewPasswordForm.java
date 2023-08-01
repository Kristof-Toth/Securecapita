package hu.test.securecapita.form;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class NewPasswordForm {
    @NotNull(message = "ID cannot be null or empty")
    private Long userId;
    @NotNull(message = "Password cannot be null or empty")
    private String password;
    @NotNull(message = "Confirm password cannot be null or empty")
    private String confirmPassword;
}
