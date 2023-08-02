package hu.test.securecapita.repositroy.implementation;

import hu.test.securecapita.domain.Role;
import hu.test.securecapita.domain.User;
import hu.test.securecapita.domain.UserPrincipal;
import hu.test.securecapita.dto.UserDTO;
import hu.test.securecapita.enumeration.VerificationType;
import hu.test.securecapita.exception.ApiException;
import hu.test.securecapita.form.UpdateForm;
import hu.test.securecapita.repositroy.RoleRepository;
import hu.test.securecapita.repositroy.UserRepositroy;
import hu.test.securecapita.rowmapper.UserRowMapper;
import hu.test.securecapita.service.EmailService;
import hu.test.securecapita.utils.SmsUtils;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import static hu.test.securecapita.enumeration.RoleType.ROLE_USER;
import static hu.test.securecapita.enumeration.VerificationType.ACCOUNT;
import static hu.test.securecapita.enumeration.VerificationType.PASSWORD;
import static hu.test.securecapita.query.UserQuery.*;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.util.Arrays.stream;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toList;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.time.DateUtils.addDays;

@Repository
@RequiredArgsConstructor
@Slf4j
public class UserRepositoryImpl implements UserRepositroy<User>, UserDetailsService {
    private static final String DATE_FORMAT = "yyyy-MM-dd hh:mm:ss";
    private final NamedParameterJdbcTemplate jdbc;
    private final RoleRepository<Role> roleRepository;
    private final EmailService emailService;
    private final SmsUtils smsUtils;
    private final BCryptPasswordEncoder encoder;

    @Override
    public User create(User user) {
        // check the email is unique
        if (getEmailCount(user.getEmail().trim().toLowerCase()) > 0)
            throw new ApiException("Email already in use. Please use a different email and try again");
        // save new user
        try {
            KeyHolder holder = new GeneratedKeyHolder();
            SqlParameterSource parameters = getSqlParameterSource(user);
            jdbc.update(INSERT_USER_QUERY, parameters, holder);
            user.setId(requireNonNull(holder.getKey()).longValue());
            // add role to the user
            roleRepository.addRoleToUser(user.getId(), ROLE_USER.name());
            // send verification url
            String verificationUrl = getVerificationUrl(UUID.randomUUID().toString(), ACCOUNT.getType());
            // save url in verification table
            jdbc.update(INSERT_ACCOUNT_VERIFICATION_URL_QUERY, Map.of("userId", user.getId(), "url", verificationUrl));
            // send email to user with verification url
            sendEmail(user.getFirstName(), user.getEmail(), verificationUrl, ACCOUNT);
            user.setEnabled(false);
            user.setNotLocked(true);
            // return the newly created user
            return user;
            // if any errors, throw exception with proper message
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occured. Please try again");
        }
    }

    @Override
    public Collection<User> list(int page, int pageSize) {
        return null;
    }

    @Override
    public User get(Long id) {
        try {
            return jdbc.queryForObject(SELECT_USER_BY_ID_QUERY, Map.of("id", id), new UserRowMapper());
        } catch (EmptyResultDataAccessException exception) {
            throw new ApiException("No user found by id: " + id);
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occured. Please try again");
        }
    }

    @Override
    public User update(User data) {
        return null;
    }

    @Override
    public Boolean delete(Long id) {
        return null;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = getUserByEmail(email);

        if (user == null) {
            log.info("User not found in the database: {}", email);
            throw new UsernameNotFoundException("User not found in the database");
        } else {
            log.info("User found in the database: {}", email);
            return new UserPrincipal(user, roleRepository.getRoleByUserId(user.getId()));
        }
    }

    @Override
    public User getUserByEmail(String email) {
        try {
            User user = jdbc.queryForObject(SELECT_USER_BY_EMAIL_QUERY, Map.of("email", email), new UserRowMapper());
            return user;
        } catch (EmptyResultDataAccessException exception) {
            throw new ApiException("No user found by email: " + email);
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occured. Please try again");
        }
    }

    @Override
    public void sendVerificationCode(UserDTO user) {
        String expirationDate = DateFormatUtils.format(addDays(new Date(), 1), DATE_FORMAT);
        String verificationCode = RandomStringUtils.randomAlphabetic(8).toUpperCase();

        try {
            jdbc.update(DELETE_VERIFICATION_CODE_BY_UER_ID, Map.of("id", user.getId()));
            jdbc.update(INSERT_VERIFICATION_CODE_QUERY, Map.of("userId", user.getId(), "code", verificationCode, "expirationDate", expirationDate));
            //smsUtils.sendSMS(user.getPhone(), "From: SecureCapita \nVerification code\n" + verificationCode);
            log.info("Verification Code: {}", verificationCode);
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occured. Please try again");
        }
    }

    @Override
    public User verifyCode(String email, String code) {
        if (isVerificationCodeExpired(code))
            throw new ApiException("This code has expired. Please login again");
        try {
            User userByCode = jdbc.queryForObject(SELECT_USER_BY_USER_CODE_QUERY, Map.of("code", code), new UserRowMapper());
            User userByEmail = jdbc.queryForObject(SELECT_USER_BY_EMAIL_QUERY, Map.of("email", email), new UserRowMapper());

            if (userByCode.getEmail().equalsIgnoreCase(userByEmail.getEmail())) {
                jdbc.update(DELETE_CODE, Map.of("code", code));
                return userByCode;
            } else {
                throw new ApiException("Code is invalid. Please try again");
            }
        } catch (EmptyResultDataAccessException exception) {
            throw new ApiException("Unable to find record");
        } catch (Exception exception) {
            throw new ApiException("An error occured. Please try again");
        }
    }

    @Override
    public void resetPassword(String email) {
        if (getEmailCount(email.trim().toLowerCase()) <= 0)
            throw new ApiException("There is no account for this email address");

        try {
            String expirationDate = DateFormatUtils.format(addDays(new Date(), 1), DATE_FORMAT);
            User user = getUserByEmail(email);
            String verificationUrl = getVerificationUrl(UUID.randomUUID().toString(), PASSWORD.getType());

            jdbc.update(DELETE_PASSWORD_VERIFICATION_BY_USER_ID_QUERY, Map.of("userId", user.getId()));
            jdbc.update(INSERT_PASSWORD_VERIFICATION_QUERY, Map.of("userId", user.getId(), "url", verificationUrl, "expirationDate", expirationDate));

            sendEmail(user.getFirstName(), email, verificationUrl, PASSWORD);
            log.info("Verification url: {}", verificationUrl);
        } catch (Exception exception) {
            throw new ApiException("An error occured. Please try again");
        }
    }

    @Override
    public User verifyPasswordKey(String key) {
        if (isLinkExpired(key, PASSWORD))
            throw new ApiException("This link has expired. Please reset your password again");
        try {
            User user = jdbc.queryForObject(SELECT_USER_BY_PASSWORD_URL_QUERY, Map.of("url", getVerificationUrl(key, PASSWORD.getType())), new UserRowMapper());
            //jdbc.update(DELETE_USER_FROM_PASSWORD_VERIFICATION, Map.of("id", user.getId()));
            return user;
        } catch (EmptyResultDataAccessException exception) {
            log.error(exception.getMessage());
            throw new ApiException("This link is not valid. Please reset your password again.");
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occured. Please try again");
        }
    }

    @Override
    public void renewPassword(String key, String password, String confirmPassword) {
        if (!password.equals(confirmPassword))
            throw new ApiException("Password dont match. Please try again.");
        try {
            jdbc.update(UPDATE_USER_PASSWORD_BY_URL_QUERY, Map.of("password", encoder.encode(password), "url", getVerificationUrl(key, PASSWORD.getType())));
            jdbc.update(DELETE_VERIFICATION_BY_URL_QUERY, Map.of("url", getVerificationUrl(key, PASSWORD.getType())));
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occured. Please try again");
        }
    }

    @Override
    public void renewPassword(Long userId, String password, String confirmPassword) {
        if (!password.equals(confirmPassword))
            throw new ApiException("Password dont match. Please try again.");
        try {
            jdbc.update(UPDATE_USER_PASSWORD_BY_USER_ID_QUERY, Map.of("userId", userId, "password", encoder.encode(password)));
            //jdbc.update(DELETE_PASSWORD_VERIFICATION_BY_USER_ID_QUERY, Map.of("userId", userId));
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occured. Please try again");
        }
    }

    @Override
    public User verifyAccountKey(String key) {
        try {
            User user = jdbc.queryForObject(SELECT_USER_BY_ACCOUNT_URL_QUERY, Map.of("url", getVerificationUrl(key, ACCOUNT.getType())), new UserRowMapper());
            jdbc.update(UPDATE_USER_ENABLED_QUERY, Map.of("enabled", true, "id", user.getId()));
            return user;
        } catch (EmptyResultDataAccessException exception) {
            throw new ApiException("This link is not valid.");
        } catch (Exception exception) {
            throw new ApiException("An error occured. Please try again");
        }
    }

    @Override
    public User updateUserDetails(UpdateForm user) {
        try {
            jdbc.update(UPDATE_USER_DETAILS_QUERY, getUserDetailsSqlParameterSource(user));
            return get(user.getId());
        } catch (EmptyResultDataAccessException exception) {
            throw new ApiException("No user found by id: " + user.getId());
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occured. Please try again.");
        }
    }

    @Override
    public void updatePassword(Long id, String currentPassword, String newPassword, String confirmNewPassword) {
        if (!newPassword.equals(confirmNewPassword))
            throw new ApiException("Passwords dont match, Please try again");

        User user = get(id);

        if (encoder.matches(currentPassword, user.getPassword())) {
            try {
                jdbc.update(UPDATE_USER_PASSWORD_BY_ID_QUERY, Map.of("userId", id, "password", encoder.encode(newPassword)));
            } catch (Exception exception) {
                log.error(exception.getMessage());
                throw new ApiException("An error occured. Please try again");
            }
        } else
            throw new ApiException("Incorrect current password, Please try again");

    }

    @Override
    public void updateAccountSettings(Long userId, Boolean enabled, Boolean notLocked) {
        try {
            jdbc.update(UPDATE_USER_SETTINGS_QUERY, Map.of("userId", userId, "enabled", enabled, "notLocked", notLocked));
        } catch (Exception exception) {
            throw new ApiException("An error occured. Please try again");
        }
    }

    @Override
    public User toggleMfa(String email) {
        User user = getUserByEmail(email);
        if (isBlank(user.getPhone()))
            throw new ApiException("You need a phone number to change Multi-Factor Authentication");
        user.setUsingMfa(!user.isUsingMfa());
        try {
            jdbc.update(TOGGLE_USER_MFA_QUERY, Map.of("email", email, "isUsingMfa", user.isUsingMfa()));
            return user;
        } catch (Exception exception) {
            throw new ApiException("Unable to update Multi-Factor Authentication");
        }
    }

    @Override
    public void updateImage(UserDTO userDTO, MultipartFile image) {
        String userImageUrl = setUserImageUrl(userDTO.getEmail());
        userDTO.setImageUrl(userImageUrl);
        saveImage(userDTO.getEmail(), image);
        jdbc.update(UPDATE_USER_IMAGE_QUERY, Map.of("imageUrl", userImageUrl, "id", userDTO.getId()));

    }

    private String setUserImageUrl(String email) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/image/" + email + ".png").toUriString();
    }

    private void saveImage(String email, MultipartFile image) {
        Path fileStorageLocation = Paths.get(System.getProperty("user.home") + "/Downloads/images/").toAbsolutePath().normalize();
        if (!Files.exists(fileStorageLocation)) {
            try {
                Files.createDirectories(fileStorageLocation);
            } catch (Exception exception) {
                log.error(exception.getMessage());
                throw new ApiException("Unable to create directories to save image");
            }
            log.info("Created directories: {}", fileStorageLocation);
        }

        try {
            Files.copy(image.getInputStream(), fileStorageLocation.resolve(email + ".png"), REPLACE_EXISTING);
        } catch (IOException exception) {
            throw new ApiException(exception.getMessage());
        }
        log.info("File saved in: {} folder", fileStorageLocation);

    }

    private Boolean isVerificationCodeExpired(String code) {
        try {
            return jdbc.queryForObject(SELECT_CODE_EXPIRATION_QUERY, Map.of("code", code), Boolean.class);
        } catch (EmptyResultDataAccessException exception) {
            throw new ApiException("This code is not valid. Please login again.");
        } catch (Exception exception) {
            throw new ApiException("An error occured. Please try again");
        }
    }

    private Boolean isLinkExpired(String key, VerificationType password) {
        try {
            return jdbc.queryForObject(SELECT_EXPIRATION_BY_URL, Map.of("url", getVerificationUrl(key, PASSWORD.getType())), Boolean.class);
        } catch (EmptyResultDataAccessException exception) {
            log.error(exception.getMessage());
            throw new ApiException("This link is not valid. Please reset your password again.");
        } catch (Exception exception) {
            log.error(exception.getMessage());
            throw new ApiException("An error occured. Please try again");
        }
    }

    private Integer getEmailCount(String email) {
        return jdbc.queryForObject(COUNT_USER_EMAIL_QUERY, Map.of("email", email), Integer.class);
    }

    private SqlParameterSource getSqlParameterSource(User user) {
        return new MapSqlParameterSource()
                .addValue("firstName", user.getFirstName())
                .addValue("lastName", user.getLastName())
                .addValue("email", user.getEmail())
                .addValue("password", encoder.encode(user.getPassword()));
    }

    private SqlParameterSource getUserDetailsSqlParameterSource(UpdateForm user) {
        return new MapSqlParameterSource()
                .addValue("id", user.getId())
                .addValue("firstName", user.getFirstName())
                .addValue("lastName", user.getLastName())
                .addValue("email", user.getEmail())
                .addValue("phone", user.getPhone())
                .addValue("address", user.getAddress())
                .addValue("title", user.getTitle())
                .addValue("bio", user.getBio());
    }

    private String getVerificationUrl(String key, String type) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/verify/" + type + "/" + key).toUriString();
    }

    private void sendEmail(String firstName, String email, String verificationUrl, VerificationType verificationType) {
        CompletableFuture.runAsync(() -> {
            emailService.sendVerificationEmail(firstName, email, verificationUrl, verificationType);
        });
        /*CompletableFuture.runAsync(() -> {
            try {
                emailService.sendVerificationEmail(firstName, email, verificationUrl, verificationType);
            } catch (Exception exception) {
                throw new ApiException("Unable to send email");
            }

        });*/

        /*CompletableFuture<Void> future = CompletableFuture.runAsync(new Runnable() {
            @Override
            public void run() {
                try {
                    emailService.sendVerificationEmail(firstName, email, verificationUrl, verificationType);
                } catch (Exception exception) {
                    throw new ApiException("Unable to send email");
                }
            }
        });*/
    }
}
