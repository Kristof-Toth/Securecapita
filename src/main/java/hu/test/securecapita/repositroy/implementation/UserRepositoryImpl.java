package hu.test.securecapita.repositroy.implementation;

import hu.test.securecapita.domain.Role;
import hu.test.securecapita.domain.User;
import hu.test.securecapita.exception.ApiException;
import hu.test.securecapita.repositroy.RoleRepository;
import hu.test.securecapita.repositroy.UserRepositroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.Collection;
import java.util.Map;
import java.util.UUID;

import static hu.test.securecapita.enumeration.RoleType.ROLE_USER;
import static hu.test.securecapita.enumeration.VerificationType.ACCOUNT;
import static hu.test.securecapita.query.UserQuery.*;
import static java.util.Objects.requireNonNull;

@Repository
@RequiredArgsConstructor
@Slf4j
public class UserRepositoryImpl implements UserRepositroy<User> {

    private final NamedParameterJdbcTemplate jdbc;
    private final RoleRepository<Role> roleRepository;
    private final BCryptPasswordEncoder encoder;

    @Override
    public User create(User user) {
        // check the email is unique
        if (getEmailCount(user.getEmail().trim().toLowerCase()) > 0) throw new ApiException("Email already in use. Please use a different email and try again");
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
            //emailService.sendVerificationUrl(user.getEmail(), verificationUrl, ACCOUNT);
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
        return null;
    }

    @Override
    public User update(User data) {
        return null;
    }

    @Override
    public Boolean delete(Long id) {
        return null;
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

    private String getVerificationUrl(String key, String type){
        //return ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/verify/" + type + "/" + key).toUriString();
        return ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/verify/" + type + "/" + key).toUriString();

    }
}
