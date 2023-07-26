package hu.test.securecapita.resource;

import hu.test.securecapita.domain.HttpResponse;
import hu.test.securecapita.domain.User;
import hu.test.securecapita.domain.UserPrincipal;
import hu.test.securecapita.dto.UserDTO;
import hu.test.securecapita.dtomapper.UserDTOMapper;
import hu.test.securecapita.enumeration.EventType;
import hu.test.securecapita.event.NewUserEvent;
import hu.test.securecapita.exception.ApiException;
import hu.test.securecapita.form.LoginForm;
import hu.test.securecapita.form.SettingsForm;
import hu.test.securecapita.form.UpdateForm;
import hu.test.securecapita.form.UpdatePasswordForm;
import hu.test.securecapita.provider.TokenProvider;
import hu.test.securecapita.service.EventService;
import hu.test.securecapita.service.RoleService;
import hu.test.securecapita.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import jakarta.validation.Valid;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.Map;

import static hu.test.securecapita.enumeration.EventType.*;
import static hu.test.securecapita.utils.ExceptionUtils.processError;
import static hu.test.securecapita.utils.UserUtils.getAuthentication;
import static hu.test.securecapita.utils.UserUtils.getLoggedInUser;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.IMAGE_PNG_VALUE;


@RestController
@RequestMapping(path = "/user")
@RequiredArgsConstructor
public class UserResource {
    private static final String TOKEN_PREFIX = "Bearer ";
    private final UserService userService;
    private final RoleService roleService;
    private final EventService eventService;
    private final AuthenticationManager authenticationManager;
    private final TokenProvider tokenProvider;
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private final ApplicationEventPublisher publisher;

    @PostMapping("/login")
    public ResponseEntity<HttpResponse> login(@RequestBody @Valid LoginForm loginForm){
        UserDTO userDTO = authenticate(loginForm.getEmail(), loginForm.getPassword());
        return userDTO.isUsingMfa() ? sendVerificationCode(userDTO) : sendResponse(userDTO);
    }

    @PostMapping("/register")
    public ResponseEntity<HttpResponse> saveUser(@RequestBody @Valid User user){
        UserDTO userDto = userService.createUser(user);
        return ResponseEntity.created(getUri()).body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", userDto))
                        .message("User created")
                        .status(HttpStatus.CREATED)
                        .statusCode(HttpStatus.CREATED.value())
                        .build()
        );
    }

    @GetMapping("/profile")
    public ResponseEntity<HttpResponse> profile(Authentication authentication){
        UserDTO user = userService.getUserByEmail(getAuthentication(authentication).getEmail());
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", user, "events", eventService.getEventsByUserId(user.getId()), "roles", roleService.getRoles()))
                        .message("Profile Retrieved")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @PatchMapping("/update")
    public ResponseEntity<HttpResponse> updateUser(@RequestBody @Valid UpdateForm user){
        UserDTO updatedUser = userService.updateUserDetails(user);
        publisher.publishEvent(new NewUserEvent(updatedUser.getEmail(), PROFILE_UPDATE));
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", updatedUser, "events", eventService.getEventsByUserId(user.getId()), "roles", roleService.getRoles()))
                        .message("User updated")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @GetMapping("/resetpassword/{email}")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email") String email) {
        userService.resetPassword(email);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .message("Email sent. Please check your email to reset your password.")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @GetMapping("/verify/password/{key}")
    public ResponseEntity<HttpResponse> verifyPasswordUrl(@PathVariable("key") String key) {
        UserDTO user = userService.verifyPasswordKey(key);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", user))
                        .message("Please enter a new password")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @PostMapping("/resetpassword/{key}/{password}/{confirmPassword}")
    public ResponseEntity<HttpResponse> resetPasswordWithKey(@PathVariable("key") String key, @PathVariable("password") String password,
                                                          @PathVariable("confirmPassword") String confirmPassword) {
        userService.renewPassword(key, password, confirmPassword);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .message("Password reset successfully")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @RequestMapping("/error")
    public ResponseEntity<HttpResponse> handleError(HttpServletRequest request){
        return new ResponseEntity<>(HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .reason("There is no mapping for a " + request.getMethod() + " request for this path on the server")
                        .status(HttpStatus.NOT_FOUND)
                        .statusCode(HttpStatus.NOT_FOUND.value())
                        .build(), HttpStatus.NOT_FOUND);
    }

    @GetMapping("/verify/code/{email}/{code}")
    public ResponseEntity<HttpResponse> verifyCode(@PathVariable("email") String email, @PathVariable("code") String code){
        UserDTO userDTO = userService.verifyCode(email, code);
        publisher.publishEvent(new NewUserEvent(userDTO.getEmail(), LOGIN_ATTEMPT_SUCCESS));
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", userDTO, "access_token", tokenProvider.createAccessToken(getUserPrincipal(userDTO)),
                                "refresh_token", tokenProvider.createRefreshToken(getUserPrincipal(userDTO))))
                        .message("Login Success")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @GetMapping("/verify/account/{key}")
    public ResponseEntity<HttpResponse> verifyAccount(@PathVariable("key") String key){
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .message(userService.verifyAccountKey(key).isEnabled() ? "Account already verified" : "Account verified")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @PatchMapping("/update/password")
    public ResponseEntity<HttpResponse> updatePassword(Authentication authentication, @RequestBody @Valid UpdatePasswordForm form){
        UserDTO userDTO = getAuthentication(authentication);
        userService.updatePassword(userDTO.getId(), form.getCurrentPassword(), form.getNewPassword(), form.getConfirmNewPassword());
        publisher.publishEvent(new NewUserEvent(userDTO.getEmail(), PASSWORD_UPDATE));
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", userService.getUserById(userDTO.getId()), "events", eventService.getEventsByUserId(userDTO.getId()), "roles", roleService.getRoles()))
                        .message("Password updated successfully")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @PatchMapping("/update/role/{roleName}")
    public ResponseEntity<HttpResponse> updateRole(Authentication authentication, @PathVariable("roleName") String roleName){
        UserDTO userDTO = getAuthentication(authentication);
        userService.updateUserRole(userDTO.getId(), roleName);
        publisher.publishEvent(new NewUserEvent(userDTO.getEmail(), ROLE_UPDATE));
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", userService.getUserById(userDTO.getId()), "events", eventService.getEventsByUserId(userDTO.getId()), "roles", roleService.getRoles()))
                        .message("Role updated successfully")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @PatchMapping("/update/settings")
    public ResponseEntity<HttpResponse> updateAccountSetting(Authentication authentication, @RequestBody @Valid SettingsForm form){
        UserDTO userDTO = getAuthentication(authentication);
        userService.updateAccountSettings(userDTO.getId(), form.getEnabled(), form.getNotLocked());
        publisher.publishEvent(new NewUserEvent(userDTO.getEmail(), ACCOUNT_SETTINGS_UPDATE));
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", userService.getUserById(userDTO.getId()), "events", eventService.getEventsByUserId(userDTO.getId()), "roles", roleService.getRoles()))
                        .message("Account settings updated successfully")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @PatchMapping("/togglemfa")
    public ResponseEntity<HttpResponse> toggleMfa(Authentication authentication){
        UserDTO userDTO = userService.toggleMfa(getAuthentication(authentication).getEmail());
        publisher.publishEvent(new NewUserEvent(userDTO.getEmail(), MFA_UPDATE));
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", userService.getUserById(userDTO.getId()), "events", eventService.getEventsByUserId(userDTO.getId()), "roles", roleService.getRoles()))
                        .message("Multi factor authentication updated")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @PatchMapping("/update/image")
    public ResponseEntity<HttpResponse> updateProfileImage(Authentication authentication, @RequestParam("image")MultipartFile image){
        UserDTO userDTO = getAuthentication(authentication);
        userService.updateImage(userDTO, image);
        publisher.publishEvent(new NewUserEvent(userDTO.getEmail(), PROFILE_PICTURE_UPDATE));
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", userService.getUserById(userDTO.getId()), "events", eventService.getEventsByUserId(userDTO.getId()), "roles", roleService.getRoles()))
                        .message("Profile picture updated")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    @GetMapping(value = "/image/{fileName}", produces = IMAGE_PNG_VALUE)
    public byte[] getProfileImage(@PathVariable("fileName") String fileName) throws Exception{
        return Files.readAllBytes(Paths.get(System.getProperty("user.home") + "/Downloads/images/" + fileName));
    }

    @GetMapping("/refresh/token")
    public ResponseEntity<HttpResponse> refreshToken(HttpServletRequest request){
        if (isHeaderTokenValid(request)){
            String token = request.getHeader(AUTHORIZATION).substring(TOKEN_PREFIX.length());
            UserDTO user = userService.getUserById(tokenProvider.getSubject(token, request));
            return ResponseEntity.ok().body(
                    HttpResponse.builder()
                            .timeStamp(LocalDateTime.now().toString())
                            .data(Map.of("user", user, "access_token", tokenProvider.createAccessToken(getUserPrincipal(user)),
                                    "refresh_token", token))
                            .message("Token refreshed")
                            .status(HttpStatus.OK)
                            .statusCode(HttpStatus.OK.value())
                            .build());
        } else {
            return ResponseEntity.badRequest().body(
                    HttpResponse.builder()
                            .timeStamp(LocalDateTime.now().toString())
                            .reason("Refresh Token missing or invalid")
                            .developerMessage("Refresh Token missing or invalid")
                            .status(HttpStatus.BAD_REQUEST)
                            .statusCode(HttpStatus.BAD_REQUEST.value())
                            .build());
        }
    }


    private UserDTO authenticate(String email, String password) {
        try {
            if (null != userService.getUserByEmail(email)) {
                publisher.publishEvent(new NewUserEvent(email, LOGIN_ATTEMPT));
            }

            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            UserDTO loggedInUser = getLoggedInUser(authentication);

            if (!loggedInUser.isUsingMfa()) {
                publisher.publishEvent(new NewUserEvent(email, LOGIN_ATTEMPT_SUCCESS));
            }

            return loggedInUser;
        } catch (Exception exception) {
            publisher.publishEvent(new NewUserEvent(email, LOGIN_ATTEMPT_FAILURE));
            processError(request, response, exception);
            throw new ApiException(exception.getMessage());
        }
    }



    private URI getUri(){
        return URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/get/<userId>").toUriString());
    }

    private ResponseEntity<HttpResponse> sendVerificationCode(UserDTO userDTO) {
        userService.sendVerificationCode(userDTO);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", userDTO))
                        .message("Verification Code Sent")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    private ResponseEntity<HttpResponse> sendResponse(UserDTO userDTO) {
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", userDTO, "access_token", tokenProvider.createAccessToken(getUserPrincipal(userDTO)),
                                "refresh_token", tokenProvider.createRefreshToken(getUserPrincipal(userDTO))))
                        .message("Login Success")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

    private UserPrincipal getUserPrincipal(UserDTO userDTO) {
        return new UserPrincipal(UserDTOMapper.toUser(userService.getUserByEmail(userDTO.getEmail())), roleService.getRoleByUserId(userDTO.getId()));
    }

    private boolean isHeaderTokenValid(HttpServletRequest request) {
        return request.getHeader(AUTHORIZATION) != null &&
                request.getHeader(AUTHORIZATION).startsWith(TOKEN_PREFIX) &&
                tokenProvider.isTokenValid(tokenProvider.getSubject(request.getHeader(AUTHORIZATION).substring(TOKEN_PREFIX.length()), request),
                        request.getHeader(AUTHORIZATION).substring(TOKEN_PREFIX.length())
                );
    }
}
