package hu.test.securecapita.utils;

import hu.test.securecapita.domain.UserPrincipal;
import hu.test.securecapita.dto.UserDTO;
import org.springframework.security.core.Authentication;

public class UserUtils {
    public static UserDTO getAuthentication(Authentication authentication){
        return ((UserDTO) authentication.getPrincipal());
    }

    public static UserDTO getLoggedInUser(Authentication authentication) {
        return ((UserPrincipal) authentication.getPrincipal()).getUser();
    }
}
