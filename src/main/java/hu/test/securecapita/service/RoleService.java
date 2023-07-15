package hu.test.securecapita.service;

import hu.test.securecapita.domain.Role;

public interface RoleService {
    Role getRoleByUserId(Long id);
}
