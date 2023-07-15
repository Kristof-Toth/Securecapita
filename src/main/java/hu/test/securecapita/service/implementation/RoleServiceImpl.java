package hu.test.securecapita.service.implementation;

import hu.test.securecapita.domain.Role;
import hu.test.securecapita.repositroy.RoleRepository;
import hu.test.securecapita.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {
    private final RoleRepository<Role> roleRepository;

    @Override
    public Role getRoleByUserId(Long id) {
        return roleRepository.getRoleByUserId(id);
    }
}
