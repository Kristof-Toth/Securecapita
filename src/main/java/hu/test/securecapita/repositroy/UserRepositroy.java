package hu.test.securecapita.repositroy;

import hu.test.securecapita.domain.User;

import java.util.Collection;

public interface UserRepositroy<T extends User>  {
    T create(T data);
    Collection<T> list(int page, int pageSize);
    T get(Long id);
    T update(T data);
    Boolean delete(Long id);
}
