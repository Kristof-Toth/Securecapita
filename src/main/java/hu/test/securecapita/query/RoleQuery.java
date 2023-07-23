package hu.test.securecapita.query;

public class RoleQuery {

    public static final String SELECT_ROLES = "SELECT * FROM Roles ORDER BY id";
    public static final String INSERT_ROLE_TO_USER_QUERY = "INSERT INTO UsersRoles (user_id, role_id) VALUES (:userId, :roleId)";
    public static final String SELECT_ROLE_BY_NAME_QUERY = "SELECT * FROM Roles WHERE name = :name";

    public static final String SELECT_ROLE_BY_ID_QUERY =
            "SELECT r.id, r.name, r.permission FROM Roles r JOIN UsersRoles ur ON ur.role_id = r.id " +
                    "JOIN Users u ON u.id = ur.user_id WHERE u.id = :id";

    public static final String UPDATE_USER_ROLE_QUERY = "UPDATE UsersRoles SET role_id = :roleId WHERE user_id = :userId";

}
