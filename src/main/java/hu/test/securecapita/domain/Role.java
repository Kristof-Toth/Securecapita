package hu.test.securecapita.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class Role {

    private Long id;
    @NotEmpty(message = "First name cannot be empty")
    private String name;
    @NotEmpty(message = "Last name cannot be empty")
    private String permission;
}
