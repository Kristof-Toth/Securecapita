package hu.test.securecapita.event;

import hu.test.securecapita.enumeration.EventType;
import lombok.Getter;
import lombok.Setter;
import org.springframework.context.ApplicationEvent;

import java.time.Clock;

@Getter
@Setter
public class NewUserEvent extends ApplicationEvent {
    private EventType type;
    private String email;

    public NewUserEvent(String email, EventType type) {
        super(email);
        this.type = type;
        this.email = email;
    }
}
