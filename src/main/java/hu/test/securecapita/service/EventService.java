package hu.test.securecapita.service;

import hu.test.securecapita.domain.UserEvent;
import hu.test.securecapita.enumeration.EventType;

import java.util.Collection;

public interface EventService {
    Collection<UserEvent> getEventsByUserId(Long userId);
    void addUserEvent(String email, EventType eventType, String device, String ipAddress);
    void addUserEvent(Long id, EventType eventType, String device, String ipAddress);

}
