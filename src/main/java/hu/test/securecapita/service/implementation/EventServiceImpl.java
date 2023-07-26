package hu.test.securecapita.service.implementation;

import hu.test.securecapita.domain.UserEvent;
import hu.test.securecapita.enumeration.EventType;
import hu.test.securecapita.repositroy.EventRepository;
import hu.test.securecapita.service.EventService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
@RequiredArgsConstructor
public class EventServiceImpl implements EventService {
    private final EventRepository eventRepository;
    @Override
    public Collection<UserEvent> getEventsByUserId(Long userId) {
        return eventRepository.getEventsByUserId(userId);
    }

    @Override
    public void addUserEvent(String email, EventType eventType, String device, String ipAddress) {
        eventRepository.addUserEvent(email, eventType, device, ipAddress);
    }

    @Override
    public void addUserEvent(Long id, EventType eventType, String device, String ipAddress) {

    }
}
