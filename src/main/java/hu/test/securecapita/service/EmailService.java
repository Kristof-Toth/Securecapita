package hu.test.securecapita.service;

import hu.test.securecapita.enumeration.VerificationType;

public interface EmailService {
    void sendVerificationEmail(String firstName, String email, String verificationUrl, VerificationType verificationType);
}
