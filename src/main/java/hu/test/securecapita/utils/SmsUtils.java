package hu.test.securecapita.utils;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.springframework.stereotype.Component;

@Component
public class SmsUtils {
    public static final String FROM_NUMBER = "";
    public static final String SID_KEY = "";
    public static final String TOKEN_KEY = "";

    public void sendSMS(String to, String messageBody){
        System.out.println(to);
        System.out.println(messageBody);
        Twilio.init(SID_KEY, TOKEN_KEY);
        Message message = Message.creator(new PhoneNumber("" + to), new PhoneNumber(FROM_NUMBER), messageBody).create();
        System.out.println(message);
    }
}
