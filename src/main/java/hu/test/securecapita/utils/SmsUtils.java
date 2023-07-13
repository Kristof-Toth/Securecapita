package hu.test.securecapita.utils;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

public class SmsUtils {
    public static final String FROM_NUMBER = "+36309057330";
    public static final String SID_KEY = "AC1748115354847da0b2e69218f8555da1";
    public static final String TOKEN_KEY = "b20c23b700d6a5672a1559332f456981";

    public static void SendSMS(String to, String messageBody){
        Twilio.init(SID_KEY, TOKEN_KEY);
        Message message = Message.creator(new PhoneNumber("+36" + to), new PhoneNumber(FROM_NUMBER), messageBody).create();
        System.out.println(message);
    }
}
