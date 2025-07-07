package com.example.authservice.service;

import com.example.authservice.exception.OtpException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class WhatsAppService {

    @Value("${whatsapp.api.phone-number-id}")
    private String phoneNumberId;

    @Value("${whatsapp.api.access-token}")
    private String accessToken;

    @Value("${otp.expiration-seconds}")
    private long otpExpirationSeconds;

    private final HttpClient httpClient = HttpClients.createDefault();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Async("taskExecutor")
    public void sendOtpMessage(String toPhoneNumber, String otpCode, String purpose) {
        if (toPhoneNumber == null || toPhoneNumber.trim().isEmpty()) {
            log.error("WhatsApp Phone Number is null or empty. Cannot send OTP.");
            throw new OtpException("WhatsApp telefon nömrəsi qeydə alınmayıb.");
        }

        // WhatsApp Cloud API URL-i
        String url = String.format("https://graph.facebook.com/v19.0/%s/messages", phoneNumberId); // API versiyasını yoxlayın

        Map<String, Object> body = new HashMap<>();
        body.put("messaging_product", "whatsapp");
        body.put("to", toPhoneNumber);
        body.put("type", "text"); // OTP üçün "text" tipi kifayətdir, lakin rəsmi API şablonları daha yaxşıdır.

        Map<String, String> textContent = new HashMap<>();
        textContent.put("body", String.format("AuthService: Sizin %s üçün OTP kodunuz: %s. Bu kod %d dəqiqə ərzində etibarlıdır.",
                purpose, otpCode, (otpExpirationSeconds / 60)));
        body.put("text", textContent);

        try {
            String requestBody = objectMapper.writeValueAsString(body);
            HttpPost request = new HttpPost(url);
            request.setHeader("Authorization", "Bearer " + accessToken);
            request.setEntity(new StringEntity(requestBody, ContentType.APPLICATION_JSON));

            httpClient.execute(request, response -> {
                int statusCode = response.getCode();
                String responseBody = new String(response.getEntity().getContent().readAllBytes());

                if (statusCode == 200) {
                    log.info("OTP sent successfully to WhatsApp {}: {}", toPhoneNumber, otpCode);
                } else {
                    log.error("Failed to send OTP via WhatsApp to {}. Status: {}, Response: {}", toPhoneNumber, statusCode, responseBody);
                    throw new OtpException("WhatsApp üzərindən OTP göndərilərkən xəta baş verdi: " + responseBody);
                }
                return null; // or handle response object
            });

        } catch (Exception e) {
            log.error("Error sending OTP via WhatsApp to {}: {}", toPhoneNumber, e.getMessage());
            throw new OtpException("WhatsApp API ilə əlaqə qurularkən xəta baş verdi: " + e.getMessage());
        }
    }
}