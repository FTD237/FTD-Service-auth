package com.authenticate.ftdserviceauthenticate.services;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    public void sendPasswordEmail(String email, String token) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setTo(email);
            helper.setSubject("Reset your password");

            String resetUrl = frontendUrl + "/reset-password?token=" + token;

            String htmlContent = buildEmailContent(resetUrl);
            helper.setText(htmlContent, true);

            mailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("We got an issue when trying to send the email", e);
        }
    }

    private String buildEmailContent(String resetUrl) {
        return "<html>" +
                "<body>" +
                "<h2>Réinitialisation de mot de passe</h2>" +
                "<p>Vous avez demandé une réinitialisation de votre mot de passe.</p>" +
                "<p>Cliquez sur le lien ci-dessous pour définir un nouveau mot de passe :</p>" +
                "<a href='" + resetUrl + "' style='background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>Réinitialiser le mot de passe</a>" +
                "<p>Ce lien expire dans 30 minutes.</p>" +
                "<p>Si vous n'avez pas demandé cette réinitialisation, ignorez cet email.</p>" +
                "</body>" +
                "</html>";
    }
}
