package example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.core.io.ClassPathResource;
import java.security.KeyFactory;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import org.springframework.security.config.Customizer;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/test", "/saml/metadata").permitAll()
                        .anyRequest().authenticated())
                .saml2Login(Customizer.withDefaults()) // SAML 2.0 Login Configuration
                .logout(logout -> logout.logoutSuccessUrl("/logout-success")); // Custom logout success URL

        return http.build();
    }

    @Bean
    public InMemoryRelyingPartyRegistrationRepository saml2RelyingPartyRegistrationRepository() {
        Saml2X509Credential verificationCredential = getVerificationCredential();
        Saml2X509Credential signingCredential = getSigningCredential();

        RelyingPartyRegistration registration = RelyingPartyRegistration.withRegistrationId("samlexample")
                .entityId("test-service-provider")
                .assertionConsumerServiceLocation("http://172.27.9.4:8080/sp/login/saml2/sso/samlexample")
                .signingX509Credentials(c -> c.add(signingCredential))
                .singleLogoutServiceLocation("http://localhost:8080/logout") // Your SP logout URL
                .singleLogoutServiceResponseLocation("http://localhost:8080/logout/response") // Your SP logout response
                                                                                              // URL
                .assertingPartyDetails(partyDetails -> partyDetails
                        .entityId("https://ssoyellow.cuny.edu/oam/fed")
                        .singleSignOnServiceLocation("https://ssoyellow.cuny.edu/oamfed/idp/samlv20")
                        .wantAuthnRequestsSigned(true)
                        .verificationX509Credentials(c -> c.add(verificationCredential)))
                .build();

        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    private Saml2X509Credential getVerificationCredential() {
        try (InputStream certStream = new ClassPathResource("credentials/public.pk8").getInputStream()) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(certStream);
            return Saml2X509Credential.verification(certificate);
        } catch (Exception e) {
            throw new RuntimeException("Unable to load IdP verification certificate", e);
        }
    }

    private Saml2X509Credential getSigningCredential() {
        // Load the private key
        try (InputStream keyStream = new ClassPathResource("credentials/private.pk8").getInputStream()) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyStream.readAllBytes());
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(spec);

            // Load the certificate
            try (InputStream certStream = new ClassPathResource("credentials/public.pk8").getInputStream()) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate certificate = (X509Certificate) cf.generateCertificate(certStream);
                return Saml2X509Credential.signing(privateKey, certificate);
            }
        } catch (Exception e) {
            throw new RuntimeException("Unable to load signing credentials", e);
        }
    }

}
