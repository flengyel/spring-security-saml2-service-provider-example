package example;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MetadataController {

    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    // implied @Autowired
    public MetadataController(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
    }

    @GetMapping(value = "/saml/metadata", produces = "application/xml")
    public String metadata() {
        try {
            RelyingPartyRegistration relyingPartyRegistration = this.relyingPartyRegistrationRepository
                    .findByRegistrationId("samlexample");
            if (relyingPartyRegistration == null) {
                return "Relying Party Registration not found";
            }
            OpenSamlMetadataResolver metadataResolver = new OpenSamlMetadataResolver();
            return metadataResolver.resolve(relyingPartyRegistration);
        } catch (Exception e) {
            // Log the exception
            return "Error generating metadata: " + e.getMessage();
        }
    }

    @GetMapping("/test")
    public String test() {
        return "Test endpoint response";
    }

}
