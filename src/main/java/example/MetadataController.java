package example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MetadataController {

    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Autowired
    public MetadataController(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
    }

    @GetMapping("/saml/metadata")
    public String metadata() {
        // Replace 'your-registration-id' with the actual ID
        RelyingPartyRegistration relyingPartyRegistration = this.relyingPartyRegistrationRepository
                .findByRegistrationId("samlexample");

        OpenSamlMetadataResolver metadataResolver = new OpenSamlMetadataResolver();
        return metadataResolver.resolve(relyingPartyRegistration);
    }

    @GetMapping("/test")
    public String test() {
        return "Test endpoint response";
    }

}
