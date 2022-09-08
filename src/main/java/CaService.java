import cert_generation.GeneratedCert;
import lombok.SneakyThrows;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;

import static cert_generation.GeneratedCert.createCertificate;

public class CaService {

    @SneakyThrows
    public static void main(String[] args) {

        Security.setProperty("crypto.policy", "unlimited");

        GeneratedCert rootCA = createCertificate("root_CA",   /*domain=*/null,     /*issuer=*/null,  /*isCa=*/true);
        GeneratedCert issuer = createCertificate("self_signed_issuer_(CA)", /*domain=*/null, rootCA, /*isCa=*/true);
        GeneratedCert domain = createCertificate("first.Base58.hr", "vloboda.Base58.hr", issuer, /*isCa=*/false);
        GeneratedCert otherD = createCertificate("second.Base58.hr", "vloboda.Base58.hr", issuer, /*isCa=*/false);


        char[] emptyPassword = new char[0];
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
// Key store expects a load first to initialize.
        keyStore.load(null, emptyPassword);

        keyStore.setKeyEntry("root_CA", rootCA.privateKey, emptyPassword,
                new X509Certificate[]{rootCA.certificate});

        keyStore.setKeyEntry("self_signed_issuer_(CA)", issuer.privateKey, emptyPassword,
                new X509Certificate[]{issuer.certificate, rootCA.certificate});

// Store domain certificate, with the private key and the cert chain
        keyStore.setKeyEntry("first.Base58.hr", domain.privateKey, emptyPassword,
                new X509Certificate[]{domain.certificate, issuer.certificate, rootCA.certificate});

        keyStore.setKeyEntry("second.Base58.hr", otherD.privateKey, emptyPassword,
                new X509Certificate[]{otherD.certificate, issuer.certificate, rootCA.certificate});
// Store to a file
        try (FileOutputStream store = new FileOutputStream("my-cert.p12")) {
            keyStore.store(store, emptyPassword);
        }
    }
}
