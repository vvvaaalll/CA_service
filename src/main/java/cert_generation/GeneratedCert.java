package cert_generation;

import lombok.Data;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import sun.security.x509.X500Name;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Data
public final class GeneratedCert {

    public final PrivateKey privateKey;
    public final X509Certificate certificate;

    public GeneratedCert(PrivateKey privateKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
    }

    public static GeneratedCert createCertificate(String cnName,
                                                   String domain,
                                                   GeneratedCert issuer,
                                                   boolean isCA) throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair certKeyPair = keyGen.generateKeyPair();
        X500Name name = new X500Name("CN=" + cnName);
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Instant validFrom = Instant.now();
        Instant validUntil = validFrom.plus(10 * 360, ChronoUnit.DAYS);

        X500Name issuerName;
        PrivateKey issuerKey;
        if (issuer == null) {
            issuerName = name;
            issuerKey = certKeyPair.getPrivate();
        } else {
            issuerName = new X500Name(issuer.certificate.getSubjectDN().getName());
            issuerKey = issuer.privateKey;
        }

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName.asX500Principal(),
                serialNumber,
                Date.from(validFrom), Date.from(validUntil),
                name.asX500Principal(), certKeyPair.getPublic());

        if(isCA){
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));
        }
        if (domain != null){
            builder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, domain)));
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(issuerKey);
        X509CertificateHolder certHolder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

        return new GeneratedCert(certKeyPair.getPrivate(), cert);
    }
}

