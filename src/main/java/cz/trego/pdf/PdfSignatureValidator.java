package cz.trego.pdf;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

/**
 * Created by cen29414 on 19.2.2016.
 */
public class PdfSignatureValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(PdfSignatureValidator.class);

    public VerificationResult verifyPdf(String file) throws IOException, GeneralSecurityException {

        LOGGER.info("Verifying " + file);
        PdfReader reader = new PdfReader(file);
        AcroFields af = reader.getAcroFields();

        // Search of the whole signature
        ArrayList<String> names = af.getSignatureNames();
        final List<SignatureResult> signatureResults = new ArrayList<>();

        // For every signature :
        names.stream().forEach(name -> {
            signatureResults.add(isValidSignature(name, af));
        });

        VerificationResult result =  new VerificationResult();
        result.setAllSignaturesValid(signatureResults.stream().allMatch(SignatureResult::isSignatureValid));
        result.setSignatureResults(signatureResults);
        return result;
    }

    private SignatureResult isValidSignature(String signatureName, AcroFields af) {
        boolean valid = true;
        SignatureResult result = new SignatureResult();
        try {
            LOGGER.debug("Signature name: " + signatureName);
            LOGGER.debug("Signature covers whole document: " + af.signatureCoversWholeDocument(signatureName));
            LOGGER.debug("Document revision: " + af.getRevision(signatureName) + " of " + af.getTotalRevisions());

            PdfPKCS7 pk = af.verifySignature(signatureName);
            Calendar cal = pk.getSignDate();
            Certificate certificates[] = pk.getSignCertificateChain();
            LOGGER.info("Integrity check OK? " + pk.verify());
            valid = pk.verify();
            result.setIntegrity(valid);

            for (Certificate certificate : certificates) {
                X509Certificate x509Certificate = (X509Certificate) certificate;
                String errMsg = CertificateVerification.verifyCertificate(x509Certificate, null, cal);
                LOGGER.info("Verificating certificate: " + x509Certificate.getSubjectDN());
                if (errMsg == null) LOGGER.info("Certificate verification OK");
                else LOGGER.error("Certificate verification failed: " + errMsg);
                valid = valid && (errMsg == null);
                result.getCertificateVerifications().add(new CertificateInfo(x509Certificate, errMsg));
            }

        } catch (GeneralSecurityException e) {
            LOGGER.error("Error while verifiing certificate", e);
            valid = false;
        }

        result.setSignatureValid(valid);

        return result;
    }
}
