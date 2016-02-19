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

/**
 * Created by cen29414 on 19.2.2016.
 */
public class PdfSignatureValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(PdfSignatureValidator.class);
    public boolean verifyPdf(String file) throws IOException, GeneralSecurityException {

        LOGGER.info("Verifying " + file);
        PdfReader reader = new PdfReader(file);
        AcroFields af = reader.getAcroFields();

        // Search of the whole signature
        ArrayList<String> names = af.getSignatureNames();
        final boolean[] valid = {true};

        // For every signature :
        names.stream().forEach(name -> valid[0] = valid[0] && isValidSignature(name, af));

        return valid[0];
    }

    private boolean isValidSignature(String signatureName, AcroFields af) {
        boolean valid = true;
        try {
            LOGGER.debug("Signature name: " + signatureName);
            LOGGER.debug("Signature covers whole document: " + af.signatureCoversWholeDocument(signatureName));
            LOGGER.debug("Document revision: " + af.getRevision(signatureName) + " of " + af.getTotalRevisions());

            PdfPKCS7 pk = af.verifySignature(signatureName);
            Calendar cal = pk.getSignDate();
            Certificate certificates[] = pk.getCertificates();
            LOGGER.info("Integrity check OK? " + pk.verify());
            valid = pk.verify();

            for (Certificate certificate : certificates) {
                X509Certificate x509Certificate = (X509Certificate) certificate;
                String result = CertificateVerification.verifyCertificate(x509Certificate, null, cal);
                LOGGER.info("Verificating certificate: " + x509Certificate.getSubjectDN());
                if (result == null) LOGGER.info("Certificate verification OK");
                else LOGGER.error("Certificate verification failed: " + result);
                valid = valid && (result == null);
            }
        } catch (GeneralSecurityException e) {
            LOGGER.error("Error while verifiing certificate", e);
            valid = false;
        }

        return valid;
    }
}
