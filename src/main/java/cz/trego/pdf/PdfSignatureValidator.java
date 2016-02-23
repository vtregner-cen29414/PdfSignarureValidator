package cz.trego.pdf;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.*;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

/**
 * Created by cen29414 on 19.2.2016.
 */
public class PdfSignatureValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(PdfSignatureValidator.class);

    private KeyStore keyStore;

    public PdfSignatureValidator() {
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(getClass().getClassLoader().getResourceAsStream("cacerts"), "changeit".toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

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
            Calendar signDate = pk.getSignDate();
            Certificate certificates[] = pk.getSignCertificateChain();
            LOGGER.info("Integrity check OK? " + pk.verify());
            valid = pk.verify();
            result.setIntegrity(valid);
            X509Certificate signerCert = pk.getSigningCertificate();
            result.setNameOfSigner(com.itextpdf.text.pdf.security.CertificateInfo.getSubjectFields(signerCert).getField("CN"));
            result.setSignDate(signDate.getTime());

            SimpleDateFormat date_format = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss.SS");
            if (pk.getTimeStampToken() != null) {
                LOGGER.debug("TimeStamp: " + date_format.format(pk.getTimeStampDate().getTime()));
                TimeStampToken ts = pk.getTimeStampToken();
                LOGGER.debug("TimeStamp service: " + ts.getTimeStampInfo().getTsa());
                LOGGER.debug("Timestamp verified? " + pk.verifyTimestampImprint());
            }
            LOGGER.debug("Location: " + pk.getLocation());
            result.setLocation(pk.getLocation());
            LOGGER.debug("Reason: " + pk.getReason());
            result.setReason(pk.getReason());
            PdfDictionary sigDict = af.getSignatureDictionary(signatureName);
            SignaturePermissions perms = new SignaturePermissions(sigDict, null);
            LOGGER.debug("Signature type: " + (perms.isCertification() ? "certification" : "approval"));
            LOGGER.debug("Filling out fields allowed: " + perms.isFillInAllowed());
            result.setFillingOutFieldsAllowed(perms.isFillInAllowed());
            LOGGER.debug("Adding annotations allowed: " + perms.isAnnotationsAllowed());
            result.setAddingAnnotationsAllowed(perms.isAnnotationsAllowed());
            for (SignaturePermissions.FieldLock lock : perms.getFieldLocks()) {
                System.out.println("Lock: " + lock.toString());
            }

            List<VerificationException> errors = CertificateVerification.verifyCertificates(certificates, keyStore, signDate);
            if (errors.size() == 0)
                LOGGER.debug("Certificates verified against the KeyStore");
            else
                LOGGER.debug(errors.toString());
            result.setErrors(errors);
            result.setSignerCertificate(signerCert);
            valid = valid && errors.size() == 0;

            /*for (Certificate certificate : certificates) {
                X509Certificate x509Certificate = (X509Certificate) certificate;
                String errMsg = CertificateVerification.verifyCertificate(x509Certificate, null, signDate);
                LOGGER.info("Verificating certificate: " + x509Certificate.getSubjectDN());
                if (errMsg == null) LOGGER.info("Certificate verification OK");
                else LOGGER.error("Certificate verification failed: " + errMsg);
                valid = valid && (errMsg == null);
                result.getCertificateVerifications().add(new CertificateInfo(x509Certificate, errMsg));
            }*/



        } catch (GeneralSecurityException e) {
            LOGGER.error("Error while verifiing certificate", e);
            valid = false;
        }

        result.setSignatureValid(valid);

        return result;
    }
}
