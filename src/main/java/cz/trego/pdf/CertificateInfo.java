package cz.trego.pdf;

import java.security.cert.X509Certificate;

/**
 * Created by cen29414 on 19.2.2016.
 */
public class CertificateInfo {
    private X509Certificate certificate;
    private String validationErrorMessage;

    public CertificateInfo(X509Certificate certificate, String validationErrorMessage) {
        this.certificate = certificate;
        this.validationErrorMessage = validationErrorMessage;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public String getValidationErrorMessage() {
        return validationErrorMessage;
    }

    public void setValidationErrorMessage(String validationErrorMessage) {
        this.validationErrorMessage = validationErrorMessage;
    }
}
