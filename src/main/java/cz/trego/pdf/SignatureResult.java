package cz.trego.pdf;

import com.itextpdf.text.pdf.security.CertificateVerification;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by cen29414 on 19.2.2016.
 */
public class SignatureResult {
    private boolean signatureValid;
    private boolean integrity;
    private List<CertificateInfo> certificateInfos;

    public SignatureResult() {
        certificateInfos = new ArrayList<>();
    }

    public boolean isSignatureValid() {
        return signatureValid;
    }

    public void setSignatureValid(boolean signatureValid) {
        this.signatureValid = signatureValid;
    }

    public boolean isIntegrity() {
        return integrity;
    }

    public void setIntegrity(boolean integrity) {
        this.integrity = integrity;
    }

    public List<CertificateInfo> getCertificateVerifications() {
        return certificateInfos;
    }
}
