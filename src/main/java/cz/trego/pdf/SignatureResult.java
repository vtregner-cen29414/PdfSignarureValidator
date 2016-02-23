package cz.trego.pdf;

import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.VerificationException;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Created by cen29414 on 19.2.2016.
 */
public class SignatureResult {
    private boolean signatureValid;
    private boolean integrity;
    private Boolean isRevokedInTimeOfSignature;
    private Boolean isRevokedNow;

    List<VerificationException> errors;

    private X509Certificate signerCertificate;
    private String nameOfSigner;
    private Date signDate;
    private String location;
    private String reason;
    private boolean fillingOutFieldsAllowed;
    private boolean addingAnnotationsAllowed;

    public SignatureResult() {
    }

    public Boolean getRevokedInTimeOfSignature() {
        return isRevokedInTimeOfSignature;
    }

    public void setRevokedInTimeOfSignature(Boolean revokedInTimeOfSignature) {
        isRevokedInTimeOfSignature = revokedInTimeOfSignature;
    }

    public Boolean getRevokedNow() {
        return isRevokedNow;
    }

    public void setRevokedNow(Boolean revokedNow) {
        isRevokedNow = revokedNow;
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

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public boolean isFillingOutFieldsAllowed() {
        return fillingOutFieldsAllowed;
    }

    public void setFillingOutFieldsAllowed(boolean fillingOutFieldsAllowed) {
        this.fillingOutFieldsAllowed = fillingOutFieldsAllowed;
    }

    public boolean isAddingAnnotationsAllowed() {
        return addingAnnotationsAllowed;
    }

    public void setAddingAnnotationsAllowed(boolean addingAnnotationsAllowed) {
        this.addingAnnotationsAllowed = addingAnnotationsAllowed;
    }

    public void setIntegrity(boolean integrity) {
        this.integrity = integrity;
    }

    public String getNameOfSigner() {
        return nameOfSigner;
    }

    public void setNameOfSigner(String nameOfSigner) {
        this.nameOfSigner = nameOfSigner;
    }

    public Date getSignDate() {
        return signDate;
    }

    public void setSignDate(Date signDate) {
        this.signDate = signDate;
    }

    public List<VerificationException> getErrors() {
        return errors;
    }

    public void setErrors(List<VerificationException> errors) {
        this.errors = errors;
    }

    public X509Certificate getSignerCertificate() {
        return signerCertificate;
    }

    public void setSignerCertificate(X509Certificate signerCertificate) {
        this.signerCertificate = signerCertificate;
    }
}
