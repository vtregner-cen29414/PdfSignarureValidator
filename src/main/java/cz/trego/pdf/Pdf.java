package cz.trego.pdf;

import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;

import java.nio.file.Path;

/**
 * Created by cen29414 on 22.2.2016.
 */
public class Pdf {
    private SimpleObjectProperty<Path> file = new SimpleObjectProperty<>();
    private SimpleStringProperty validationResult = new SimpleStringProperty();
    private SimpleStringProperty certificate = new SimpleStringProperty();

    private VerificationResult verificationResult;

    public Path getFile() {
        return file.get();
    }

    public SimpleObjectProperty<Path> fileProperty() {
        return file;
    }

    public void setFile(Path file) {
        this.file.set(file);
    }

    public String getValidationResult() {
        return validationResult.get();
    }

    public SimpleStringProperty validationResultProperty() {
        return validationResult;
    }

    public void setValidationResult(String validationResult) {
        this.validationResult.set(validationResult);
    }

    public String getCertificate() {
        return certificate.get();
    }

    public SimpleStringProperty certificateProperty() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate.set(certificate);
    }

    public VerificationResult getVerificationResult() {
        return verificationResult;
    }

    public void setVerificationResult(VerificationResult verificationResult) {
        this.verificationResult = verificationResult;
    }
}
