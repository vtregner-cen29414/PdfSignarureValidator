package cz.trego.pdf;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Created by cen29414 on 19.2.2016.
 */
public class VerificationResult {
    private boolean allSignaturesValid;
    private List<SignatureResult> signatureResults;

    public boolean isAllSignaturesValid() {
        return allSignaturesValid;
    }

    public void setAllSignaturesValid(boolean allSignaturesValid) {
        this.allSignaturesValid = allSignaturesValid;
    }

    public List<SignatureResult> getSignatureResults() {
        return signatureResults;
    }

    public void setSignatureResults(List<SignatureResult> signatureResults) {
        this.signatureResults = signatureResults;
    }

    public String composeErrorMessage() {
        StringBuilder sb = new StringBuilder();
        if (!allSignaturesValid) {
            for (SignatureResult signatureResult : signatureResults) {
                if (!signatureResult.isSignatureValid()) {
                    if (!signatureResult.isIntegrity()) {
                        sb.append("Neplatný podpis. Porušena integrita souboru!\n");
                    }
                    for (CertificateInfo certificateInfo : signatureResult.getCertificateVerifications()) {
                        if (certificateInfo.getValidationErrorMessage() != null) {
                            sb.append(certificateInfo.getValidationErrorMessage()).append("\n");
                        }
                    }
                }
            }
            return sb.toString();
        }
        else return null;
    }

    public X509Certificate getFirstSignatureCertificate() {
        if (signatureResults != null) {
            return signatureResults.get(0).getCertificateVerifications().get(0).getCertificate();
        }
        return null;
    }
}
