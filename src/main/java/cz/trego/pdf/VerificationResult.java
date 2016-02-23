package cz.trego.pdf;

import com.itextpdf.text.pdf.security.VerificationException;

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
    };

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
                    if (signatureResult.getErrors() != null) {
                        for (VerificationException verificationException : signatureResult.getErrors()) {
                            sb.append(verificationException.getMessage().substring(verificationException.getMessage().indexOf("failed: ")+8)).append("\n");
                        }
                    }
                    if (signatureResult.getRevokedInTimeOfSignature() != null && signatureResult.getRevokedInTimeOfSignature()) {
                        sb.append("Platnost certifikátu byla odvolána v době podpisu").append("\n");
                    }
                    if (signatureResult.getRevokedNow() != null && signatureResult.getRevokedNow()) {
                        sb.append("Certifikátu je nyní zneplatněn").append("\n");
                    }
                }
            }
            return sb.toString();
        }
        else return null;
    }

    public X509Certificate getFirstSignatureCertificate() {
        if (signatureResults != null) {
            return signatureResults.get(0).getSignerCertificate();
        }
        return null;
    }
}
