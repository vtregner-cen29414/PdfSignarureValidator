package cz.trego.pdf;

import com.itextpdf.text.pdf.security.*;
import com.itextpdf.text.pdf.security.CertificateInfo;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.prefs.Preferences;

/**
 * Created by cen29414 on 22.2.2016.
 */
public class PdfValidatorController implements Initializable {

    public static final String STYLE_ERROR = "-fx-text-fill: #ff4331";
    private static final Logger LOGGER = LoggerFactory.getLogger(PdfValidatorController.class);
    public static final String LAST_DIR = "LAST_DIR";

    @FXML
    private Button btnSelectDir;

    @FXML
    private TableView<Pdf> tab;

    @FXML
    private TableColumn<Pdf, Path> colFile;
    @FXML
    private TableColumn<Pdf, String> colResult;
    @FXML
    private TableColumn<Pdf, String> colCert;

    private ObservableList<Pdf> data;
    private FilteredList<Pdf> filteredData;

    @FXML
    private Hyperlink lblTotal;
    @FXML
    private Hyperlink lblValid;
    @FXML
    private Hyperlink lblInvalid;
    @FXML
    private Hyperlink lblNoSignature;

    @FXML
    private ProgressIndicator progress;




    @FXML
    public void onSelectDir(ActionEvent actionEvent) {
        final Preferences preferences = Preferences.userNodeForPackage(this.getClass());
        String lastDir = preferences.get(LAST_DIR, null);
        LOGGER.info("LAST_DIR='{}'", lastDir);
        DirectoryChooser fileChooser = new DirectoryChooser();
        fileChooser.setTitle("Vyberte adresář");
        if (lastDir != null) {
            File lastDirFile = new File(lastDir);
            if (lastDirFile.isDirectory() && lastDirFile.canRead()) {
                fileChooser.setInitialDirectory(new File(lastDir));
            }
            else LOGGER.warn("Cannot read directory {}", lastDir);
        }
        final File dir = fileChooser.showDialog(btnSelectDir.getScene().getWindow());
        if (dir != null) {
            LOGGER.info("Selected dir {}", dir.toString());
            final PdfSignatureValidator validator = new PdfSignatureValidator();
            final AtomicInteger total = new AtomicInteger(0);
            final AtomicInteger valid = new AtomicInteger(0);
            final AtomicInteger invalid = new AtomicInteger(0);
            final AtomicInteger noSignature = new AtomicInteger(0);
            Task<Void> validateTask = new Task<Void>() {
                @Override
                protected Void call() throws Exception {
                    Files.walkFileTree(dir.toPath(), new SimpleFileVisitor<Path>() {

                                @Override
                                public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                                    LOGGER.warn("Cannot read file/directory skipping: {}", exc.toString());
                                    return FileVisitResult.SKIP_SUBTREE;
                                }

                                @Override
                                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                                    if (attrs.isRegularFile() && file.getFileName().toString().toLowerCase().endsWith(".pdf")) {
                                        try {
                                            VerificationResult result = validator.verifyPdf(file.toString());
                                            Pdf pdf = new Pdf();
                                            pdf.setFile(file);
                                            if (result.isNoSignature()) pdf.setValidationResult("N/A");
                                            else
                                                pdf.setValidationResult(result.isAllSignaturesValid() ? "OK" : result.composeErrorMessage());

                                            if (result.isNoSignature()) {
                                                pdf.setCertificate("N/A");
                                            } else {
                                                String dn = result.getFirstSignatureCertificate().getSubjectDN().getName();
                                                pdf.setCertificate(getSubjectDnPart(dn, "cn"));
                                            }
                                            pdf.setVerificationResult(result);

                                            total.incrementAndGet();
                                            if (pdf.getVerificationResult().isAllSignaturesValid() && !pdf.getVerificationResult().isNoSignature())
                                                valid.incrementAndGet();
                                            else if (pdf.getVerificationResult().isNoSignature()) noSignature.incrementAndGet();
                                            else invalid.incrementAndGet();

                                            Platform.runLater(() -> data.add(pdf));

                                        } catch (Exception e) {
                                            LOGGER.error("Error while verifiing signature", e);
                                        }
                                    }
                                    return FileVisitResult.CONTINUE;
                                }
                            }
                    );
                    return null;
                }

                @Override
                protected void succeeded() {
                    preferences.put(LAST_DIR, dir.toString());
                    Platform.runLater(() -> {
                        lblTotal.setText(String.valueOf(total.get()));
                        lblValid.setText(String.valueOf(valid.get()));
                        lblInvalid.setText(String.valueOf(invalid.get()));
                        lblNoSignature.setText(String.valueOf(noSignature.get()));
                        progress.setVisible(false);
                        btnSelectDir.setDisable(false);
                    });
                }

                @Override
                protected void failed() {
                    LOGGER.error("Error while verifiing signature", getException());
                    Platform.runLater(() -> {
                        progress.setVisible(false);
                        btnSelectDir.setDisable(false);
                    });
                }


            };

            btnSelectDir.setDisable(true);
            progress.setVisible(true);
            data = FXCollections.observableArrayList();
            filteredData = new FilteredList<>(data);
            tab.setItems(filteredData);
            new Thread(validateTask).start();
        }
        else LOGGER.info("No dir selected!");
    }

    private String getSubjectDnPart(String dn, String part) {
        try {
            LdapName ldapName = new LdapName(dn);
            Optional<Rdn> rdn1 = ldapName.getRdns().stream().filter(rdn -> part.toLowerCase().equals(rdn.getType().toLowerCase())).findFirst();
            return rdn1.isPresent() ? rdn1.get().getValue().toString() : null;
        } catch (InvalidNameException e) {
            return dn;
        }
    }


    @Override
    public void initialize(URL location, ResourceBundle resources) {
        colFile.setCellValueFactory(new PropertyValueFactory<>("file"));
        colResult.setCellValueFactory(new PropertyValueFactory<>("validationResult"));
        colCert.setCellValueFactory(new PropertyValueFactory<>("certificate"));
        colFile.setCellFactory( column -> new TableCell<Pdf, Path>() {
            @Override
            protected void updateItem(Path item, boolean empty) {
                super.updateItem(item, empty);
                if (!empty) {
                    setText(item.toFile().getName());
                    setTooltip(new Tooltip(item.getParent().toFile().getAbsolutePath()));
                }
                else setText(null);
            }
        });

        colResult.setCellFactory(column -> new TableCell<Pdf, String>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (item == null || empty) {
                    setGraphic(null);
                } else {
                    Pdf pdf = getTableView().getItems().get(getTableRow().getIndex());
                    if (!pdf.getVerificationResult().isNoSignature()) {
                        Hyperlink certLink = new Hyperlink(item);
                        certLink.setOnAction(event -> onValidationDetailLink(event, getIndex()));
                        certLink.setStyle(pdf.getVerificationResult().isAllSignaturesValid() ? "" : STYLE_ERROR);
                        setGraphic(certLink);
                    }
                    else setGraphic(new Label(item));
                }
            }
        });

        colCert.setCellFactory(column -> new TableCell<Pdf, String>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (!empty && item != null) {
                    Pdf pdf = getTableView().getItems().get(getTableRow().getIndex());
                    if (!pdf.getVerificationResult().isNoSignature()) {
                        Hyperlink certLink = new Hyperlink(item);
                        certLink.setOnAction(event -> onCertLink(event, getIndex()));
                        setGraphic(certLink);
                    }
                    else setGraphic(new Label(item));
                }
                else {
                    setGraphic(null);
                }
            }
        });

    }

    @FXML
    private void onFilter(ActionEvent event) {
        if (data != null && data.size() > 0) {
            final Hyperlink hyperlink = (Hyperlink) event.getSource();

            filteredData.setPredicate(pdf -> {
                boolean filter = true;
                if (hyperlink == lblNoSignature) filter = pdf.getVerificationResult().isNoSignature();
                if (hyperlink == lblValid) filter = pdf.getVerificationResult().isAllSignaturesValid() && !pdf.getVerificationResult().isNoSignature();
                if (hyperlink == lblInvalid) filter = !pdf.getVerificationResult().isAllSignaturesValid() && !pdf.getVerificationResult().isNoSignature();

                return filter;
            });

        }
    }

    private void onValidationDetailLink(ActionEvent event, int index) {
        Pdf pdf = tab.getItems().get(index);
        Alert alert = new Alert(pdf.getVerificationResult().isAllSignaturesValid() ?  Alert.AlertType.INFORMATION : pdf.getVerificationResult().isIntegrityOk() ? Alert.AlertType.WARNING : Alert.AlertType.ERROR);

        alert.setTitle("Vlastnosti podpisu");
        StringBuilder headerText = new StringBuilder();
        SignatureResult signatureResult;
        if (pdf.getVerificationResult().isAllSignaturesValid()) {
            signatureResult = pdf.getVerificationResult().getSignatureResults().get(0);
        }
        else {
            Optional<SignatureResult> first = pdf.getVerificationResult().getSignatureResults().stream().filter(s -> !s.isSignatureValid()).findFirst();
            signatureResult = first.get();
        }

        VBox content = new VBox(3);
        if (pdf.getVerificationResult().isAllSignaturesValid()) {
            headerText.append("Podpis je PLATNÝ, podepsaný uživatelem ").append(signatureResult.getNameOfSigner()).append(".");
        }
        else if (!pdf.getVerificationResult().isIntegrityOk()) {
            //Tento Dokument byl od aplikování podpisu změněn nebo poškozen.
            headerText.append("Podpis je NEPLATNÝ.");
        }
        else {
            headerText.append("Platnost podpisu je NEZNÁMÁ.");
        }
        SimpleDateFormat sfd = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
        headerText.append("\nČas podepsání: ").append(sfd.format(signatureResult.getSignDate()));
        alert.setHeaderText(headerText.toString());

        Label integrityLabel = new Label(pdf.getVerificationResult().isIntegrityOk() ?
                "Tento dokument se od aplikování podpisu nezměnil." :
                "Tento dokument byl od aplikování podpisu změněn nebo poškozen.");
        if (!pdf.getVerificationResult().isIntegrityOk()) integrityLabel.setStyle(STYLE_ERROR);
        content.getChildren().add(integrityLabel);

        if (signatureResult.isFillingOutFieldsAllowed() || signatureResult.isAddingAnnotationsAllowed()) {
            String text = "Autor certifikátu určil, že v tomto dokumentu je povoleno ";
            if (signatureResult.isFillingOutFieldsAllowed()) text+= "vyplňování polí formulárů";
            if (signatureResult.isAddingAnnotationsAllowed()) text+=" a přidávání poznámek";
            text+=". Žádné další změny nejsou povoleny.";
            content.getChildren().add(new Label(text));
        }
        else {
            content.getChildren().add(new Label("Autor certifikátu určil, že v tomto dokumentu nejsou žádné změny povoleny."));
        }

        if (pdf.getVerificationResult().isAllSignaturesValid()) {
            content.getChildren().add(new Label("Identita autora podpisu je platná."));
            content.getChildren().add(new Label("Cesta od certifikátu autora podpisu k certifikátu vystavitele byla úspěšně vytvořena."));
        }
        else {
            if (signatureResult.getErrors() != null) {
                for (VerificationException verificationException : signatureResult.getErrors()) {
                    String text;
                    if (verificationException.getMessage().contains("Cannot be verified against the KeyStore")) {
                        text = "Vyskytly se chyby při vytváření cesty od certifikátu autora podpisu k certifikátu vystavitele.";

                    }
                    else text = verificationException.getMessage().substring(verificationException.getMessage().indexOf("failed: ")+8);

                    Label label = new Label(text);
                    label.setStyle(STYLE_ERROR);
                    content.getChildren().add(label);
                }
            }
        }

        if (signatureResult.getRevokedNow() == null && signatureResult.getRevokedInTimeOfSignature() == null) {
            content.getChildren().add(new Label("Kontrola odvolání platnosti nebyla provedena"));
        }
        if (signatureResult.getRevokedNow() != null && !signatureResult.getRevokedNow()) {
            content.getChildren().add(new Label("Certifikát autora podpisu je platný a nebyl odvolán."));
        }
        alert.getDialogPane().setContent(content);

        alert.showAndWait();

    }


    private void onCertLink(ActionEvent event, int index) {
        Pdf pdf = tab.getItems().get(index);
        Alert alert = new Alert(Alert.AlertType.INFORMATION);

        alert.setTitle("Detaily certifikátu");
        SignatureResult signatureResult;
        if (pdf.getVerificationResult().isAllSignaturesValid()) {
            signatureResult = pdf.getVerificationResult().getSignatureResults().get(0);
        }
        else {
            Optional<SignatureResult> first = pdf.getVerificationResult().getSignatureResults().stream().filter(s -> !s.isSignatureValid()).findFirst();
            signatureResult = first.get();
        }
        X509Certificate certificate = signatureResult.getSignerCertificate();
        StringBuilder header = new StringBuilder();
        header.append(signatureResult.getNameOfSigner()).append("\n");
        String organization = CertificateInfo.getSubjectFields(certificate).getField("O");
        if (organization != null) header.append(organization).append("\n\n");

        header.append("Vydal: ");
        header.append(CertificateInfo.getIssuerFields(certificate).getField("CN")).append(", ");
        header.append(CertificateInfo.getIssuerFields(certificate).getField("O")).append("\n");

        SimpleDateFormat sfd = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
        header.append("Platný od: ").append(sfd.format(certificate.getNotBefore())).append("\n");
        header.append("Platný do: ").append(sfd.format(certificate.getNotAfter())).append("\n");

        alert.setHeaderText(header.toString());

        alert.showAndWait();


    }
}
