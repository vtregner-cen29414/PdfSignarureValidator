package cz.trego.pdf;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableArray;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
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
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.prefs.Preferences;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by cen29414 on 22.2.2016.
 */
public class PdfValidatorController implements Initializable {

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

    @FXML
    private Label lblTotal;
    @FXML
    private Label lblValid;
    @FXML
    private Label lblInvalid;
    @FXML
    private Label lblNoSignature;




    @FXML
    public void onSelectDir(ActionEvent actionEvent) {
        final Preferences preferences = Preferences.userNodeForPackage(this.getClass());
        String lastDir = preferences.get(LAST_DIR, null);
        DirectoryChooser fileChooser = new DirectoryChooser();
        fileChooser.setTitle("Vyberte adresář");
        if (lastDir != null) fileChooser.setInitialDirectory(new File(lastDir));
        final File dir = fileChooser.showDialog(btnSelectDir.getScene().getWindow());
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
                        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                            if (attrs.isRegularFile() && file.getFileName().toString().toLowerCase().endsWith(".pdf")) {
                                try {
                                    VerificationResult result = validator.verifyPdf(file.toString());
                                    Pdf pdf = new Pdf();
                                    pdf.setFile(file);
                                    pdf.setValidationResult(result.isAllSignaturesValid() ? "OK" : result.composeErrorMessage());
                                    String dn = result.getFirstSignatureCertificate().getSubjectDN().getName();
                                    pdf.setCertificate(getSubjectDnPart(dn, "cn"));
                                    pdf.setVerificationResult(result);

                                    total.incrementAndGet();
                                    if (pdf.getVerificationResult().isAllSignaturesValid()) valid.incrementAndGet();
                                    else invalid.incrementAndGet();

                                    Platform.runLater(() -> data.add(pdf));

                                } catch (GeneralSecurityException e) {
                                    LOGGER.error("Error while verifiing signature", e);
                                    e.printStackTrace();
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
                });
            }

            @Override
            protected void failed() {
                LOGGER.error("Error while verifiing signature", getException());
            }
        };

        data = FXCollections.observableArrayList();
        tab.setItems(data);
        new Thread(validateTask).start();

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
                    setText(null);
                    setStyle("");
                } else {
                    setText(item);
                    Pdf pdf = getTableView().getItems().get(getTableRow().getIndex());
                    setStyle(pdf.getVerificationResult().isAllSignaturesValid() ? "" : "-fx-text-fill: #ff4331");
                }
            }
        });

        colCert.setCellFactory(column -> new TableCell<Pdf, String>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (!empty && item != null) {
                    Hyperlink certLink = new Hyperlink(item);
                    certLink.setOnAction(event -> onCertLink(event));
                    setGraphic(certLink);
                }
                else {
                    setGraphic(null);
                }
            }
        });

    }

    private void onCertLink(ActionEvent event) {
        System.out.println(event);
    }
}
