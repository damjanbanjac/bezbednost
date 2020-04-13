package Busep.ModelDTO;

public class ExtensionDTO {
    private Boolean digitalSignature;
    private Boolean keyEncipherment;
    private Boolean keyAgreement;
    private Boolean tLSWebserverauthentication;
    private Boolean tLSWebclientauthentication;
    private Boolean  emailProtection;
    private Boolean nonRepudiation;
    private  String codeSigning;

    public ExtensionDTO() {

    }

    public Boolean getDigitalSignature() {
        return digitalSignature;
    }

    public void setDigitalSignature(Boolean digitalSignature) {
        this.digitalSignature = digitalSignature;
    }

    public Boolean getKeyEncipherment() {
        return keyEncipherment;
    }

    public void setKeyEncipherment(Boolean keyEncipherment) {
        this.keyEncipherment = keyEncipherment;
    }

    public Boolean getKeyAgreement() {
        return keyAgreement;
    }

    public void setKeyAgreement(Boolean keyAgreement) {
        this.keyAgreement = keyAgreement;
    }

    public Boolean gettLSWebserverauthentication() {
        return tLSWebserverauthentication;
    }

    public void settLSWebserverauthentication(Boolean tLSWebserverauthentication) {
        this.tLSWebserverauthentication = tLSWebserverauthentication;
    }

    public Boolean gettLSWebclientauthentication() {
        return tLSWebclientauthentication;
    }

    public void settLSWebclientauthentication(Boolean tLSWebclientauthentication) {
        this.tLSWebclientauthentication = tLSWebclientauthentication;
    }

    public Boolean getEmailProtection() {
        return emailProtection;
    }

    public void setEmailProtection(Boolean emailProtection) {
        this.emailProtection = emailProtection;
    }

    public Boolean getNonRepudiation() {
        return nonRepudiation;
    }

    public void setNonRepudiation(Boolean nonRepudiation) {
        this.nonRepudiation = nonRepudiation;
    }

    public String getCodeSigning() {
        return codeSigning;
    }

    public void setCodeSigning(String codeSigning) {
        this.codeSigning = codeSigning;
    }
}
