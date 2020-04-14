package Busep.Services;

import Busep.Repository.OCSPRepository;
import Busep.model.OCSP;
import keyStore.KeyStoreReader;
import keyStore.KeyStoreWriter;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
@SuppressWarnings({"unused", "InfiniteRecursion", "SpellCheckingInspection", "ConstantConditions"})
public class OCSPService {

    @Autowired
    private OCSPRepository ocspRepository;

    public OCSP getOCSP(long id) {
        return ocspRepository.findOneById(id);
    }

    public List<OCSP> getAll() {
        return ocspRepository.findAll();
    }

    public List<OCSP> getAllByAdminId(long id) {
        return ocspRepository.findAllByAdminId(id);
    }

    public boolean checkValidityOfOneCertificate(X509Certificate certificate) throws NullPointerException {
        OCSP revokedCert = ocspRepository.findOneBySerialNumber(certificate.getSerialNumber());
        String p = "";
        if (revokedCert != null) {
            p = "false";
            System.out.println(p);
            return false; //povucen je

        }
        else {
            p = "true";
            System.out.println(p);
            return true; //nije povucen
        }

    }

    public boolean revokeCertificate(X509Certificate certificate) throws NullPointerException {
        OCSP ocsp1 = ocspRepository.findOneBySerialNumber(certificate.getSerialNumber());
        if(ocsp1 == null){
            OCSP ocsp2 = new OCSP();

            ocsp2.setSerialNumber(certificate.getSerialNumber());
            ocspRepository.save(ocsp2);
        } //mozemo staviti exception da nam napise da je mozda vec bio povucen ako ne udje u if
        return true;
    }

    public boolean denyRevokation(X509Certificate certificate, long id) throws NullPointerException {
        OCSP ocsp = ocspRepository.findOneBySerialNumber(certificate.getSerialNumber());
        if (ocsp != null && ocsp.getAdminId() == id){
            ocspRepository.deleteById(ocsp.getId());
        } //mozemo staviti exception ako slucajno nije bio obrisan
        return true;
    }

    public Boolean checkValidityOfParents(X509Certificate certificate) throws NullPointerException, CertificateEncodingException {
        X509Certificate parent = null;
        KeyStoreWriter ks=new KeyStoreWriter();
        char[] array = "tim14".toCharArray();

        X500Name x500name = new JcaX509CertificateHolder(certificate).getIssuer();
        RDN  uid = x500name.getRDNs(BCStyle.UID)[0];
        String alias = IETFUtils.valueToString(uid.getFirst().getValue());
        System.out.println(alias);

        ks.loadKeyStore("interCertificate.jks",array);
        KeyStoreReader kr = new KeyStoreReader();
        parent = (X509Certificate) kr.readCertificate("interCertificate.jks", "tim14", alias);

        boolean validity;
        boolean validityData;
        boolean p = false;
        validity = checkValidityOfOneCertificate(certificate);

        String currentDate = java.time.LocalDate.now().toString();
        System.out.println(currentDate);
        validityData = checkDate(certificate);
        String end = "";

        if(!validity) {
            //end = "notValid";
            p = false;
            return false;
        }

        if(!validityData) {
            //end = "notValid";
            p = false;
            return false;
        } else  if (alias.equals("123456")) {
            System.out.println("usao");
            end = "end";
            p = true;
            return true;
        } else  {
          System.out.println("prosao");
         return checkValidityOfParents(parent);
        }

    }

    private boolean checkDate(X509Certificate certificate){
        SimpleDateFormat iso8601Formater = new SimpleDateFormat("yyyy-MM-dd");

        if(certificate == null){
            return false;
        }
        Date certDate = certificate.getNotAfter();
        final Instant now = Instant.now();
        final Date nowDate = Date.from(now);
        if(certDate.compareTo(nowDate) > 0) {
            System.out.println(certDate);
            System.out.println(nowDate);
            System.out.println("veci je");
            return true;
        }
        else {
            return false;
        }
    }

}
