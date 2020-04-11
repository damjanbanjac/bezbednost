package Busep.Services;

import Busep.Repository.OCSPRepository;
import Busep.model.OCSP;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
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

    public boolean checkValidityOfOneCertificate(X509Certificate certificate, X509Certificate issuerCert) throws NullPointerException {
        OCSP revokedCert = ocspRepository.findOneBySerialNumber(certificate.getSerialNumber());
        if (revokedCert != null) {
            return false; //povucen je
        }
        else {
            return true; //nije povucen
        }
    }

    public boolean revokeCertificate(X509Certificate certificate, long id) throws NullPointerException {
        OCSP ocsp1 = ocspRepository.findOneBySerialNumber(certificate.getSerialNumber());
        if(ocsp1 == null){
            OCSP ocsp2 = new OCSP();
            ocsp2.setAdminId(id);
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

    public Boolean checkValidityOfParents(X509Certificate certificate) throws NullPointerException {
        X509Certificate parent = null; //treba mu nekako izvuci parenta od certificate

        boolean validity;
        validity = checkValidityOfOneCertificate(certificate, parent);

        String currentDate = java.time.LocalDate.now().toString();

        while(true){

            if(!checkDate(certificate, currentDate))
            return false;

            if(!validity)
                return false;

            if(false)
                return false; //ovde treba proveriti digitalni potpis


            if(certificate.equals(parent))
                return true;

            checkValidityOfParents(parent);
        }

    }

    private boolean checkDate(X509Certificate certificate, String date){
        SimpleDateFormat iso8601Formater = new SimpleDateFormat("yyyy-MM-dd");

        if(certificate == null){
            return false;
        }
        try {
            Date currentDate = iso8601Formater.parse(date);
            certificate.checkValidity(currentDate);
            return true;
        }catch(CertificateExpiredException e) {
        }catch(CertificateNotYetValidException e) {
        }catch (ParseException e) {
        }

        return false;
    }

}
