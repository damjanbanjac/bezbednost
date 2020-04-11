package Busep.Services;

import Busep.Repository.OCSPRepository;
import Busep.model.OCSP;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.List;

@Service
@SuppressWarnings({"unused", "InfiniteRecursion", "SpellCheckingInspection", "ConstantConditions"})
public class OCSPService {

        private String currentDate = java.time.LocalDate.now().toString();

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
            if (revokedCert != null){
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
}
