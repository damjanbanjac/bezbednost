package Busep.Repository;

import Busep.model.OCSP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.math.BigInteger;
import java.util.List;


@Repository
public interface OCSPRepository extends JpaRepository<OCSP, Long> {

    OCSP findOneById(long id);

    List<OCSP> findAllByAdminId(long id);

    OCSP findOneBySerialNumber(BigInteger serialNumber);
}
