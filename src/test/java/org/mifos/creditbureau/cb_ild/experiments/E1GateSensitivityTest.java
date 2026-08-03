package org.mifos.creditbureau.cb_ild.experiments;

import org.junit.jupiter.api.Test;
import org.mifos.creditbureau.cb_ild.client.FineractClientData;
import org.mifos.creditbureau.cb_ild.service.kyc.KycCompletenessScorer;
import org.mifos.creditbureau.cb_ild.service.kyc.KycScoringProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * E1 — KYC Gate Sensitivity (RQ1)
 * n=10,000 seed=42 real KycCompletenessScorer + KycScoringProperties.
 * Presence: RFC=.85 DOB=.90 fn=.98 ln=.98 addr=.80 phone=.70
 */
@SpringBootTest
@ActiveProfiles("test")
class E1GateSensitivityTest {

    static final int N = 10_000;
    static final long SEED = 42L;
    static final double RFC=.85, DOB=.90, FN=.98, LN=.98, ADDR=.80, PHONE=.70;

    @Autowired KycCompletenessScorer scorer;
    @Autowired KycScoringProperties props;

    @Test
    void e1_sweep() {
        Random rng = new Random(SEED);
        List<FineractClientData> clients = new ArrayList<>(N);
        int rfcVeto = 0;

        for (int i = 0; i < N; i++) {
            String rfc   = rng.nextDouble() < RFC   ? "RFC"+i : null;
            List<Integer> dob = rng.nextDouble() < DOB ? List.of(1985,6,15) : null;
            String fn    = rng.nextDouble() < FN   ? "Juan"  : null;
            String ln    = rng.nextDouble() < LN   ? "Garcia": null;
            boolean ha   = rng.nextDouble() < ADDR;
            String addr  = ha ? "Av. 100" : null;
            String city  = ha ? "CDMX"    : null;
            String phone = rng.nextDouble() < PHONE ? "555" : null;
            if (rfc == null) rfcVeto++;
            clients.add(new FineractClientData(
                i, fn, ln, rfc, dob, phone, null, addr, null, null, city, null, null, null));
        }

        int[] taus = {50, 60, 70, 80, 90};
        for (int tau : taus) {
            props.setThreshold(tau);
            int blocked = 0;
            for (var c : clients) if (!scorer.score(c).ready()) blocked++;
            System.out.printf("E1_SWEEP tau=%d blocked=%d avoided=%.1f%%%n",
                tau, blocked, 100.0*blocked/N);
        }
        props.setThreshold(70);

        System.out.printf("E1_RFC_VETO_COUNT=%d PCT=%.1f%%%n", rfcVeto, 100.0*rfcVeto/N);
        assertThat(rfcVeto).isBetween((int)(N*.10),(int)(N*.20));
    }
}
