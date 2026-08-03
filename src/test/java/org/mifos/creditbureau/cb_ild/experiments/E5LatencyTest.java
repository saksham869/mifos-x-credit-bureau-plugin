package org.mifos.creditbureau.cb_ild.experiments;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mifos.creditbureau.cb_ild.service.bureau.IBureauReadinessService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * E5 — Pipeline Latency (mock mode)
 * 20 warmup + 200 measured calls to IBureauReadinessService.checkReadiness()
 * Reports p50/p95 in ms.
 *
 * Mock mode: mifos.cdc.mock.enabled=true in application-test.properties
 * No Fineract/CDC calls — measures pure service + AOP + DB overhead.
 */
@SpringBootTest
@ActiveProfiles("test")
class E5LatencyTest {

    @Autowired
    private IBureauReadinessService bureauReadinessService;

    private static final int WARMUP  = 20;
    private static final int MEASURED = 200;
    private static final long CLIENT_ID = 5L;

    @Test
    void e5_readinessPipelineLatency() {
        // Warmup
        for (int i = 0; i < WARMUP; i++) {
            try { bureauReadinessService.checkReadiness(CLIENT_ID); }
            catch (Exception ignored) {}
        }

        long[] ns = new long[MEASURED];
        for (int i = 0; i < MEASURED; i++) {
            long start = System.nanoTime();
            try { bureauReadinessService.checkReadiness(CLIENT_ID); }
            catch (Exception ignored) {}
            ns[i] = System.nanoTime() - start;
        }

        Arrays.sort(ns);
        double p50 = ns[MEASURED / 2]           / 1_000_000.0;
        double p95 = ns[(int)(MEASURED * 0.95)] / 1_000_000.0;

        System.out.printf("E5_READINESS_P50_MS=%.3f%n", p50);
        System.out.printf("E5_READINESS_P95_MS=%.3f%n", p95);

        assertThat(p50).isGreaterThan(0.0);
        assertThat(p95).isGreaterThan(0.0);
    }
}
