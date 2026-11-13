import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeEquipmentHealthAndRisk,
  evaluateSensorReadingAnomaly,
  analyzeEnergyIntelligence,
  isDuplicateWorkflowExecution
} from './infrastructureMath.ts';

describe('VANTA AI Infrastructure Pure Logic Suite', () => {
  it('computes high health score and LOW risk for nominal equipment telemetry', () => {
    const res = computeEquipmentHealthAndRisk({
      temperature_c: 52,
      vibration_mm_s: 1.8,
      power_kw: 11,
      rated_power_kw: 15,
      runtime_hours: 2200,
      mtbf_hours: 12000,
      recent_anomaly_count: 0,
      days_since_maintenance: 25
    });
    assert.ok(res.health_score >= 90);
    assert.equal(res.risk_level, 'LOW');
    assert.ok(res.rul_estimated_hours > 5000);
  });

  it('detects CRITICAL failure risk when vibration and temperature breach ISO-10816 limits', () => {
    const res = computeEquipmentHealthAndRisk({
      temperature_c: 94.5,
      vibration_mm_s: 9.2,
      power_kw: 18.5,
      rated_power_kw: 15,
      runtime_hours: 9500,
      mtbf_hours: 10000,
      recent_anomaly_count: 4,
      days_since_maintenance: 240
    });
    assert.ok(res.health_score < 30);
    assert.equal(res.risk_level, 'CRITICAL');
    assert.ok(res.failure_risk_pct >= 70);
    assert.ok(res.contributing_factors.some(f => f.includes('Critical vibration')));
  });

  it('flags sensor threshold breaches and statistical spikes accurately', () => {
    const nominal = evaluateSensorReadingAnomaly(48.0, [47.5, 48.2, 47.9, 48.1, 47.8], 20, 75);
    assert.equal(nominal.is_anomaly, false);
    assert.equal(nominal.severity, 'NOMINAL');

    const highBreach = evaluateSensorReadingAnomaly(88.0, [47.5, 48.2, 47.9, 48.1, 47.8], 20, 75);
    assert.equal(highBreach.is_anomaly, true);
    assert.equal(highBreach.threshold_breach, 'HIGH_LIMIT');
    assert.equal(highBreach.severity, 'CRITICAL');

    assert.throws(() => evaluateSensorReadingAnomaly(NaN, [1, 2, 3]), /Invalid sensor value/);
  });

  it('distinguishes estimated energy savings from verified metered savings', () => {
    const report = analyzeEnergyIntelligence(
      {
        active_power_kw: 480,
        baseline_power_kw: 380,
        power_factor: 0.84,
        idle_equipment_kw: 22,
        production_units_per_hr: 120,
        electricity_tariff_usd_per_kwh: 0.15
      },
      1200 // verified kWh saved
    );
    assert.equal(report.abnormal_consumption, true);
    assert.equal(report.power_factor_penalty_risk, true);
    assert.ok(report.estimated_wastage_kw > 22);
    assert.ok(report.estimated_monthly_savings_usd > 0);
    assert.equal(report.verified_monthly_savings_usd, 180);
  });

  it('enforces duplicate-action protection for active or recently executed workflows', () => {
    const now = 1_700_000_000_000;
    const existing = [
      {
        template_id: 'WF-TPL-MAINT-ISOLATION',
        target_asset_id: 'EQ-CNC-01',
        status: 'PENDING_APPROVAL',
        created_at_ms: now - 30_000
      }
    ];
    const dupCheck = isDuplicateWorkflowExecution(existing, 'WF-TPL-MAINT-ISOLATION', 'EQ-CNC-01', now);
    assert.equal(dupCheck.duplicate, true);
    assert.equal(dupCheck.blocking_status, 'PENDING_APPROVAL');

    const diffAsset = isDuplicateWorkflowExecution(existing, 'WF-TPL-MAINT-ISOLATION', 'EQ-TURB-02', now);
    assert.equal(diffAsset.duplicate, false);
  });
});
