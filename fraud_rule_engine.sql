ALTER TABLE asnf_fraud.rule_registry
    ADD COLUMN IF NOT EXISTS implementation TEXT NOT NULL DEFAULT 'sql'
    CHECK (implementation IN ('sql','python'));

UPDATE asnf_fraud.rule_registry SET implementation = 'python' WHERE rule_id = 'GRF05';

CREATE OR REPLACE FUNCTION asnf_fraud.run_all_rules()
RETURNS uuid
LANGUAGE plpgsql
AS $$
DECLARE
    v_run_id uuid := gen_random_uuid();
    v_rule   RECORD;
BEGIN
    FOR v_rule IN SELECT rule_id FROM asnf_fraud.rule_registry WHERE active AND implementation = 'sql' LOOP
        IF v_rule.rule_id !~ '^[A-Za-z0-9_]+$' THEN
            RAISE EXCEPTION 'Unsafe rule_id blocked from dynamic dispatch: %', v_rule.rule_id;
        END IF;

        EXECUTE format(
            'INSERT INTO asnf_fraud.flags (run_id, case_id, patient_id, rule_id, points, evidence)
             SELECT %L, case_id, patient_id, rule_id, points, evidence
             FROM asnf_fraud.detect_%s()',
            v_run_id, lower(v_rule.rule_id)
        );
    END LOOP;
    RETURN v_run_id;
END;
$$;
