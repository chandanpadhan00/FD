

This document contains the complete layout of extracted fields (both PCD and PHI datasets) belonging to the view `asnfdm.pcd_phi_consolidated_vw`, followed by the SQL scripts utilized for fraud and anomaly detection.

---

## 1. Column Inventory (`asnfdm.pcd_phi_consolidated_vw`)

### PCD Fields (Patient Case Details & Insurance)

#### Case & Eligibility Core Metrics
* `patient_id`
* `case_id`
* `sub_case_id`
* `case_enrollment_status`
* `drug`
* `file_receipt_date_time`
* `case_created_date`
* `case_determination_date`
* `case_determination_month`
* `case_determination_year`
* `case_status`
* `case_sub_status`
* `case_sub_status_reason_code`
* `case_status_date`
* `case_sub_status_date`
* `case_reason_code_date`
* `case_sub_status_month`
* `case_sub_status_year`
* `eligibility_start_date`
* `eligibility_start_month`
* `eligibility_start_year`
* `eligibility_end_date`
* `eligibility_end_month`
* `eligibility_end_year`
* `last_ship_date`

#### Enrollment & FPL (Federal Poverty Level) Metrics
* `enrollment_status`
* `enrollment_sub_status`
* `enrollment_reason_code`
* `patient_fpl_case_determination`
* `patient_fpl_case_determination_flag`
* `patient_fpl_reported`
* `patient_fpl_poi`
* `patient_fpl_validated`

#### Household, Income & Prior Authorization (PA) Metrics
* `patient_household_size_case_determination`
* `patient_household_size_reported`
* `patient_household_size_validated`
* `patient_income_case_determination`
* `patient_income_case_determination_flag`
* `patient_income_reported`
* `patient_income_poi`
* `patient_income_validated`
* `patient_net_worth_case_determination`
* `patient_net_worth_reported`
* `patient_authorization`
* `patient_authorization_date`
* `patient_certification`
* `patient_certification_date`
* `health_data_consent_signature`
* `health_data_consent_signature_date`
* `pa_effective_date`
* `pa_end_date`
* `pa_status`
* `pa_status_reason`

#### Primary, Secondary & Pharmacy Insurance Information
* `primary_medical_insurance_start_date`
* `primary_medical_insurance_end_date`
* `primary_medical_insurance_payer_or_insurer`
* `primary_medical_insurance_plan_name`
* `primary_medical_insurance_type`
* `primary_medical_insurance_sub_type`
* `medical_insurance_primary_status`
* `secondary_medical_insurance_start_date`
* `secondary_medical_insurance_end_date`
* `secondary_medical_insurance_payer_or_insurer`
* `secondary_medical_insurance_plan_name`
* `secondary_medical_insurance_type`
* `secondary_medical_insurance_sub_type`
* `medical_insurance_secondary_status`
* `pharmacy_insurance_start_date`
* `pharmacy_insurance_end_date`
* `pharmacy_insurance_payer_or_insurer`
* `pharmacy_insurance_plan_name`
* `pharmacy_insurance_type`
* `pharmacy_insurance_sub_type`
* `pharmacy_insurance_primary_status`

#### Medical Director (MD) & Facility Demographics
* `amgen_pulse_id`
* `rx_facility_id`
* `patient_birth_year`
* `patient_gender`
* `patient_residency_status`
* `md_address_1`
* `md_address_2`
* `md_city`
* `md_fax`
* `md_first_name`
* `md_last_name`
* `md_phone`
* `md_state`
* `md_zip`
* `md_npi`
* `office_contact_first_name`
* `office_contact_last_name`
* `last_order_date`
* `overnetworth`
* `lis_received`
* `rx_facility_name`
* `rx_facility_from`
* `rx_facility_to`
* `rx_facility_to_address`

#### Health Plan (HP) & Insurance Determination Fields
* `hp_determination_start_date`
* `hp_determination_end_date`
* `hp_determination_payer_or_insurer`
* `hp_determination_plan_name`
* `hp_determination_type`
* `hp_determination_sub_type`
* `hp_determination_status`
* `sec_pharm_ins_effective_date__c`
* `sec_pharm_ins_effective_end_date__c`
* `sec_pharm_ins_payer_insurer__c`
* `sec_pharm_ins_plan_name__c`
* `sec_pharm_ins_plan_type__c`
* `pri_medical_insurance_used_for_determination`
* `pharm_ins_used_for_determination`
* `sec_pharm_ins_used_for_determination`
* `pri_medical_insurance_start_date_used_for_determination`
* `pri_medical_insurance_end_date_used_for_determination`
* `pri_medical_insurance_payer_insurer_used_for_determination`
* `pri_medical_insurance_plan_name_used_for_determination`
* `pri_medical_insurance_type_used_for_determination`
* `sec_medical_insurance_start_date_used_for_determination`
* `sec_medical_insurance_end_date_used_for_determination`
* `sec_medical_insurance_payer_insurer_used_for_determination`
* `sec_medical_insurance_plan_name_used_for_determination`
* `sec_medical_insurance_type_used_for_determination`
* `pharm_ins_effective_date_c_used_for_determination`
* `pharm_ins_effective_end_date_c_used_for_determination`
* `pharm_ins_payer_insurer_c_used_for_determination`
* `pharm_ins_plan_name_c_used_for_determination`
* `pharm_ins_plan_type_c_used_for_determination`
* `sec_pharm_ins_effective_date_c_used_for_determination`
* `sec_pharm_ins_effective_end_date_c_used_for_determination`
* `sec_pharm_ins_payer_insurer_c_used_for_determination`
* `sec_pharm_ins_plan_name_c_used_for_determination`
* `sec_pharm_ins_plan_type_c_used_for_determination`

### PHI Fields (Protected Health Information)
* `patient_state`
* `phi_patient_id`
* `lname`
* `fname`
* `mi`
* `gender`
* `dob`
* `addr1`
* `addr_city`
* `addr_state`
* `addr_zip`
* `phone_preferred`
* `phone_alternate`
* `email_addr`
* `is_latest`
* `qc_passed`
* `external_source`
* `dummy`

---

## 2. Fraud & Quality Control Queries (`asnf_fraud_qc.sql`) --These are just my initial thoughts

```sql
-- FRAUD detection

-- a) many orders from same Address
select drug, addr1, addr_city, addr_state, addr_zip, count(distinct case_id) number_cases
from
asnfdm.pcd_phi_consolidated_vw
where addr1 is not null
group by drug, addr1, addr_city, addr_state, addr_zip
having count(distinct case_id) > 5
order by count(distinct case_id) desc, drug, addr1, addr_city, addr_state, addr_zip;

-- a) many orders from same Phone #
select drug, phone_preferred, count(distinct case_id) number_cases
from 
asnfdm.pcd_phi_consolidated_vw
where phone_preferred is not null
group by drug, phone_preferred
having count(distinct case_id) > 5
order by count(distinct case_id) desc, drug, phone_preferred;

-- c) orders from Correctional facilities or Prisons
select drug, addr1, addr_city, addr_state, addr_zip, count(distinct case_id) number_cases
from
asnfdm.pcd_phi_consolidated_vw
where addr1 is not null
and btrim(upper(addr1)) like '%CORRECTION%'
group by drug, addr1, addr_city, addr_state, addr_zip
--having count(distinct case_id) > 5
order by count(distinct case_id) desc, drug, addr1, addr_state, addr_zip;

-- join/include other fields
SELECT
    t.*,
    a.number_cases
FROM asnfdm.pcd_phi_consolidated_vw t
JOIN (
    SELECT
        drug, addr1, addr_city, addr_state, addr_zip,
        COUNT(DISTINCT case_id) AS number_cases
    FROM asnfdm.pcd_phi_consolidated_vw
    WHERE drug IS NOT NULL
        AND addr1 IS NOT NULL
    GROUP BY
        drug, addr1, addr_city, addr_state, addr_zip
    HAVING COUNT(DISTINCT case_id) > 5
) a
ON t.drug = a.drug
AND t.addr1 = a.addr1
AND t.addr_city = a.addr_city -- Note: Corrected typo from 'a.city' to 'a.addr_city'
AND t.addr_zip = a.addr_zip
ORDER BY
    a.number_cases DESC,
    t.drug, t.addr1, t.addr_city, t.addr_state, t.addr_zip, t.case_id;