"""
Python complement to fraud_rule_engine.sql.

Handles the one lens SQL genuinely struggles with: multi-hop identity rings.
A same-field GROUP BY only sees direct shares (patient A and B share an
email). It can't see a transitive chain -- A links to B via phone, B links
to C via email -- where A and C never share anything directly but are part
of the same ring. Graph connected-components sees that; SQL self-joins
don't scale to it cleanly.

Writes results into the same asnf_fraud.flags table the SQL detectors use,
under rule_id = 'GRF05', reading its own thresholds from asnf_fraud.rule_config
exactly like the SQL detectors do -- so it rolls into the same
asnf_fraud.case_risk_score alongside everything else.
"""

import argparse
import os
import uuid
from itertools import combinations
from pathlib import Path

import networkx as nx
import pandas as pd
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from rapidfuzz.distance import Levenshtein
from rapidfuzz.fuzz import ratio as fuzzy_ratio

RULE_ID = "GRF05"
SOURCE_VIEW = "asnfdm.pcd_phi_consolidated_vw"

CONTACT_FIELD_PAIRS = [
    ("email_addr", "email_addr"),
    ("phone_preferred", "phone_preferred"),
    ("phone_preferred", "phone_alternate"),
    ("phone_alternate", "phone_alternate"),
]


def get_connection():
    load_dotenv(Path(__file__).resolve().parent / ".env")
    return psycopg2.connect(
        host=os.environ["PGHOST"],
        port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ["PGDATABASE"],
        user=os.environ["PGUSER"],
        password=os.environ["PGPASSWORD"],
    )


def get_config(conn, rule_id: str, param_name: str) -> str:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT param_value FROM asnf_fraud.rule_config WHERE rule_id = %s AND param_name = %s",
            (rule_id, param_name),
        )
        row = cur.fetchone()
    if row is None:
        raise ValueError(f"Missing config: {rule_id}.{param_name}")
    return row[0]


def load_identity_frame(conn) -> pd.DataFrame:
    query = f"""
        SELECT case_id, patient_id, lname, fname, dob,
               phone_preferred, phone_alternate, email_addr
        FROM {SOURCE_VIEW}
        WHERE patient_id IS NOT NULL
    """
    return pd.read_sql(query, conn)


def add_link(graph: nx.Graph, a, b, reason: str, value) -> None:
    if a == b:
        return
    if graph.has_edge(a, b):
        graph[a][b]["links"].append({"reason": reason, "value": str(value)})
    else:
        graph.add_edge(a, b, links=[{"reason": reason, "value": str(value)}])


def build_identity_graph(df: pd.DataFrame, max_lname_distance: int, min_fname_similarity: float) -> nx.Graph:
    graph = nx.Graph()
    patients = df.drop_duplicates(subset="patient_id").set_index("patient_id")
    graph.add_nodes_from(patients.index)

    for left_field, right_field in CONTACT_FIELD_PAIRS:
        left = patients[[left_field]].dropna().reset_index()
        right = patients[[right_field]].dropna().reset_index()
        merged = left.merge(right, left_on=left_field, right_on=right_field, suffixes=("_a", "_b"))
        merged = merged[merged["patient_id_a"] < merged["patient_id_b"]]
        for _, row in merged.iterrows():
            add_link(graph, row["patient_id_a"], row["patient_id_b"], f"shared_{left_field}_{right_field}", row[left_field])

    dob_groups = patients.dropna(subset=["dob", "lname", "fname"]).reset_index().groupby("dob")
    for dob, group in dob_groups:
        if len(group) < 2:
            continue
        for (_, a), (_, b) in combinations(group.iterrows(), 2):
            lname_distance = Levenshtein.distance(a["lname"].upper(), b["lname"].upper())
            fname_similarity = fuzzy_ratio(a["fname"].upper(), b["fname"].upper())
            if lname_distance <= max_lname_distance and fname_similarity >= min_fname_similarity:
                add_link(
                    graph, a["patient_id"], b["patient_id"], "fuzzy_name_dob_match",
                    f"{a['fname']} {a['lname']} vs {b['fname']} {b['lname']} (dob={dob})",
                )

    return graph


def find_rings(graph: nx.Graph, min_ring_size: int):
    for component in nx.connected_components(graph):
        if len(component) < min_ring_size:
            continue
        subgraph = graph.subgraph(component)
        edges = [
            {"a": a, "b": b, "links": data["links"]}
            for a, b, data in subgraph.edges(data=True)
        ]
        yield sorted(component), edges


def write_flags(conn, run_id: str, df: pd.DataFrame, rings, points: float) -> int:
    case_lookup = df.groupby("patient_id")["case_id"].apply(lambda s: sorted(set(s))).to_dict()

    rows = []
    for member_patients, edges in rings:
        evidence = {
            "ring_size": len(member_patients),
            "member_patient_ids": member_patients,
            "linking_edges": edges,
        }
        for patient_id in member_patients:
            for case_id in case_lookup.get(patient_id, []):
                rows.append((run_id, case_id, patient_id, RULE_ID, points, psycopg2.extras.Json(evidence)))

    if not rows:
        return 0

    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            """
            INSERT INTO asnf_fraud.flags (run_id, case_id, patient_id, rule_id, points, evidence)
            VALUES %s
            """,
            rows,
        )
    conn.commit()
    return len(rows)


def run_sql_rules(conn) -> str:
    with conn.cursor() as cur:
        cur.execute("SELECT asnf_fraud.run_all_rules()")
        run_id = cur.fetchone()[0]
    conn.commit()
    return str(run_id)


def main():
    parser = argparse.ArgumentParser(description="Run the SQL rule engine plus the Python identity-ring detector under one shared run_id.")
    parser.add_argument("--skip-sql", action="store_true", help="Only run the Python detector, skip asnf_fraud.run_all_rules()")
    parser.add_argument("--run-id", type=str, default=None, help="Reuse an existing run_id instead of starting a new SQL run")
    args = parser.parse_args()

    conn = get_connection()
    try:
        if args.run_id:
            run_id = args.run_id
        elif args.skip_sql:
            run_id = str(uuid.uuid4())
        else:
            run_id = run_sql_rules(conn)
            print(f"SQL rule engine complete. run_id={run_id}")

        min_ring_size = int(get_config(conn, RULE_ID, "min_ring_size"))
        max_lname_distance = int(get_config(conn, RULE_ID, "max_lname_distance"))
        min_fname_similarity = float(get_config(conn, RULE_ID, "min_fname_similarity"))
        points = float(get_config(conn, RULE_ID, "points"))

        df = load_identity_frame(conn)
        graph = build_identity_graph(df, max_lname_distance, min_fname_similarity)
        rings = list(find_rings(graph, min_ring_size))

        flag_count = write_flags(conn, run_id, df, rings, points)
        print(f"Identity-ring detector complete. run_id={run_id} rings_found={len(rings)} flags_written={flag_count}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
