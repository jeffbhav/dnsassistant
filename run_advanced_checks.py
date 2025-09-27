# run_advanced_checks.py
import sqlite3
import argparse
import os
import sys
import json
import time
from datetime import datetime
import configparser
import dns.resolver
import dns.exception
import dns.flags
import dns.reversename

# --- Configuration Loading ---
config_parser_obj = configparser.ConfigParser()
CONFIG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")

DB_NAME_CFG = "dns_lookup_results.db"
STATUS_FILE_DIR_NAME_CFG = "status_updates"
DEFAULT_TIMEOUT_CFG = 5
DEFAULT_RETRIES_CFG = 2

if os.path.exists(CONFIG_FILE_PATH):
    config_parser_obj.read(CONFIG_FILE_PATH)
    DB_NAME_CFG = config_parser_obj.get('General', 'db_name', fallback=DB_NAME_CFG)
    STATUS_FILE_DIR_NAME_CFG = config_parser_obj.get('General', 'status_file_dir_name', fallback=STATUS_FILE_DIR_NAME_CFG)
    DEFAULT_TIMEOUT_CFG = config_parser_obj.getint('DNSChecker', 'default_timeout_seconds', fallback=DEFAULT_TIMEOUT_CFG)
    DEFAULT_RETRIES_CFG = config_parser_obj.getint('DNSChecker', 'default_retries', fallback=DEFAULT_RETRIES_CFG)

DB_NAME = DB_NAME_CFG
STATUS_FILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), STATUS_FILE_DIR_NAME_CFG)

# --- Helper Functions ---
def get_db_connection():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"DB Connection Error: {e}")
        return None

def update_status_file(batch_run_id, status_data):
    if not batch_run_id: return
    status_file_path = os.path.join(STATUS_FILE_DIR, f"status_{batch_run_id}.json")
    status_data["timestamp"] = datetime.now().isoformat()
    status_data["batch_run_id"] = batch_run_id
    try:
        with open(status_file_path, 'w') as sf:
            json.dump(status_data, sf, indent=2)
    except IOError as e:
        print(f"Error writing status file {status_file_path}: {e}")

def resolve_with_retries(domain_name, rdtype, resolver_obj, retries=DEFAULT_RETRIES_CFG): 
    for attempt in range(retries):
        try: return resolver_obj.resolve(domain_name, rdtype, raise_on_no_answer=False)
        except dns.resolver.Timeout:
            if attempt >= retries - 1: print(f"  Max retries timeout for {rdtype} {domain_name}."); return None
        except dns.resolver.NXDOMAIN: return None 
        except dns.resolver.NoAnswer: return [] 
        except dns.resolver.NoNameservers:
            if attempt >= retries -1: print(f"  Max retries NoNameservers for {rdtype} {domain_name}."); return None
        except dns.exception.DNSException as e: print(f"  DNS error {domain_name} {rdtype}: {e}"); return None
        time.sleep(1 * (attempt + 1)) 
    return None

# --- Main Logic ---
def main():
    parser = argparse.ArgumentParser(description="Run advanced DNS checks (DNSSEC, PTR).")
    parser.add_argument("--domains", nargs='+', help="Specific list of domains to check.")
    parser.add_argument("--batch-run-id", required=True, help="Unique ID for this batch run.")
    args = parser.parse_args()

    domains_to_check = args.domains
    if not domains_to_check:
        print("No domains provided to check.")
        return

    total_domains = len(domains_to_check)
    update_status_file(args.batch_run_id, {"status": "starting", "message": f"Starting advanced checks for {total_domains} domains.", "total_domains": total_domains, "processed_domains": 0})
    
    conn = get_db_connection()
    if not conn:
        update_status_file(args.batch_run_id, {"status": "error", "message": "DB connection failed."})
        return
        
    cursor = conn.cursor()
    resolver = dns.resolver.Resolver()
    resolver.timeout = DEFAULT_TIMEOUT_CFG

    for i, domain in enumerate(domains_to_check):
        update_status_file(args.batch_run_id, {"status": "processing", "message": f"Checking {domain}", "total_domains": total_domains, "processed_domains": i, "current_domain": domain})
        
        # --- DNSSEC Check ---
        dnssec_status = "Unchecked"
        dnssec_details = ""
        try:
            q = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
            response = dns.query.udp(q, resolver.nameservers[0], timeout=resolver.timeout)
            if response.rcode() == dns.rcode.NOERROR:
                if response.flags & dns.flags.AD:
                    dnssec_status = "Secure"
                    dnssec_details = "AD flag set, chain of trust validated by resolver."
                else:
                    answer = response.get_rrset(response.answer, 0) if len(response.answer) > 0 else None
                    if answer and answer.rdtype == dns.rdatatype.RRSIG:
                        dnssec_status = "Bogus"
                        dnssec_details = "RRSIGs found but AD flag not set; validation may have failed."
                    else:
                        dnssec_status = "Insecure"
                        dnssec_details = "No AD flag or signatures found. Domain not signed."
            else:
                dnssec_status = "Insecure"
                dnssec_details = f"Query for DNSKEY returned rcode {dns.rcode.to_text(response.rcode())}."
        except Exception as e:
            dnssec_status = "Error"
            dnssec_details = f"DNSSEC check failed: {type(e).__name__}"

        # --- PTR Check ---
        ptr_records_data = []
        a_records = []
        try:
            a_answers = resolve_with_retries(domain, 'A', resolver)
            if a_answers:
                a_records = [r.address for r in a_answers]
                for ip_address in a_records:
                    try:
                        reversed_name = dns.reversename.from_address(ip_address)
                        ptr_answer = resolve_with_retries(reversed_name, "PTR", resolver)
                        if ptr_answer:
                            hostnames = [rdata.to_text(omit_final_dot=True) for rdata in ptr_answer]
                            ptr_records_data.append({"ip": ip_address, "hostnames": hostnames})
                        else:
                            ptr_records_data.append({"ip": ip_address, "hostnames": ["No PTR Record"]})
                    except dns.resolver.NXDOMAIN:
                         ptr_records_data.append({"ip": ip_address, "hostnames": ["No PTR Record (NXDOMAIN)"]})
                    except Exception as e:
                        ptr_records_data.append({"ip": ip_address, "hostnames": [f"Error: {type(e).__name__}"]})
        except Exception as e:
            print(f"Error getting A records for PTR check on {domain}: {e}")

        # --- Update Database ---
        try:
            # Find the latest lookup_results ID for this domain to update
            cursor.execute("SELECT id FROM lookup_results WHERE domain_name = ? ORDER BY timestamp DESC LIMIT 1", (domain,))
            res = cursor.fetchone()
            if res:
                latest_id = res['id']
                cursor.execute("""
                    UPDATE lookup_results 
                    SET dnssec_status = ?, dnssec_details = ?, ptr_records = ?
                    WHERE id = ?
                """, (dnssec_status, dnssec_details, json.dumps(ptr_records_data), latest_id))
            else:
                print(f"  No existing record for {domain} found to update.")
        except sqlite3.Error as e:
            print(f"  DB Error updating record for {domain}: {e}")
        
    conn.commit()
    conn.close()

    final_message = f"Advanced checks complete for {total_domains} domains."
    print(final_message)
    update_status_file(args.batch_run_id, {"status": "complete", "message": final_message, "processed_domains": total_domains, "total_domains": total_domains})
    time.sleep(1)
    os.remove(os.path.join(STATUS_FILE_DIR, f"status_{args.batch_run_id}.json"))

if __name__ == "__main__":
    main()