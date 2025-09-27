# run_whois_lookup.py
import sqlite3
import requests
import json
import argparse
import time
import os
import sys 
from datetime import datetime
import configparser 

# --- Configuration Loading ---
config_parser_obj = configparser.ConfigParser()
CONFIG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")

if not os.path.exists(CONFIG_FILE_PATH):
    print(f"CRITICAL: Configuration file '{CONFIG_FILE_PATH}' not found. Using hardcoded defaults (not recommended).")
    DB_NAME_CFG = "dns_lookup_results.db"
    STATUS_FILE_DIR_NAME_CFG = "status_updates"
    WHOIS_API_BASE_URL_CFG = "https://api.whoxy.com/"
    WHOIS_API_RETRIES_CFG = 1 
    WHOIS_API_RETRY_DELAY_CFG = 2
    PRIVACY_KEYWORDS_STR_CFG = "Privacy Protect, Domains By Proxy, WhoisGuard, Contact Privacy, REDACTED FOR PRIVACY, Private Registration, Anonymized, Whois Privacy, See PrivacyGuardian.org, Whois privacy services, Domain Privacy, Privacy Service, Identity Protection, Guard Privacidad, Privacy Service Provided, Jewella Privacy LLC, JewellaPrivacy.com" 
else:
    config_parser_obj.read(CONFIG_FILE_PATH)
    try:
        DB_NAME_CFG = config_parser_obj.get('General', 'db_name', fallback="dns_lookup_results.db")
        STATUS_FILE_DIR_NAME_CFG = config_parser_obj.get('General', 'status_file_dir_name', fallback="status_updates")
        WHOIS_API_BASE_URL_CFG = config_parser_obj.get('WHOIS', 'whois_api_base_url', fallback="https://api.whoxy.com/")
        WHOIS_API_RETRIES_CFG = config_parser_obj.getint('WHOIS', 'api_retries', fallback=1)
        WHOIS_API_RETRY_DELAY_CFG = config_parser_obj.getint('WHOIS', 'api_retry_delay_seconds', fallback=2)
        PRIVACY_KEYWORDS_STR_CFG = config_parser_obj.get('WHOIS', 'privacy_keywords', fallback="Privacy Protect, Domains By Proxy, WhoisGuard, Contact Privacy, REDACTED FOR PRIVACY, Private Registration, Anonymized, Whois Privacy, See PrivacyGuardian.org, Whois privacy services, Domain Privacy, Privacy Service, Identity Protection, Guard Privacidad, Privacy Service Provided, Jewella Privacy LLC, JewellaPrivacy.com")


    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        print(f"ERROR reading from config.ini: {e}. Using some hardcoded defaults.")
        DB_NAME_CFG = getattr(config_parser_obj, 'get', lambda s,o,fallback: fallback)('General', 'db_name', fallback="dns_lookup_results.db")
        STATUS_FILE_DIR_NAME_CFG = getattr(config_parser_obj, 'get', lambda s,o,fallback: fallback)('General', 'status_file_dir_name', fallback="status_updates")
        WHOIS_API_BASE_URL_CFG = getattr(config_parser_obj, 'get', lambda s,o,fallback: fallback)('WHOIS', 'whois_api_base_url', fallback="https://api.whoxy.com/")
        WHOIS_API_RETRIES_CFG = 1
        WHOIS_API_RETRY_DELAY_CFG = 2
        PRIVACY_KEYWORDS_STR_CFG = "Privacy Protect, Domains By Proxy, WhoisGuard, Contact Privacy, REDACTED FOR PRIVACY, Private Registration, Anonymized, Whois Privacy, See PrivacyGuardian.org, Whois privacy services, Domain Privacy, Privacy Service, Identity Protection, Guard Privacidad, Privacy Service Provided, Jewella Privacy LLC, JewellaPrivacy.com"


DB_NAME = DB_NAME_CFG
WHOIS_API_BASE_URL = WHOIS_API_BASE_URL_CFG
STATUS_FILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), STATUS_FILE_DIR_NAME_CFG)
API_RETRIES = WHOIS_API_RETRIES_CFG
API_RETRY_DELAY = WHOIS_API_RETRY_DELAY_CFG
PRIVACY_KEYWORDS_LIST = [k.strip().lower() for k in PRIVACY_KEYWORDS_STR_CFG.split(',') if k.strip()]


def get_db_connection():
    try:
        conn = sqlite3.connect(DB_NAME) 
        conn.row_factory = sqlite3.Row 
        return conn
    except sqlite3.Error as e:
        print(f"DB Connection Error: {e}. This script might not be able to proceed.")
        return None

def get_domains_by_latest_category(category):
    conn = get_db_connection()
    if not conn: return [] 
    cursor = conn.cursor(); domains = []
    try:
        query = "SELECT DISTINCT lr1.domain_name FROM lookup_results lr1 WHERE lr1.timestamp = (SELECT MAX(lr2.timestamp) FROM lookup_results lr2 WHERE lr2.domain_name = lr1.domain_name) AND lr1.category = ?"
        cursor.execute(query, (category,))
        domains = [row['domain_name'] for row in cursor.fetchall()]
        print(f"Found {len(domains)} domains in category '{category}' for Whois.")
    except sqlite3.Error as e: print(f"DB error (get_domains_by_latest_category): {e}")
    finally:
        if conn: conn.close()
    return domains

def get_domains_by_ids(domain_ids_str):
    conn = get_db_connection()
    if not conn: return []
    cursor = conn.cursor(); domains = []
    if not domain_ids_str: print("No domain IDs provided."); return []
    try:
        domain_ids = [int(id_val) for id_val in domain_ids_str.split(',') if id_val.isdigit()]
        if not domain_ids: print("No valid numeric domain IDs."); return []
        placeholders = ','.join(['?'] * len(domain_ids))
        query = f"SELECT DISTINCT domain_name FROM lookup_results WHERE id IN ({placeholders})"
        cursor.execute(query, domain_ids)
        domains = [row['domain_name'] for row in cursor.fetchall()]
        print(f"Found {len(domains)} domains for IDs: {domain_ids_str}")
    except sqlite3.Error as e: print(f"DB error (get_domains_by_ids): {e}")
    except ValueError: print(f"Error: Invalid non-numeric in domain IDs: {domain_ids_str}")
    finally:
        if conn: conn.close()
    return domains

def get_domains_without_whois():
    conn = get_db_connection()
    if not conn: return []
    cursor = conn.cursor(); domains = []
    try:
        query_latest_no_whois = """
            SELECT DISTINCT T1.domain_name
            FROM (
                SELECT domain_name, MAX(timestamp) as max_ts
                FROM lookup_results
                GROUP BY domain_name
            ) AS LATEST_LR
            JOIN lookup_results T1 ON LATEST_LR.domain_name = T1.domain_name AND LATEST_LR.max_ts = T1.timestamp
            LEFT JOIN whois_records wr ON T1.domain_name = wr.domain_name
            WHERE wr.id IS NULL;
        """
        cursor.execute(query_latest_no_whois)
        rows = cursor.fetchall()
        domains = [row['domain_name'] for row in rows if row['domain_name']]
        print(f"Found {len(domains)} unique domains without any WHOIS records.")
    except sqlite3.Error as e:
        print(f"DB error fetching domains without WHOIS: {e}")
    finally:
        if conn: conn.close()
    return domains

def get_all_domains_from_db_list():
    conn = get_db_connection()
    if not conn: return []
    cursor = conn.cursor(); domains = []
    try:
        cursor.execute("SELECT DISTINCT domain_name FROM lookup_results ORDER BY domain_name")
        rows = cursor.fetchall()
        domains = [row['domain_name'] for row in rows if row['domain_name']]
        print(f"Found {len(domains)} unique domains in the database.")
    except sqlite3.Error as e:
        print(f"DB error fetching all domains: {e}")
    finally:
        if conn: conn.close()
    return domains


def _get_contact_field(contact_block, field_name, default_value="N/A"):
    if isinstance(contact_block, dict): return contact_block.get(field_name, default_value)
    return default_value

def parse_and_store_whois_data(conn, domain_name, whois_json_data, batch_run_id_for_logging="N/A"):
    if not conn: print(f"  DB not available for {domain_name}."); return False
    if not whois_json_data or whois_json_data.get("status") != 1:
        print(f"  Skipping DB store for {domain_name} due to unsuccessful API status or no data.")
        return False

    cursor = conn.cursor()
    rc = whois_json_data.get("registrant_contact") if isinstance(whois_json_data.get("registrant_contact"), dict) else {}
    ac = whois_json_data.get("administrative_contact") if isinstance(whois_json_data.get("administrative_contact"), dict) else {}
    tc = whois_json_data.get("technical_contact") if isinstance(whois_json_data.get("technical_contact"), dict) else {}
    
    is_privacy_enabled = 0
    raw_text_lower = (whois_json_data.get("raw_whois", "") or "").lower()
    registrant_name_lower = (_get_contact_field(rc, "full_name", "") or "").lower()
    registrant_org_lower = (_get_contact_field(rc, "company_name", "") or "").lower()
    registrant_email_lower = (_get_contact_field(rc, "email_address", "") or "").lower()
    searchable_text = f"{raw_text_lower} {registrant_name_lower} {registrant_org_lower} {registrant_email_lower}"
    for keyword in PRIVACY_KEYWORDS_LIST:
        if keyword in searchable_text:
            is_privacy_enabled = 1
            break

    data = { "domain_name": domain_name, "api_status": whois_json_data.get("status"), 
        "api_status_reason": whois_json_data.get("status_reason"), "domain_registered": whois_json_data.get("domain_registered"),
        "registered_on_timestamp": whois_json_data.get("registered_on"), "created_date_iso": whois_json_data.get("created_date"),
        "updated_date_iso": whois_json_data.get("updated_date"), "expiry_date_iso": whois_json_data.get("expiry_date"),
        "registrar_name": whois_json_data.get("registrar_name"), "registrar_iana_id": whois_json_data.get("registrar_iana_id"),
        "registrar_url": whois_json_data.get("registrar_url"), "registrar_email": whois_json_data.get("registrar_email_address"),
        "registrar_phone": whois_json_data.get("registrar_phone_number"),
        "registrant_contact_name": _get_contact_field(rc, "full_name"), "registrant_contact_company": _get_contact_field(rc, "company_name"),
        "registrant_contact_address": _get_contact_field(rc, "street_address"), "registrant_contact_city": _get_contact_field(rc, "city_name"),
        "registrant_contact_state": _get_contact_field(rc, "region_name"), "registrant_contact_zipcode": _get_contact_field(rc, "zip_code"),
        "registrant_contact_country_code": _get_contact_field(rc, "country_code"), "registrant_contact_country_name": _get_contact_field(rc, "country_name"),
        "registrant_contact_phone": _get_contact_field(rc, "phone_number"), "registrant_contact_fax": _get_contact_field(rc, "fax_number"),
        "registrant_contact_email": _get_contact_field(rc, "email_address"),
        "administrative_contact_name": _get_contact_field(ac, "full_name"), "administrative_contact_company": _get_contact_field(ac, "company_name"),
        "administrative_contact_address": _get_contact_field(ac, "street_address"), "administrative_contact_city": _get_contact_field(ac, "city_name"),
        "administrative_contact_state": _get_contact_field(ac, "region_name"), "administrative_contact_zipcode": _get_contact_field(ac, "zip_code"),
        "administrative_contact_country_code": _get_contact_field(ac, "country_code"), "administrative_contact_country_name": _get_contact_field(ac, "country_name"),
        "administrative_contact_phone": _get_contact_field(ac, "phone_number"), "administrative_contact_fax": _get_contact_field(ac, "fax_number"),
        "administrative_contact_email": _get_contact_field(ac, "email_address"),
        "technical_contact_name": _get_contact_field(tc, "full_name"), "technical_contact_company": _get_contact_field(tc, "company_name"),
        "technical_contact_address": _get_contact_field(tc, "street_address"), "technical_contact_city": _get_contact_field(tc, "city_name"),
        "technical_contact_state": _get_contact_field(tc, "region_name"), "technical_contact_zipcode": _get_contact_field(tc, "zip_code"),
        "technical_contact_country_code": _get_contact_field(tc, "country_code"), "technical_contact_country_name": _get_contact_field(tc, "country_name"),
        "technical_contact_phone": _get_contact_field(tc, "phone_number"), "technical_contact_fax": _get_contact_field(tc, "fax_number"),
        "technical_contact_email": _get_contact_field(tc, "email_address"),
        "name_servers": ", ".join(whois_json_data.get("name_servers", []) if whois_json_data.get("name_servers") else ["N/A"]),
        "domain_status": ", ".join(whois_json_data.get("domain_status", []) if whois_json_data.get("domain_status") else ["N/A"]),
        "domain_owner": whois_json_data.get("domain_owner"), "whois_server": whois_json_data.get("whois_server"),
        "raw_whois_text": whois_json_data.get("raw_whois"), "formatted_whois_text": whois_json_data.get("formatted_whois"),
        "whois_privacy_enabled": is_privacy_enabled 
    }
    try:
        for key, value in data.items():
            if value is None: data[key] = "N/A"
            elif isinstance(value, (dict, list)): data[key] = json.dumps(value)
        db_cols = list(data.keys()) 
        val_placeholders = ", ".join(["?"] * len(db_cols))
        sql = f"INSERT INTO whois_records ({', '.join(db_cols)}) VALUES ({val_placeholders})"
        cursor.execute(sql, [data[col] for col in db_cols])
        conn.commit(); print(f"  Stored Whois for {domain_name} (Batch: {batch_run_id_for_logging})"); return True
    except sqlite3.Error as e: print(f"  DB error Whois {domain_name} (Batch: {batch_run_id_for_logging}): {e}. Data: {str(data)[:200]}")
    except Exception as ex: print(f"  Generic error Whois {domain_name} (Batch: {batch_run_id_for_logging}): {ex}. JSON: {str(whois_json_data)[:200]}")
    return False

def fetch_whois_from_api(domain_name, api_key):
    params = {"key": api_key, "whois": domain_name}
    
    for attempt in range(API_RETRIES): 
        print(f"  Querying Whoxy API for {domain_name} (Attempt {attempt + 1}/{API_RETRIES})...")
        try:
            response = requests.get(WHOIS_API_BASE_URL, params=params, timeout=60) 
            response.raise_for_status() 
            api_data = response.json()
            if api_data.get("status") == 1:
                return api_data 
            elif api_data.get("status") == 0:
                print(f"  Whoxy API Error for {domain_name}: {api_data.get('status_reason', 'Unknown API error')}")
            else: 
                print(f"  Unexpected API response format for {domain_name}: {str(api_data)[:200]}")
        except requests.exceptions.Timeout: print(f"  API Request Timeout for {domain_name}.")
        except requests.exceptions.HTTPError as http_err: print(f"  API HTTP Error for {domain_name}: {http_err}.")
        except requests.exceptions.RequestException as req_err: print(f"  API Request Exception for {domain_name}: {req_err}")
        except json.JSONDecodeError: print(f"  API response for {domain_name} was not valid JSON.")
        
        if attempt < API_RETRIES - 1:
            print(f"  Retrying in {API_RETRY_DELAY} seconds...")
            time.sleep(API_RETRY_DELAY) 
        else:
            print(f"  Max retries reached for {domain_name}. Giving up on this domain for this run.")
    return None 


def update_status_file(batch_run_id, status_data):
    if not batch_run_id: print("Error: Cannot update status file without batch_run_id."); return
    if not os.path.exists(STATUS_FILE_DIR): 
        try: os.makedirs(STATUS_FILE_DIR); print(f"Created status dir: {STATUS_FILE_DIR}")
        except OSError as e: print(f"Error creating status dir {STATUS_FILE_DIR}: {e}"); return
    status_file_path = os.path.join(STATUS_FILE_DIR, f"status_{batch_run_id}.json") 
    status_data["timestamp"] = datetime.now().isoformat()
    status_data["batch_run_id"] = batch_run_id 
    try:
        with open(status_file_path, 'w') as sf: json.dump(status_data, sf, indent=2)
    except IOError as e: print(f"Error writing status file {status_file_path}: {e}")
    except TypeError as e: print(f"Error serializing status data {status_file_path}: {e}. Data: {status_data}")

def main():
    parser = argparse.ArgumentParser(description="Fetch and store Whois data.")
    domain_source_group = parser.add_mutually_exclusive_group(required=True)
    domain_source_group.add_argument("--category", choices=["SUCCESSFUL", "UNSUCCESSFUL", "OTHER"], help="Category of domains to process.")
    domain_source_group.add_argument("--domain-ids", type=str, help="Comma-separated string of domain IDs to process.")
    domain_source_group.add_argument("--domain", type=str, help="A single domain name to process directly.")
    domain_source_group.add_argument("--no-whois-yet", action="store_true", help="Process domains that have no WHOIS records yet.") 
    domain_source_group.add_argument("--all-domains-in-db", action="store_true", help="Process ALL unique domains currently in the database.") 
    parser.add_argument("--api-key", required=True, help="Whoxy API key.")
    parser.add_argument("--batch-run-id", required=True, help="Unique ID for this batch run.")
    
    args = parser.parse_args()

    batch_run_id = args.batch_run_id
    status_file_path = os.path.join(STATUS_FILE_DIR, f"status_{batch_run_id}.json")
    
    print(f"--- Whois Lookup Script Started (Batch ID: {batch_run_id}) ---")
    print(f"--- Status File: {status_file_path} ---")
    print(f"--- API Retries: {API_RETRIES}, Retry Delay: {API_RETRY_DELAY}s ---")

    current_run_status = { "batch_run_id": batch_run_id, "status": "error", "message": "Init failed.", "total_domains": 0, "processed_domains": 0, "current_domain": "", "errors": ["Init error."]}
    db_conn_main = None; total_domains = 0; processed_count = 0

    try:
        current_run_status.update({"status": "starting", "message": "Initializing...", "errors": []})
        update_status_file(batch_run_id, current_run_status)
        db_conn_main = get_db_connection()
        if not db_conn_main:
            current_run_status.update({"status": "error", "message": f"DB connection failed to {DB_NAME}."}); return
        
        domains_to_process = []
        if args.domain: domains_to_process = [args.domain.strip()]
        elif args.category: domains_to_process = get_domains_by_latest_category(args.category)
        elif args.domain_ids: domains_to_process = get_domains_by_ids(args.domain_ids)
        elif args.no_whois_yet: domains_to_process = get_domains_without_whois()
        elif args.all_domains_in_db: domains_to_process = get_all_domains_from_db_list() 


        if not domains_to_process:
            current_run_status.update({"status": "complete", "message": "No domains to process."}); return
        
        total_domains = len(domains_to_process)
        current_run_status.update({"status": "starting", "message": f"Found {total_domains} domains.", "total_domains": total_domains, "processed_domains": 0})
        update_status_file(batch_run_id, current_run_status)

        success_c = 0; api_call_failures = 0; db_store_failures = 0; api_errors_encountered = []
        
        for i, domain_name in enumerate(domains_to_process):
            processed_count = i 
            print(f"\nProcessing domain {i+1}/{total_domains}: {domain_name}")
            current_run_status.update({
                "status": "running", 
                "message": f"Fetching WHOIS for {domain_name} ({i+1}/{total_domains}).", 
                "processed_domains": i, 
                "current_domain": domain_name, 
                "errors": api_errors_encountered 
            })
            update_status_file(batch_run_id, current_run_status)

            whois_json = fetch_whois_from_api(domain_name, args.api_key) 
            
            if whois_json and whois_json.get("status") == 1: 
                if parse_and_store_whois_data(db_conn_main, domain_name, whois_json, batch_run_id):
                    success_c += 1
                else:
                    db_store_failures += 1
                    api_errors_encountered.append(f"DB store error for {domain_name}") 
            else: 
                api_call_failures += 1
                api_errors_encountered.append(f"Failed to fetch valid WHOIS for {domain_name} after retries.")
            
            if total_domains > 1 and i < total_domains - 1: 
                time.sleep(API_RETRY_DELAY / 2 if API_RETRY_DELAY > 1 else 0.5) 
        
        processed_count = total_domains 
        msg = f"Batch Whois finished. Successful lookups stored: {success_c}. API call failures: {api_call_failures}. DB store failures: {db_store_failures}."
        current_run_status.update({"status": "complete", "message": msg, "processed_domains": total_domains, "successful_lookups": success_c, "api_call_failures": api_call_failures, "db_store_failures": db_store_failures, "errors": api_errors_encountered})
    except Exception as e:
        err_msg = f"Critical error: {str(e)}"; print(err_msg)
        current_run_status.update({"status": "error", "message": err_msg, "processed_domains": processed_count, "errors": current_run_status.get("errors", []) + [f"Critical: {str(e)}"]})
    finally:
        if db_conn_main: db_conn_main.close(); print("DB connection closed.")
        current_run_status["batch_run_id"] = batch_run_id
        update_status_file(batch_run_id, current_run_status)
        print(f"\n--- Whois Lookup Script Finalizing (Batch ID: {batch_run_id}) ---")
        print(f"--- Final Status: {current_run_status.get('status')}, Message: {current_run_status.get('message', 'N/A')} ---")
        if current_run_status.get("errors"): print(f"Final errors list: {current_run_status.get('errors')}")
        
        print(f"Waiting a moment before removing status file: {status_file_path}")
        time.sleep(2) 
        try:
            if os.path.exists(status_file_path): os.remove(status_file_path); print(f"Status file {status_file_path} removed.")
        except OSError as e: print(f"Error removing status file {status_file_path}: {e}")

if __name__ == "__main__":
    main()