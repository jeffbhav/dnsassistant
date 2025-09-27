# parse_whois.py
import sqlite3
import json
import argparse
import time
import os
import sys
import re
from datetime import datetime
from dateutil.parser import parse as date_parse

DB_NAME = "dns_lookup_results.db"
STATUS_FILE_DIR_NAME = "status_updates"
STATUS_FILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), STATUS_FILE_DIR_NAME)

DATE_PATTERNS = {
    'creation': [
        re.compile(r"Creation Date:\s*(.*)", re.IGNORECASE),
        re.compile(r"Created Date:\s*(.*)", re.IGNORECASE),
        re.compile(r"Registered on:\s*(.*)", re.IGNORECASE),
        re.compile(r"Registration Time:\s*(.*)", re.IGNORECASE),
        re.compile(r"Domain Create Date:\s*(.*)", re.IGNORECASE),
    ],
    'expiry': [
        re.compile(r"Registry Expiry Date:\s*(.*)", re.IGNORECASE),
        re.compile(r"Registrar Registration Expiration Date:\s*(.*)", re.IGNORECASE),
        re.compile(r"Expiration Date:\s*(.*)", re.IGNORECASE),
        re.compile(r"Expires on:\s*(.*)", re.IGNORECASE),
        re.compile(r"Domain Expiration Date:\s*(.*)", re.IGNORECASE),
    ],
    'updated': [
        re.compile(r"Updated Date:\s*(.*)", re.IGNORECASE),
        re.compile(r"Last-updated:\s*(.*)", re.IGNORECASE),
        re.compile(r"Last-Update:\s*(.*)", re.IGNORECASE),
        re.compile(r"Last Update Date:\s*(.*)", re.IGNORECASE),
        re.compile(r"Domain Last Updated Date:\s*(.*)", re.IGNORECASE),
    ]
}

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
    if not os.path.exists(STATUS_FILE_DIR):
        try: os.makedirs(STATUS_FILE_DIR)
        except OSError as e: print(f"Error creating status dir: {e}"); return
    status_file_path = os.path.join(STATUS_FILE_DIR, f"status_{batch_run_id}.json")
    status_data["timestamp"] = datetime.now().isoformat()
    status_data["batch_run_id"] = batch_run_id
    try:
        with open(status_file_path, 'w') as sf:
            json.dump(status_data, sf, indent=2)
    except IOError as e:
        print(f"Error writing status file {status_file_path}: {e}")

def get_domains_by_latest_category(category):
    conn = get_db_connection()
    if not conn: return []
    domains = []
    try:
        cursor = conn.cursor()
        query = """
            SELECT lr1.domain_name FROM lookup_results lr1 
            WHERE lr1.category = ? 
            AND lr1.timestamp = (
                SELECT MAX(lr2.timestamp) 
                FROM lookup_results lr2 
                WHERE lr2.domain_name = lr1.domain_name
            ) 
            GROUP BY lr1.domain_name
        """
        cursor.execute(query, (category,))
        domains = [row['domain_name'] for row in cursor.fetchall()]
        print(f"Found {len(domains)} domains in category '{category}' to parse.")
    except sqlite3.Error as e:
        print(f"DB Error getting domains by category: {e}")
    finally:
        if conn: conn.close()
    return domains

def get_domain_names_from_ids(domain_ids_str):
    conn = get_db_connection()
    if not conn: return []
    domains = []
    try:
        safe_ids = [int(s_id) for s_id in domain_ids_str.split(',') if s_id.strip().isdigit()]
        if not safe_ids: return []
        placeholders = ','.join('?' for _ in safe_ids)
        cursor = conn.cursor()
        # This needs to select from lookup_results, not whois_records, as the ID is from the main table
        cursor.execute(f"SELECT DISTINCT domain_name FROM lookup_results WHERE id IN ({placeholders})", safe_ids)
        domains = [row['domain_name'] for row in cursor.fetchall()]
        print(f"Found {len(domains)} domain names from {len(safe_ids)} provided IDs to parse.")
    except sqlite3.Error as e:
        print(f"DB Error getting domains from IDs: {e}")
    finally:
        if conn: conn.close()
    return domains
    
def get_whois_records_to_parse(target_domains=None, no_parsed_data_yet=False):
    """Fetches whois records based on criteria."""
    conn = get_db_connection()
    if not conn: return []
    records = []
    
    base_query = "SELECT id, domain_name, raw_whois_text FROM whois_records"
    conditions = []
    params = []

    if target_domains:
        placeholders = ','.join('?' * len(target_domains))
        conditions.append(f"domain_name IN ({placeholders})")
        params.extend(target_domains)

    if no_parsed_data_yet:
        conditions.append("(creation_date_from_parse IS NULL OR expiry_date_from_parse IS NULL OR updated_date_from_parse IS NULL)")

    if conditions:
        query = f"{base_query} WHERE {' AND '.join(conditions)}"
    else:
        query = base_query
        
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        records = cursor.fetchall()
        print(f"Found {len(records)} WHOIS records to parse for the selected criteria.")
    except sqlite3.Error as e:
        print(f"DB Error fetching WHOIS records to parse: {e}")
    finally:
        conn.close()
    return records

def parse_date_from_text(text, patterns):
    """Tries multiple regex patterns to find and parse a date."""
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            date_str = match.group(1).strip()
            # Remove timezone info in parentheses, e.g., (JST)
            date_str = re.sub(r'\s*\([A-Z]{3,4}\)\s*$', '', date_str)
            try:
                # dateutil.parser is very flexible
                return date_parse(date_str).strftime('%Y-%m-%d')
            except (ValueError, TypeError):
                # Try to clean up and parse again, e.g. "before 21-dec-2012"
                cleaned_str = date_str.split("before ")[-1]
                try:
                    return date_parse(cleaned_str).strftime('%Y-%m-%d')
                except:
                    continue # Try next pattern
    return None

def main():
    parser = argparse.ArgumentParser(description="Parse raw WHOIS text to extract structured dates.")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--category", help="Category of domains to process.")
    source_group.add_argument("--domain-ids", help="Comma-separated string of domain IDs to process.")
    source_group.add_argument("--all-domains-in-db", action="store_true", help="Process all domains in the database.")
    source_group.add_argument("--no-parsed-data-yet", action="store_true", help="Only process records missing parsed date info.")
    parser.add_argument("--batch-run-id", required=True, help="Unique ID for this batch run.")
    args = parser.parse_args()

    # --- Step 1: Get the target domain names if needed ---
    target_domains = None
    if args.category:
        # Use the local version of the function
        target_domains = get_domains_by_latest_category(args.category)
    elif args.domain_ids:
        # Use the local version of the function
        target_domains = get_domain_names_from_ids(args.domain_ids)

    # --- Step 2: Get the list of WHOIS records to process ---
    records_to_process = get_whois_records_to_parse(
        target_domains=target_domains, 
        no_parsed_data_yet=args.no_parsed_data_yet or args.all_domains_in_db # if all, we still want to re-parse
    )
    
    total_records = len(records_to_process)
    if total_records == 0:
        print("No records found to parse for the given criteria.")
        update_status_file(args.batch_run_id, {"status": "complete", "message": "No records to parse."})
        # Clean up status file
        status_file_path = os.path.join(STATUS_FILE_DIR, f"status_{args.batch_run_id}.json")
        try: time.sleep(1); os.remove(status_file_path)
        except OSError as e: print(f"Error removing status file {status_file_path}: {e}")
        return

    update_status_file(args.batch_run_id, {
        "status": "starting", "message": f"Starting to parse {total_records} WHOIS records.",
        "total_domains": total_records, "processed_domains": 0
    })
    
    conn = get_db_connection()
    if not conn:
        update_status_file(args.batch_run_id, {"status": "error", "message": "Could not connect to database."})
        return
        
    cursor = conn.cursor()
    success_count = 0
    update_count = 0

    for i, record in enumerate(records_to_process):
        raw_text = record['raw_whois_text']
        domain_name = record['domain_name']
        record_id = record['id']

        update_status_file(args.batch_run_id, {
            "status": "processing", "message": f"Parsing {domain_name}",
            "total_domains": total_records, "processed_domains": i, "current_domain": domain_name
        })

        if not raw_text:
            print(f"  Skipping {domain_name} (ID: {record_id}) - no raw WHOIS text.")
            continue
            
        created = parse_date_from_text(raw_text, DATE_PATTERNS['creation'])
        expires = parse_date_from_text(raw_text, DATE_PATTERNS['expiry'])
        updated = parse_date_from_text(raw_text, DATE_PATTERNS['updated'])
        
        if created or expires or updated:
            print(f"  Parsed dates for {domain_name}: C={created}, E={expires}, U={updated}")
            try:
                cursor.execute("""
                    UPDATE whois_records 
                    SET creation_date_from_parse = ?, 
                        expiry_date_from_parse = ?, 
                        updated_date_from_parse = ?
                    WHERE id = ?
                """, (created, expires, updated, record_id))
                update_count += 1
            except sqlite3.Error as e:
                print(f"  DB Error updating record {record_id} for {domain_name}: {e}")
        else:
             print(f"  Could not parse any dates for {domain_name} (ID: {record_id}).")

        # Commit periodically to save progress
        if i > 0 and i % 50 == 0:
            conn.commit()
            success_count = update_count

    conn.commit() # Final commit
    success_count = update_count
    conn.close()

    final_message = f"Parsing complete. Updated {success_count} of {total_records} records with new date information."
    print(final_message)
    update_status_file(args.batch_run_id, {"status": "complete", "message": final_message, "processed_domains": total_records, "total_domains": total_records})
    
    # Clean up status file
    status_file_path = os.path.join(STATUS_FILE_DIR, f"status_{args.batch_run_id}.json")
    try: time.sleep(1); os.remove(status_file_path)
    except OSError as e: print(f"Error removing status file {status_file_path}: {e}")


if __name__ == "__main__":
    main()
