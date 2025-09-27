# dns_checker.py
import dns.resolver
import dns.exception
import dns.flags
import dns.reversename
import dns.message
import dns.query
import sqlite3
import datetime
import argparse
import os
import sys
import json
import time
import configparser

# --- Configuration Loading ---
config_parser_obj = configparser.ConfigParser()
CONFIG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")

# Default values in case config.ini is missing or incomplete
DB_NAME_CFG = "dns_lookup_results.db"
STATUS_FILE_DIR_NAME_CFG = "status_updates"
SUCCESSFUL_NS_PATTERNS_CFG = []
UNSUCCESSFUL_NS_PATTERNS_CFG = []
DEFAULT_RECORD_TYPES_CFG = ["NS", "A", "AAAA", "MX", "TXT", "CNAME", "SOA", "SRV", "CAA", "PTR", "DNSSEC"]
DEFAULT_RETRIES_CFG = 3
DEFAULT_TIMEOUT_CFG = 5
DEFAULT_LIFETIME_CFG = 10
DOMAINS_INPUT_FILE_CFG = "domains.txt"
CHECK_SRV_RECORDS_CFG = True
CHECK_CAA_RECORDS_CFG = True
CHECK_EMAIL_AUTH_RECORDS_CFG = True
SRV_PREFIXES_TO_CHECK_CFG = ["_sip._tcp", "_ldap._tcp", "_autodiscover._tcp", "_submission._tcp", "_imaps._tcp", "_pop3s._tcp"]


if not os.path.exists(CONFIG_FILE_PATH):
    print(f"CRITICAL: Configuration file '{CONFIG_FILE_PATH}' not found. Using hardcoded defaults (not recommended).")
else:
    config_parser_obj.read(CONFIG_FILE_PATH)
    try:
        DB_NAME_CFG = config_parser_obj.get('General', 'db_name', fallback=DB_NAME_CFG)
        STATUS_FILE_DIR_NAME_CFG = config_parser_obj.get('General', 'status_file_dir_name', fallback=STATUS_FILE_DIR_NAME_CFG)
        DOMAINS_INPUT_FILE_CFG = config_parser_obj.get('General', 'domains_input_file', fallback=DOMAINS_INPUT_FILE_CFG)

        successful_patterns_str = config_parser_obj.get('DNSChecker', 'successful_nameserver_patterns', fallback='')
        SUCCESSFUL_NS_PATTERNS_CFG = [p.strip() for p in successful_patterns_str.split(',') if p.strip()]
        
        unsuccessful_patterns_str = config_parser_obj.get('DNSChecker', 'unsuccessful_nameserver_patterns', fallback='')
        UNSUCCESSFUL_NS_PATTERNS_CFG = [p.strip() for p in unsuccessful_patterns_str.split(',') if p.strip()]
        
        default_records_str = config_parser_obj.get('DNSChecker', 'default_record_types_to_check', fallback='NS,A,AAAA,MX,TXT,CNAME,SOA,SRV,CAA,PTR,DNSSEC')
        DEFAULT_RECORD_TYPES_CFG = [rt.strip().upper() for rt in default_records_str.split(',') if rt.strip()]
        
        DEFAULT_RETRIES_CFG = config_parser_obj.getint('DNSChecker', 'default_retries', fallback=DEFAULT_RETRIES_CFG)
        DEFAULT_TIMEOUT_CFG = config_parser_obj.getint('DNSChecker', 'default_timeout_seconds', fallback=DEFAULT_TIMEOUT_CFG)
        DEFAULT_LIFETIME_CFG = config_parser_obj.getint('DNSChecker', 'default_lifetime_seconds', fallback=DEFAULT_LIFETIME_CFG)

        CHECK_SRV_RECORDS_CFG = config_parser_obj.getboolean('DNSChecker', 'check_srv_records', fallback=CHECK_SRV_RECORDS_CFG)
        CHECK_CAA_RECORDS_CFG = config_parser_obj.getboolean('DNSChecker', 'check_caa_records', fallback=CHECK_CAA_RECORDS_CFG)
        CHECK_EMAIL_AUTH_RECORDS_CFG = config_parser_obj.getboolean('DNSChecker', 'check_email_auth_records', fallback=CHECK_EMAIL_AUTH_RECORDS_CFG)
        
        srv_prefixes_str = config_parser_obj.get('DNSChecker', 'srv_prefixes_to_check', fallback='')
        SRV_PREFIXES_TO_CHECK_CFG = [p.strip() for p in srv_prefixes_str.split(',') if p.strip()]


    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        print(f"ERROR reading from config.ini: {e}. Using some hardcoded defaults.")
        # Fallbacks already defined above will be used.

DB_NAME = DB_NAME_CFG 
STATUS_FILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), STATUS_FILE_DIR_NAME_CFG)

def init_db():
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS runs (run_id INTEGER PRIMARY KEY AUTOINCREMENT, run_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, run_type TEXT NOT NULL, domains_processed INTEGER, domains_changed_count INTEGER)''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON runs (run_timestamp)")
        cursor.execute('''CREATE TABLE IF NOT EXISTS status_changes (change_id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL, domain_name TEXT NOT NULL, previous_category TEXT, new_category TEXT, change_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (run_id) REFERENCES runs (run_id) ON DELETE CASCADE)''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sc_run_id ON status_changes (run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sc_domain_name ON status_changes (domain_name)")
        
        cursor.execute("PRAGMA table_info(lookup_results)")
        existing_lookup_cols = [col[1] for col in cursor.fetchall()]
        required_lookup_cols = {
            'id': 'INTEGER PRIMARY KEY AUTOINCREMENT','timestamp': 'DATETIME DEFAULT CURRENT_TIMESTAMP','run_id': 'INTEGER',
            'domain_name': 'TEXT NOT NULL','nameservers_found': 'TEXT','raw_status': 'TEXT','details': 'TEXT','category': 'TEXT',
            'a_records': 'TEXT','aaaa_records': 'TEXT','mx_records': 'TEXT','txt_records': 'TEXT','cname_record': 'TEXT',
            'soa_record_details': 'TEXT','soa_serial_changed': 'INTEGER','ns_consistent_with_self': 'TEXT',
            'srv_records': 'TEXT', 'caa_records': 'TEXT', 
            'dmarc_record_present': 'INTEGER', 'spf_record_present': 'INTEGER',
            'ptr_records': 'TEXT', 'dnssec_status': 'TEXT'
        }
        if not existing_lookup_cols:
            cols_def = ", ".join([f"{name} {type_def}" for name, type_def in required_lookup_cols.items() if name != 'id'])
            cursor.execute(f'''CREATE TABLE lookup_results (id INTEGER PRIMARY KEY AUTOINCREMENT, {cols_def}, FOREIGN KEY (run_id) REFERENCES runs (run_id) ON DELETE CASCADE)''')
            print("Created new 'lookup_results' table with all columns.")
        else:
            for col_name, col_type in required_lookup_cols.items():
                if col_name != 'id' and col_name not in existing_lookup_cols:
                    try: cursor.execute(f"ALTER TABLE lookup_results ADD COLUMN {col_name} {col_type.replace('PRIMARY KEY AUTOINCREMENT', '')}"); print(f"Added '{col_name}' column to lookup_results.")
                    except sqlite3.Error as e: print(f"Warning: Could not add column '{col_name}' to 'lookup_results': {e}")
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_lr_domain_name ON lookup_results (domain_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_lr_category ON lookup_results (category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_lr_timestamp ON lookup_results (timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_lr_domain_timestamp ON lookup_results (domain_name, timestamp DESC)")

        cursor.execute("PRAGMA table_info(whois_records)")
        existing_whois_cols = [col[1] for col in cursor.fetchall()]
        required_whois_cols_def = '''
            id INTEGER PRIMARY KEY AUTOINCREMENT, domain_name TEXT NOT NULL, lookup_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            api_status INTEGER, api_status_reason TEXT, domain_registered TEXT, registered_on_timestamp INTEGER,
            created_date_iso TEXT, updated_date_iso TEXT, expiry_date_iso TEXT, registrar_name TEXT, registrar_iana_id TEXT,
            registrar_url TEXT, registrar_email TEXT, registrar_phone TEXT, registrant_contact_name TEXT, registrant_contact_company TEXT,
            registrant_contact_address TEXT, registrant_contact_city TEXT, registrant_contact_state TEXT, registrant_contact_zipcode TEXT,
            registrant_contact_country_code TEXT, registrant_contact_country_name TEXT, registrant_contact_phone TEXT,
            registrant_contact_fax TEXT, registrant_contact_email TEXT, administrative_contact_name TEXT, administrative_contact_company TEXT,
            administrative_contact_address TEXT, administrative_contact_city TEXT, administrative_contact_state TEXT,
            administrative_contact_zipcode TEXT, administrative_contact_country_code TEXT, administrative_contact_country_name TEXT,
            administrative_contact_phone TEXT, administrative_contact_fax TEXT, administrative_contact_email TEXT,
            technical_contact_name TEXT, technical_contact_company TEXT, technical_contact_address TEXT, technical_contact_city TEXT,
            technical_contact_state TEXT, technical_contact_zipcode TEXT, technical_contact_country_code TEXT,
            technical_contact_country_name TEXT, technical_contact_phone TEXT, technical_contact_fax TEXT, technical_contact_email TEXT,
            name_servers TEXT, domain_status TEXT, domain_owner TEXT, whois_server TEXT, raw_whois_text TEXT, formatted_whois_text TEXT,
            whois_privacy_enabled INTEGER DEFAULT 0,
            creation_date_from_parse TEXT, expiry_date_from_parse TEXT, updated_date_from_parse TEXT,
            FOREIGN KEY (domain_name) REFERENCES lookup_results (domain_name) ON DELETE CASCADE ON UPDATE CASCADE
        '''
        if not existing_whois_cols:
            cursor.execute(f"CREATE TABLE whois_records ({required_whois_cols_def})")
            print("Created new 'whois_records' table.")
        else:
            new_cols_to_add = {
                'whois_privacy_enabled': 'INTEGER DEFAULT 0', 'creation_date_from_parse': 'TEXT',
                'expiry_date_from_parse': 'TEXT', 'updated_date_from_parse': 'TEXT'
            }
            for col_name, col_type in new_cols_to_add.items():
                if col_name not in existing_whois_cols:
                    try:
                        cursor.execute(f"ALTER TABLE whois_records ADD COLUMN {col_name} {col_type}")
                        print(f"Added '{col_name}' column to 'whois_records'.")
                    except sqlite3.Error as e:
                        print(f"Warning: Could not add column '{col_name}' to 'whois_records': {e}")
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_wr_domain_name ON whois_records (domain_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_wr_lookup_timestamp ON whois_records (lookup_timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_wr_privacy_enabled ON whois_records (whois_privacy_enabled)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_wr_creation_date ON whois_records (creation_date_from_parse)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_wr_expiry_date ON whois_records (expiry_date_from_parse)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_wr_updated_date ON whois_records (updated_date_from_parse)")
        
        conn.commit()
    except sqlite3.Error as e: print(f"Database error during initialization: {e}")
    finally:
        if conn: conn.close()

def log_to_db(domain_name, nameservers_str, raw_status_val, details_val, category_val, run_id, **kwargs):
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        columns = ['timestamp', 'run_id', 'domain_name', 'nameservers_found', 'raw_status', 'details', 'category']
        values = [datetime.datetime.now(), run_id, domain_name, nameservers_str, raw_status_val, details_val, category_val]
        
        for key, value in kwargs.items():
            if key in ['a_records', 'aaaa_records', 'mx_records', 'txt_records', 'cname_record', 'soa_record_details', 'srv_records', 'caa_records', 'ptr_records']:
                columns.append(key)
                values.append(json.dumps(value) if value is not None else None)
            elif key in ['dnssec_status', 'soa_serial_changed', 'ns_consistent_with_self', 'dmarc_record_present', 'spf_record_present']:
                columns.append(key)
                values.append(value)

        placeholders = ', '.join(['?'] * len(columns))
        sql = f"INSERT INTO lookup_results ({', '.join(columns)}) VALUES ({placeholders})"
        
        cursor.execute(sql, values)
        conn.commit()
    except sqlite3.Error as e: print(f"DB log error for {domain_name} (run {run_id}): {e}")
    finally:
        if conn: conn.close()

def load_domains_from_file(file_path):
    domains = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith("#"): domains.append(domain)
    except FileNotFoundError: print(f"Error: File '{file_path}' not found."); return None
    return domains

def get_successful_domains_from_db():
    conn = None; domains = []
    try:
        conn = sqlite3.connect(DB_NAME); conn.row_factory = sqlite3.Row; cursor = conn.cursor()
        cursor.execute('''SELECT lr1.domain_name FROM lookup_results lr1 WHERE lr1.category = 'SUCCESSFUL' AND lr1.timestamp = (SELECT MAX(lr2.timestamp) FROM lookup_results lr2 WHERE lr2.domain_name = lr1.domain_name) GROUP BY lr1.domain_name''')
        domains = [row['domain_name'] for row in cursor.fetchall()]
    except sqlite3.Error as e: print(f"Error fetching successful domains: {e}")
    finally:
        if conn: conn.close()
    return domains

def get_all_domains_from_db_set():
    conn = None; domains_set = set()
    try:
        conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT lower(domain_name) FROM lookup_results")
        domains_set = {row[0] for row in cursor.fetchall() if row[0]}
    except sqlite3.Error as e: print(f"Error fetching all domains from DB: {e}")
    finally:
        if conn: conn.close()
    return domains_set

def get_domains_by_latest_category(category_name):
    conn = None; domains = []
    try:
        conn = sqlite3.connect(DB_NAME); conn.row_factory = sqlite3.Row; cursor = conn.cursor()
        cursor.execute('''SELECT lr1.domain_name FROM lookup_results lr1 WHERE lr1.category = ? AND lr1.timestamp = (SELECT MAX(lr2.timestamp) FROM lookup_results lr2 WHERE lr2.domain_name = lr1.domain_name) GROUP BY lr1.domain_name''', (category_name,))
        domains = [row['domain_name'] for row in cursor.fetchall()]
    except sqlite3.Error as e: print(f"Error fetching domains by category: {e}")
    finally:
        if conn: conn.close()
    return domains

def get_domains_by_ids_from_db(id_csv_string):
    domains = []
    if not id_csv_string: return domains
    safe_ids = [int(s_id) for s_id in id_csv_string.split(',') if s_id.strip().isdigit()]
    if not safe_ids: return domains
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME); conn.row_factory = sqlite3.Row; cursor = conn.cursor()
        placeholders = ','.join('?' for _ in safe_ids)
        cursor.execute(f"SELECT DISTINCT domain_name FROM lookup_results WHERE id IN ({placeholders})", safe_ids)
        domains = [row['domain_name'] for row in cursor.fetchall()]
    except sqlite3.Error as e: print(f"Error fetching domains by IDs: {e}")
    finally:
        if conn: conn.close()
    return domains

def check_domain_nameservers(domain_list,
                             record_types_to_check=None, custom_dns_server=None,
                             batch_run_id=None, run_type_override=None):
    status_file_path = None
    if batch_run_id:
        os.makedirs(STATUS_FILE_DIR, exist_ok=True)
        status_file_path = os.path.join(STATUS_FILE_DIR, f"status_{batch_run_id}.json")

    def update_status_file(message, status="processing", processed=0, total=0, current_domain_name="N/A"):
        if status_file_path:
            try:
                with open(status_file_path, 'w') as f:
                    json.dump({"message": message, "status": status, "processed_domains": processed, "total_domains": total, "current_domain": current_domain_name, "timestamp": datetime.datetime.now().isoformat(), "batch_run_id": batch_run_id }, f)
            except IOError as e: print(f"Error writing status file {status_file_path}: {e}")

    successful_patterns_lower = [p.strip().lower() for p in SUCCESSFUL_NS_PATTERNS_CFG]
    unsuccessful_patterns_lower = [p.strip().lower() for p in UNSUCCESSFUL_NS_PATTERNS_CFG]
    
    conn_run = sqlite3.connect(DB_NAME)
    cursor_run = conn_run.cursor()
    cursor_run.execute("INSERT INTO runs (run_type) VALUES (?)", (run_type_override or "script_run",))
    current_run_id = cursor_run.lastrowid
    conn_run.commit()
    conn_run.close()
    
    total_domains = len(domain_list)
    update_status_file("Starting...", "starting", 0, total_domains)

    for domain_idx, domain in enumerate(domain_list):
        update_status_file(f"Processing {domain}", "running", domain_idx + 1, total_domains, domain)
        print(f"Processing {domain_idx+1}/{total_domains}: {domain}")
        
        results = {
            'a_records': [], 'aaaa_records': [], 'mx_records': [], 'txt_records': [],
            'cname_record': None, 'soa_record_details': None, 'srv_records': [],
            'caa_records': [], 'ptr_records': {}, 'dnssec_status': "Unchecked",
            'nameservers_found': [], 'raw_status': 'NEUTRAL', 'details': '',
            'category': 'OTHER', 'soa_serial_changed': None,
            'ns_consistent_with_self': 'N/A', 'dmarc_record_present': 0, 'spf_record_present': 0
        }

        resolver = dns.resolver.Resolver()
        if custom_dns_server:
            resolver.nameservers = [custom_dns_server]
        
        requested_actions = set(record_types_to_check if record_types_to_check else DEFAULT_RECORD_TYPES_CFG)
        
        if 'DNSSEC' in requested_actions:
            try:
                # Use a known public resolver for validation unless a custom one is specified
                validating_resolver_ip = custom_dns_server or '8.8.8.8'
                qname = dns.name.from_text(domain)
                # Query for DNSKEY to check for signing, ask for DNSSEC data
                request = dns.message.make_query(qname, dns.rdatatype.DNSKEY, want_dnssec=True)
                response = dns.query.udp(request, validating_resolver_ip, timeout=4)
                
                if response.rcode() == dns.rcode.NOERROR and len(response.answer) > 0:
                    # We have a response with DNSKEYs, now check the AD bit.
                    # The AD bit means the validating resolver successfully verified the chain.
                    if response.flags & dns.flags.AD:
                        results['dnssec_status'] = "Secure"
                    else:
                        results['dnssec_status'] = "Insecure"
                else: # No answer or an error RCODE means it's not secure
                    results['dnssec_status'] = "Insecure"
            except Exception as e:
                results['dnssec_status'] = f"Error: {type(e).__name__}"

        record_types_to_query = requested_actions - {'DNSSEC', 'PTR'}
        for rtype in record_types_to_query:
            try:
                answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
                if rtype == 'A': results['a_records'] = [r.address for r in answers]
                elif rtype == 'AAAA': results['aaaa_records'] = [r.address for r in answers]
                elif rtype == 'NS': results['nameservers_found'] = [r.target.to_text(omit_final_dot=True).lower() for r in answers]
                elif rtype == 'MX': results['mx_records'] = [{'preference': r.preference, 'exchange': r.exchange.to_text(omit_final_dot=True)} for r in answers]
                elif rtype == 'TXT': 
                    results['txt_records'] = [b''.join(r.strings).decode('utf-8', 'ignore') for r in answers]
                    if CHECK_EMAIL_AUTH_RECORDS_CFG:
                        for txt in results['txt_records']:
                            if txt.lower().startswith('v=spf1'): results['spf_record_present'] = 1
                elif rtype == 'CNAME': results['cname_record'] = answers[0].target.to_text(omit_final_dot=True) if answers else None
                elif rtype == 'SOA':
                    if answers: results['soa_record_details'] = {'serial': answers[0].serial}
                elif rtype == 'CAA' and CHECK_CAA_RECORDS_CFG: results['caa_records'] = [{"flags": r.flags, "tag": r.tag.decode(), "value": r.value.decode()} for r in answers]
                elif rtype == 'SRV' and CHECK_SRV_RECORDS_CFG: results['srv_records'] = [{"target": r.target.to_text(omit_final_dot=True)} for r in answers]
            except Exception as e:
                print(f"  Error querying {rtype} for {domain}: {e}")

        if 'PTR' in requested_actions:
            all_ips = results.get('a_records', []) + results.get('aaaa_records', [])
            for ip in all_ips:
                try:
                    rev_name = dns.reversename.from_address(ip)
                    ptr_answers = resolver.resolve(rev_name, 'PTR')
                    results['ptr_records'][ip] = [r.target.to_text(omit_final_dot=True) for r in ptr_answers]
                except Exception:
                    results['ptr_records'][ip] = "Lookup Error"
        
        if CHECK_EMAIL_AUTH_RECORDS_CFG:
             try:
                dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
                for r in dmarc_answers:
                    if b"v=DMARC1" in r.strings[0]:
                        results['dmarc_record_present'] = 1
                        break
             except Exception:
                pass

        # --- Name Server Consistency Check ---
        if results['nameservers_found']:
            is_consistent = False
            for ns_host in results['nameservers_found']:
                try:
                    # Create a resolver that will ONLY use the authoritative server's IP
                    auth_resolver = dns.resolver.Resolver(configure=False)
                    
                    # First, find the IP of the authoritative name server we want to query
                    ns_ip_answers = dns.resolver.resolve(ns_host, 'A')
                    if not ns_ip_answers:
                        # If we can't get an IP for the NS, we can't test it, so try the next one
                        continue
                    
                    auth_resolver.nameservers = [ns_ip_answers[0].address]
                    
                    # Ask the authoritative server directly if it has an SOA record for the domain.
                    # An SOA record is the definitive proof that a server is authoritative for a zone.
                    auth_resolver.resolve(domain, 'SOA', raise_on_no_answer=True)
                    
                    # If the line above doesn't raise an exception, it means the server responded authoritatively.
                    is_consistent = True
                    # We only need one of the listed name servers to confirm authority, so we can stop checking.
                    break 
                except Exception as e:
                    # This specific NS is not authoritative, or another error occurred. Try the next one.
                    print(f"  NS consistency sub-check for {ns_host} failed: {e}")
                    continue
            
            results['ns_consistent_with_self'] = "OK" if is_consistent else "Inconsistent"
        else:
            results['ns_consistent_with_self'] = "N/A (No NS)"

        # --- Category Logic ---
        if results['nameservers_found']:
            if any(p in ns for ns in results['nameservers_found'] for p in UNSUCCESSFUL_NS_PATTERNS_CFG):
                results['raw_status'], results['category'] = "UNSUCCESSFUL", "UNSUCCESSFUL"
            elif any(p in ns for ns in results['nameservers_found'] for p in SUCCESSFUL_NS_PATTERNS_CFG):
                results['raw_status'], results['category'] = "SUCCESSFUL", "SUCCESSFUL"
            else:
                # If there's no pattern match, but NS exist, it's neutral/other
                results['raw_status'], results['category'] = "NEUTRAL", "OTHER"
        else:
             results['raw_status'], results['category'] = "NO NS RECORDS", "OTHER"

        log_to_db(
            domain_name=domain,
            nameservers_str=', '.join(results['nameservers_found']),
            raw_status_val=results['raw_status'],
            details_val=results.get('details', ''),
            category_val=results['category'],
            run_id=current_run_id,
            **results
        )
        time.sleep(0.1)

    update_status_file("Completed", "complete", total_domains, total_domains)
    if status_file_path and os.path.exists(status_file_path):
        try: time.sleep(2); os.remove(status_file_path)
        except OSError as e: print(f"Error removing status file {status_file_path}: {e}")

if __name__ == '__main__':
    if '--update-schema' in sys.argv:
        print("Attempting to initialize and update database schema...")
        init_db()
        print("Database schema check/update complete.")
        sys.exit(0)

    parser = argparse.ArgumentParser(description="DNS NS Checker and Logger.")
    parser.add_argument('--recheck-successful', action='store_true', help="Re-check 'SUCCESSFUL' domains.")
    parser.add_argument('--input-file', default=DOMAINS_INPUT_FILE_CFG, 
                        help=f"Input file for domains. Default: {DOMAINS_INPUT_FILE_CFG}")
    parser.add_argument('--recheck-category', help="Re-check domains in specified category.")
    parser.add_argument('--domain', help="Check a single domain.")
    parser.add_argument('--record-types', nargs='*', 
                        help=f"Record types (e.g., NS A MX). Default: {','.join(DEFAULT_RECORD_TYPES_CFG)}")
    parser.add_argument('--dns-server', help="Custom DNS server IP.")
    parser.add_argument('--batch-run-id', required=True, help="Batch run ID for progress tracking.")
    parser.add_argument('--run-type-override', help="Override run_type in 'runs' table.")
    parser.add_argument('--domain-ids-from-ui', help="Comma-separated domain IDs to check.")
    parser.add_argument('--check-new-domains-from-file', action='store_true', help="Check domains in input-file NOT in DB.")
    
    args = parser.parse_args()

    domains_to_check = []
    run_mode_description = ""
    run_type_for_db = args.run_type_override

    if args.domain:
        domains_to_check = [args.domain]
    elif args.recheck_successful:
        domains_to_check = get_successful_domains_from_db()
    elif args.recheck_category:
        domains_to_check = get_domains_by_latest_category(args.recheck_category.upper())
    elif args.domain_ids_from_ui:
        domains_to_check = get_domains_by_ids_from_db(args.domain_ids_from_ui)
    elif args.check_new_domains_from_file:
        all_file_domains = load_domains_from_file(args.input_file)
        if all_file_domains is not None:
            db_domains = get_all_domains_from_db_set()
            domains_to_check = [d for d in all_file_domains if d.lower() not in db_domains]
    else:
        domains_to_check = load_domains_from_file(args.input_file)

    if domains_to_check is None:
        sys.exit(1)
        
    print(f"Starting DNS lookup for {len(domains_to_check)} domains...")
    check_domain_nameservers(
        domain_list=domains_to_check,
        record_types_to_check=args.record_types,
        custom_dns_server=args.dns_server,
        batch_run_id=args.batch_run_id,
        run_type_override=run_type_for_db
    )
    print("DNS lookup process finished.")