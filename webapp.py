# webapp.py
import sqlite3
from flask import Flask, render_template, request, g, url_for, Response, flash, redirect, stream_with_context, jsonify, session
from werkzeug.utils import secure_filename 
import csv
import io
import subprocess
import sys
import os
import json
import time
from datetime import datetime, date, timedelta
import uuid
import configparser
import re 

app = Flask(__name__)
app.secret_key = os.urandom(24) 

# --- Configuration Loading ---
config_parser_obj = configparser.ConfigParser()
CONFIG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")

if not os.path.exists(CONFIG_FILE_PATH):
    print(f"CRITICAL: Configuration file '{CONFIG_FILE_PATH}' not found. Exiting.")
    sys.exit(1)
config_parser_obj.read(CONFIG_FILE_PATH)

try:
    DB_NAME = config_parser_obj.get('General', 'db_name', fallback="dns_lookup_results.db")
    STATUS_FILE_DIR_NAME = config_parser_obj.get('General', 'status_file_dir_name', fallback="status_updates")
    DNS_CHECKER_SCRIPT_NAME = config_parser_obj.get('General', 'dns_checker_script_name', fallback="dns_checker.py")
    WHOIS_SCRIPT_NAME = config_parser_obj.get('General', 'whois_script_name', fallback="run_whois_lookup.py")
    PARSE_WHOIS_SCRIPT_NAME = config_parser_obj.get('General', 'parse_whois_script_name', fallback="parse_whois.py")
    DOMAINS_INPUT_FILE = config_parser_obj.get('General', 'domains_input_file', fallback="domains.txt")

except configparser.NoSectionError as e:
    print(f"CRITICAL: Missing section in config.ini: {e}. Exiting.")
    sys.exit(1)
except configparser.NoOptionError as e:
    print(f"CRITICAL: Missing option in config.ini: {e}. Exiting.")
    sys.exit(1)

DNS_CHECKER_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DNS_CHECKER_SCRIPT_NAME)
WHOIS_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), WHOIS_SCRIPT_NAME)
PARSE_WHOIS_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), PARSE_WHOIS_SCRIPT_NAME)
STATUS_FILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), STATUS_FILE_DIR_NAME)
DOMAINS_TXT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DOMAINS_INPUT_FILE)


# --- Global Definitions & Validation Helpers ---
VALID_SORT_COLUMNS_MAP = {
    'id': 'id', 'timestamp': 'timestamp', 'domain': 'domain_name',
    'nameservers': 'nameservers_found', 'status': 'raw_status',
    'details': 'details', 'category': 'category',
    'whois_privacy': 'whois_privacy_enabled', 
    'selected_status': 'selected_status',
    'created_date': 'creation_date_from_parse',
    'expiry_date': 'expiry_date_from_parse',
    'updated_date': 'updated_date_from_parse',
	'ptr': 'ptr_records',
    'dnssec': 'dnssec_status'
}
DEFAULT_PAGE = 1
DEFAULT_PER_PAGE = 100
MAX_STRING_LENGTH = 255
DOMAIN_REGEX = re.compile(
    r'^((?:[a-zA-Z0-9]'  
    r'(?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?)'  
    r'(?:\.(?!-))+)'  
    r'([a-zA-Z]{2,63}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$' 
)

def is_safe_id_list(id_list_csv_str):
    if not id_list_csv_str: return []
    ids = []
    parts = id_list_csv_str.split(',')
    if len(parts) > 10000:
        return False 
    for item in parts:
        item_stripped = item.strip()
        if item_stripped.isdigit():
            ids.append(int(item_stripped))
        elif item_stripped: 
            return False 
    return ids

# --- Database Connection Handling ---
def get_db():
    db_conn = getattr(g, '_database', None)
    if db_conn is None:
        db_conn = g._database = sqlite3.connect(DB_NAME) 
        db_conn.row_factory = sqlite3.Row 
    return db_conn

@app.teardown_appcontext
def close_connection(exception):
    db_conn = getattr(g, '_database', None)
    if db_conn is not None:
        db_conn.close()

# --- Jinja2 Custom Filter ---
@app.template_filter('from_json')
def from_json_filter(value):
    if value:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value 
    return None

# --- Query Building Helper ---
def build_query_components(search_term, search_by_param, category_filter, sort_by_url_key, sort_order, page, per_page, 
                           start_date_str=None, end_date_str=None, multi_category_filter=None, whois_privacy_filter=None, 
                           checked_ids_for_sort=None, 
                           created_date_filter=None, expiry_date_filter=None, updated_date_filter=None):

    base_from_clause = (
        "FROM lookup_results lr "
        "JOIN ("
        "    SELECT domain_name, MAX(timestamp) as max_ts FROM lookup_results GROUP BY domain_name"
        ") as latest_lr_ts ON lr.domain_name = latest_lr_ts.domain_name AND lr.timestamp = latest_lr_ts.max_ts "
        "LEFT JOIN ("
        "   SELECT domain_name, MAX(lookup_timestamp) as max_ts FROM whois_records GROUP BY domain_name"
        ") as latest_wr_ts ON lr.domain_name = latest_wr_ts.domain_name "
        "LEFT JOIN whois_records latest_wr ON lr.domain_name = latest_wr.domain_name AND latest_wr.lookup_timestamp = latest_wr_ts.max_ts "
    )

    select_clause = (
        "SELECT lr.id, lr.timestamp, lr.domain_name, lr.nameservers_found, lr.raw_status, lr.details, lr.category, "
        "lr.a_records, lr.aaaa_records, lr.mx_records, lr.txt_records, lr.cname_record, lr.soa_record_details, "
        "lr.soa_serial_changed, lr.ns_consistent_with_self, lr.ptr_records, lr.dnssec_status, "
        "latest_wr.whois_privacy_enabled, "
        "latest_wr.creation_date_from_parse, latest_wr.expiry_date_from_parse, latest_wr.updated_date_from_parse "
    )

    conditions = []
    params = []

    if search_term:
        search_by_db_col_map = { 
            'domain_name': 'lr.domain_name', 'nameservers_found': 'lr.nameservers_found',
            'raw_status': 'lr.raw_status', 'details': 'lr.details', 'category': 'lr.category', 'id': 'lr.id',
            'a_records': 'lr.a_records', 'aaaa_records': 'lr.aaaa_records', 'mx_records': 'lr.mx_records',
            'txt_records': 'lr.txt_records', 'cname_record': 'lr.cname_record', 'soa_record_details': 'lr.soa_record_details',
            'ns_consistent_with_self': 'lr.ns_consistent_with_self',
            'whois_privacy': 'latest_wr.whois_privacy_enabled',
            'ptr_records': 'lr.ptr_records',
            'dnssec_status': 'lr.dnssec_status'
        }
        search_by_db_col = search_by_db_col_map.get(search_by_param, 'lr.domain_name')
        if search_by_param == 'whois_privacy': 
            if search_term.lower() in ['yes', 'true', '1']:
                conditions.append("latest_wr.whois_privacy_enabled = 1")
            elif search_term.lower() in ['no', 'false', '0']:
                 conditions.append("(latest_wr.whois_privacy_enabled = 0 OR latest_wr.whois_privacy_enabled IS NULL)")
        else:
            conditions.append(f"{search_by_db_col} LIKE ?")
            params.append(f"%{search_term}%")

    if category_filter and not multi_category_filter: 
        conditions.append("lr.category = ?")
        params.append(category_filter)
    
    if multi_category_filter: 
        placeholders = ','.join('?' * len(multi_category_filter))
        conditions.append(f"lr.category IN ({placeholders})")
        params.extend(multi_category_filter)

    if start_date_str:
        conditions.append("lr.timestamp >= ?")
        params.append(start_date_str + " 00:00:00") 
    if end_date_str:
        conditions.append("lr.timestamp <= ?")
        params.append(end_date_str + " 23:59:59") 
    
    if whois_privacy_filter: 
        if whois_privacy_filter.lower() == 'yes':
            conditions.append("latest_wr.whois_privacy_enabled = 1") 
        elif whois_privacy_filter.lower() == 'no':
            conditions.append("(latest_wr.whois_privacy_enabled = 0 OR latest_wr.whois_privacy_enabled IS NULL)")
            
    if created_date_filter:
        conditions.append("latest_wr.creation_date_from_parse = ?")
        params.append(created_date_filter)
    if expiry_date_filter:
        conditions.append("latest_wr.expiry_date_from_parse = ?")
        params.append(expiry_date_filter)
    if updated_date_filter:
        conditions.append("latest_wr.updated_date_from_parse = ?")
        params.append(updated_date_filter)
    
    where_clause_str = ""
    if conditions:
        where_clause_str = "WHERE " + " AND ".join(conditions)

    count_query = f"SELECT COUNT(lr.id) as total {base_from_clause} {where_clause_str}"
    
    db_column_for_sql_order_by = 'lr.timestamp' 
    effective_sort_key_for_ui = 'timestamp' 
    if sort_by_url_key in VALID_SORT_COLUMNS_MAP:
        mapped_col_name = VALID_SORT_COLUMNS_MAP[sort_by_url_key]
        effective_sort_key_for_ui = sort_by_url_key 
        if sort_by_url_key in ['whois_privacy', 'created_date', 'expiry_date', 'updated_date']:
             db_column_for_sql_order_by = f"latest_wr.{mapped_col_name}"
        elif sort_by_url_key != 'selected_status':
             db_column_for_sql_order_by = f"lr.{mapped_col_name}"
    
    validated_sort_order_sql = 'DESC' if sort_order.lower() not in ['asc', 'desc'] else sort_order.upper()
    
    order_by_parts = []
    if sort_by_url_key == 'selected_status' and checked_ids_for_sort:
        id_placeholders = ','.join('?' * len(checked_ids_for_sort))
        order_direction = 'ASC' if validated_sort_order_sql == 'ASC' else 'DESC'
        order_by_parts.append(f"CASE WHEN lr.id IN ({id_placeholders}) THEN 0 ELSE 1 END {order_direction}")
        params_for_full_query = list(params) + checked_ids_for_sort 
    else:
        params_for_full_query = list(params)
    
    if db_column_for_sql_order_by == 'lr.domain_name':
        order_by_parts.append(f"{db_column_for_sql_order_by} COLLATE NOCASE {validated_sort_order_sql}")
    elif sort_by_url_key != 'selected_status': 
        order_by_parts.append(f"{db_column_for_sql_order_by} {validated_sort_order_sql}")

    order_by_parts.append(f"lr.id {validated_sort_order_sql}") 
    order_by_clause_str = f"ORDER BY {', '.join(order_by_parts)}"

    offset = (page - 1) * per_page
    limit_clause_str = f"LIMIT {per_page} OFFSET {offset}"

    full_query = f"{select_clause} {base_from_clause} {where_clause_str} {order_by_clause_str} {limit_clause_str}"
    
    export_header_cols = ['id', 'timestamp', 'domain_name', 'nameservers_found', 'raw_status', 'details', 'category', 'a_records', 'aaaa_records', 'mx_records', 'txt_records', 'cname_record', 'soa_record_details', 'soa_serial_changed', 'ns_consistent_with_self', 'whois_privacy_enabled', 'ptr_records', 'dnssec_status'] 
    
    query_for_all_filtered_export = f"{select_clause} {base_from_clause} {where_clause_str} {order_by_clause_str}"

    return full_query, count_query, params, params_for_full_query, effective_sort_key_for_ui, validated_sort_order_sql.lower(), where_clause_str, query_for_all_filtered_export, export_header_cols
def get_domains_txt_not_in_database():
    domains_from_txt = []
    try:
        with open(DOMAINS_TXT_PATH, 'r') as f: 
            for line in f:
                domain = line.strip().lower() 
                if domain and not domain.startswith("#"):
                    domains_from_txt.append(domain)
    except FileNotFoundError:
        print(f"Warning: {DOMAINS_TXT_PATH} not found for new domains calculation.")
        return []

    all_domains_in_db = set()
    conn = get_db() 
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT DISTINCT lower(domain_name) FROM lookup_results") 
        fetched_rows = cursor.fetchall()
        for row in fetched_rows:
            all_domains_in_db.add(row[0]) 
    except sqlite3.Error as e:
        print(f"Error fetching all domains from DB for diff: {e}")
        return []

    new_domains = [domain for domain in domains_from_txt if domain not in all_domains_in_db]
    return new_domains

@app.route('/get_new_domains_count', methods=['GET']) 
def get_new_domains_count_route():
    try:
        new_domains_list = get_domains_txt_not_in_database()
        return jsonify(count=len(new_domains_list), success=True)
    except Exception as e:
        print(f"Error in /get_new_domains_count: {e}")
        return jsonify(count=0, success=False, error=str(e))

def get_domains_without_whois_helper(): 
    conn = get_db()
    cursor = conn.cursor()
    domains = []
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
    except sqlite3.Error as e:
        print(f"DB error fetching domains without WHOIS for count: {e}")
    return domains

@app.route('/get_domains_without_whois_count', methods=['GET'])
def get_domains_without_whois_count_route():
    try:
        domains_list = get_domains_without_whois_helper()
        return jsonify(count=len(domains_list), success=True)
    except Exception as e:
        print(f"Error in /get_domains_without_whois_count: {e}")
        return jsonify(count=0, success=False, error=str(e))

def get_all_db_domains_helper(): 
    conn = get_db()
    cursor = conn.cursor()
    domains = []
    try:
        cursor.execute("SELECT DISTINCT domain_name FROM lookup_results")
        rows = cursor.fetchall()
        domains = [row['domain_name'] for row in rows if row['domain_name']]
    except sqlite3.Error as e:
        print(f"DB error fetching all domains for count: {e}")
    return domains

      
@app.route('/get_all_db_domains_count', methods=['GET'])
def get_all_db_domains_count_route():
    try:
        domains_list = get_all_db_domains_helper()
        return jsonify(count=len(domains_list), success=True)
    except Exception as e:
        print(f"Error in /get_all_db_domains_count: {e}")
        return jsonify(count=0, success=False, error=str(e))

def _run_script_and_get_batch_id(script_path, script_args, log_message):
    """Helper to run a background script and return a JSON response."""
    if not os.path.exists(script_path):
        return jsonify({"success": False, "message": f"Script not found at {script_path}."}), 500

    batch_run_id = str(uuid.uuid4())
    base_args = [sys.executable, script_path, '--batch-run-id', batch_run_id]
    full_args = base_args + script_args

    try:
        print(f"Attempting to run script (Batch ID: {batch_run_id}) for {log_message} with args: {full_args}")
        subprocess.Popen(full_args, text=True, bufsize=1)
        time.sleep(0.2)
        return jsonify({
            "success": True, 
            "message": f"Task '{log_message}' started successfully.",
            "batch_run_id": batch_run_id
        })
    except Exception as e:
        print(f"Exception running script for {log_message} (Batch ID: {batch_run_id}): {e}, ARGS: {full_args}")
        return jsonify({"success": False, "message": f"Error starting task '{log_message}': {e}"}), 500

    

def get_expiring_domain_counts():
    conn = get_db()
    cursor = conn.cursor()
    today = date.today()
    
    # This month
    start_of_this_month = today.replace(day=1)
    next_month_date = (start_of_this_month.replace(day=28) + timedelta(days=4)).replace(day=1)
    end_of_this_month = next_month_date - timedelta(days=1)
    
    # This week (next 7 days including today)
    end_of_this_week = today + timedelta(days=7)
    
    # Today
    today_str = today.strftime('%Y-%m-%d')

    start_of_next_week = today + timedelta(days=8)
    end_of_next_week = today + timedelta(days=14)

    start_of_next_month = next_month_date
    end_of_next_next_month = (start_of_next_month.replace(day=28) + timedelta(days=4)).replace(day=1)
    end_of_next_month = end_of_next_next_month - timedelta(days=1)
    
    counts = {'today': 0, 'week': 0, 'month': 0, 'next_week': 0, 'next_month': 0}
    try:
        query = """
        SELECT
            SUM(CASE WHEN expiry_date_from_parse = ? THEN 1 ELSE 0 END) as today_count,
            SUM(CASE WHEN expiry_date_from_parse BETWEEN ? AND ? THEN 1 ELSE 0 END) as week_count,
            SUM(CASE WHEN expiry_date_from_parse BETWEEN ? AND ? THEN 1 ELSE 0 END) as month_count,
            SUM(CASE WHEN expiry_date_from_parse BETWEEN ? AND ? THEN 1 ELSE 0 END) as next_week_count,
            SUM(CASE WHEN expiry_date_from_parse BETWEEN ? AND ? THEN 1 ELSE 0 END) as next_month_count
        FROM (
            SELECT domain_name, MAX(lookup_timestamp) as max_ts
            FROM whois_records
            WHERE expiry_date_from_parse IS NOT NULL
            GROUP BY domain_name
        ) as latest_wr_ts
        JOIN whois_records latest_wr ON latest_wr.domain_name = latest_wr_ts.domain_name 
                                     AND latest_wr.lookup_timestamp = latest_wr_ts.max_ts
        """
        params = (
            today_str,
            today.strftime('%Y-%m-%d'), end_of_this_week.strftime('%Y-%m-%d'),
            start_of_this_month.strftime('%Y-%m-%d'), end_of_this_month.strftime('%Y-%m-%d'),
            start_of_next_week.strftime('%Y-%m-%d'), end_of_next_week.strftime('%Y-%m-%d'),
            start_of_next_month.strftime('%Y-%m-%d'), end_of_next_month.strftime('%Y-%m-%d')
        )
        cursor.execute(query, params)
        result = cursor.fetchone()
        if result:
            counts['today'] = result['today_count'] or 0
            counts['week'] = result['week_count'] or 0
            counts['month'] = result['month_count'] or 0
            counts['next_week'] = result['next_week_count'] or 0
            counts['next_month'] = result['next_month_count'] or 0
    except sqlite3.Error as e:
        print(f"Error fetching expiring domain counts: {e}")
        
    return counts

@app.route('/', methods=['GET', 'POST'])
def index():
    is_post_sort = request.method == 'POST'
    is_get_filter = request.method == 'GET' and any(k in request.args for k in [
        'page', 'per_page', 'search_term', 'search_by', 'multi_category_filter', 
        'start_date', 'end_date', 'sort_by', 'sort_order', 'category_filter', 'whois_privacy_filter',
        'created_date_filter', 'expiry_date_filter', 'updated_date_filter'
    ])
    new_filters_applied = is_post_sort or is_get_filter
    
    source = request.form if is_post_sort else request.args

    try:
        page = int(source.get('page', session.get('filter_page', DEFAULT_PAGE) if not new_filters_applied else DEFAULT_PAGE))
        if page < 1:
            page = 1
    except (ValueError, TypeError):
        page = DEFAULT_PAGE

    try:
        per_page = int(source.get('per_page', session.get('filter_per_page', DEFAULT_PER_PAGE) if not new_filters_applied else DEFAULT_PER_PAGE))
        if per_page < 1:
            per_page = 1
        elif per_page > 200: 
            per_page = 200
    except (ValueError, TypeError):
        per_page = DEFAULT_PER_PAGE

    if request.args.get('clear_all_filters') == 'true':
        keys_to_clear = [
            'filter_page', 'filter_per_page', 'filter_search_term', 'filter_search_by',
            'filter_multi_category', 'filter_start_date', 'filter_end_date',
            'filter_sort_by', 'filter_sort_order', 'filter_category_for_form',
            'filter_whois_privacy', 'filter_checked_ids',
            'filter_created_date', 'filter_expiry_date', 'filter_updated_date'
        ]
        for key in keys_to_clear:
            session.pop(key, None)
        return redirect(url_for('index'))

    search_term = source.get('search_term', session.get('filter_search_term', '') if not new_filters_applied else '').strip()[:MAX_STRING_LENGTH]
    search_by_param = source.get('search_by', session.get('filter_search_by', 'domain_name') if not new_filters_applied else 'domain_name')
    multi_category_filter_args = source.getlist('multi_category_filter')
    multi_category_filter = [cat[:MAX_STRING_LENGTH] for cat in multi_category_filter_args] if multi_category_filter_args else (session.get('filter_multi_category', []) if not new_filters_applied else [])
    category_filter_for_form = source.get('category_filter', session.get('filter_category_for_form', '') if not new_filters_applied else '').strip()[:MAX_STRING_LENGTH]
    start_date_str = source.get('start_date', session.get('filter_start_date', '') if not new_filters_applied else '').strip()
    end_date_str = source.get('end_date', session.get('filter_end_date', '') if not new_filters_applied else '').strip()
    sort_by_url_key_from_req = source.get('sort_by', session.get('filter_sort_by', 'timestamp') if not new_filters_applied else 'timestamp')
    sort_order_from_req = source.get('sort_order', session.get('filter_sort_order', 'desc') if not new_filters_applied else 'desc')
    whois_privacy_filter_val = source.get('whois_privacy_filter', session.get('filter_whois_privacy', '') if not new_filters_applied else '')
    checked_ids_csv = source.get('checked_ids_for_sort', session.get('filter_checked_ids', '') if not new_filters_applied else '')
    checked_ids_for_sort_list = is_safe_id_list(checked_ids_csv) if checked_ids_csv else []

    created_date_filter_val = source.get('created_date_filter', session.get('filter_created_date', '') if not new_filters_applied else '').strip()
    expiry_date_filter_val = source.get('expiry_date_filter', session.get('filter_expiry_date', '') if not new_filters_applied else '').strip()
    updated_date_filter_val = source.get('updated_date_filter', session.get('filter_updated_date', '') if not new_filters_applied else '').strip()

    if new_filters_applied:
        session['filter_page'] = page
        session['filter_per_page'] = per_page
        session['filter_search_term'] = search_term
        session['filter_search_by'] = search_by_param
        session['filter_multi_category'] = multi_category_filter
        session['filter_category_for_form'] = category_filter_for_form
        session['filter_start_date'] = start_date_str
        session['filter_end_date'] = end_date_str
        session['filter_sort_by'] = sort_by_url_key_from_req
        session['filter_sort_order'] = sort_order_from_req
        session['filter_whois_privacy'] = whois_privacy_filter_val
        session['filter_checked_ids'] = checked_ids_csv
        session['filter_created_date'] = created_date_filter_val
        session['filter_expiry_date'] = expiry_date_filter_val
        session['filter_updated_date'] = updated_date_filter_val
             
    if page < 1: page = DEFAULT_PAGE
    if per_page < 1 or per_page > 200: per_page = DEFAULT_PER_PAGE 

    full_query, count_query, params_for_count, params_for_full, actual_sort_key_used, actual_validated_order, _, query_for_export, export_headers = \
        build_query_components(search_term, search_by_param, category_filter_for_form, 
                                sort_by_url_key_from_req, sort_order_from_req, page, per_page,
                                start_date_str=start_date_str, end_date_str=end_date_str,
                                multi_category_filter=multi_category_filter,
                                whois_privacy_filter=whois_privacy_filter_val,
                                checked_ids_for_sort=checked_ids_for_sort_list,
                                created_date_filter=created_date_filter_val,
                                expiry_date_filter=expiry_date_filter_val,
                                updated_date_filter=updated_date_filter_val)
             
    conn = get_db()
    cursor = conn.cursor()
    results = []
    total_records_in_db_for_filter = 0
    error_message = None
    
    try:
        cursor.execute(count_query, params_for_count)
        count_result = cursor.fetchone()
        if count_result:
            total_records_in_db_for_filter = count_result['total']
        
        cursor.execute(full_query, params_for_full)
        results = cursor.fetchall()
    except sqlite3.Error as e:
        error_message = f"Database query error: {e}"
        print(f"ERROR in index route: {error_message}.\nFull Query: {full_query}\nParams: {params_for_full}\nCount Query: {count_query}\nParams: {params_for_count}")

    total_pages = (total_records_in_db_for_filter + per_page - 1) // per_page if total_records_in_db_for_filter > 0 else 1
    current_sorting_info = {'by': actual_sort_key_used, 'order': actual_validated_order}
    pagination_checked_ids = checked_ids_csv
    pagination_info = {'page': page, 'per_page': per_page, 'total_pages': total_pages, 'total_records': total_records_in_db_for_filter, 'has_prev': page > 1, 'has_next': page < total_pages, 'prev_num': page - 1 if page > 1 else None, 'next_num': page + 1 if page < total_pages else None}
    
    categories_from_db = []
    try:
        cursor.execute("SELECT DISTINCT category FROM lookup_results WHERE category IS NOT NULL ORDER BY category")
        categories_from_db = [row['category'] for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Error fetching categories: {e}")

    total_unique_domains = 0; total_lookup_entries = 0; category_latest_counts = {} 
    try:
        cursor.execute("SELECT COUNT(DISTINCT domain_name) FROM lookup_results"); total_unique_domains = cursor.fetchone()[0] 
        cursor.execute("SELECT COUNT(*) FROM lookup_results"); total_lookup_entries = cursor.fetchone()[0]
        cursor.execute("""
            SELECT T1.category, COUNT(T1.domain_name) as count FROM lookup_results AS T1
            INNER JOIN (SELECT domain_name, MAX(timestamp) AS max_timestamp FROM lookup_results GROUP BY domain_name) AS T2 
            ON T1.domain_name = T2.domain_name AND T1.timestamp = T2.max_timestamp
            WHERE T1.category IS NOT NULL GROUP BY T1.category;
        """);
        for row in cursor.fetchall(): category_latest_counts[row['category']] = row['count']
        cursor.execute("""
            SELECT COUNT(T1.domain_name) FROM lookup_results AS T1
            INNER JOIN (SELECT domain_name, MAX(timestamp) AS max_timestamp FROM lookup_results GROUP BY domain_name) AS T2 
            ON T1.domain_name = T2.domain_name AND T1.timestamp = T2.max_timestamp WHERE T1.category IS NULL;
        """);
        null_category_count = cursor.fetchone()[0]
        category_latest_counts['SUCCESSFUL'] = category_latest_counts.get('SUCCESSFUL', 0)
        category_latest_counts['UNSUCCESSFUL'] = category_latest_counts.get('UNSUCCESSFUL', 0)
        category_latest_counts['OTHER'] = category_latest_counts.get('OTHER', 0) + null_category_count
        all_categorized_current = sum(category_latest_counts.values())
    except sqlite3.Error as e:
        print(f"Error fetching category counts for display: {e}")
        category_latest_counts = {'SUCCESSFUL': 0, 'UNSUCCESSFUL': 0, 'OTHER': 0}; all_categorized_current = 0
        
    expiring_counts = get_expiring_domain_counts()

    return render_template('index.html', 
                           results=results, search_term=search_term, search_by_param=search_by_param,
                           category_filter=category_filter_for_form, multi_category_filter=multi_category_filter,
                           start_date=start_date_str, end_date=end_date_str, whois_privacy_filter=whois_privacy_filter_val, 
                           current_sorting_info=current_sorting_info, pagination_info=pagination_info, 
                           pagination_checked_ids_csv=pagination_checked_ids, error_message=error_message,
                           valid_sort_columns=list(VALID_SORT_COLUMNS_MAP.keys()), categories=categories_from_db, 
                           total_unique_domains=total_unique_domains, total_lookup_entries=total_lookup_entries,
                           category_latest_counts=category_latest_counts, all_categorized_current=all_categorized_current,
                           per_page=per_page, default_domains_input_file=DOMAINS_INPUT_FILE,
                           created_date_filter=created_date_filter_val,
                           expiry_date_filter=expiry_date_filter_val,
                           updated_date_filter=updated_date_filter_val,
                           expiring_counts=expiring_counts
                           )

@app.route('/expiring_domains')
def expiring_domains():
    period = request.args.get('period', 'month')
    export = request.args.get('export', 'false').lower() == 'true'
    
    today = date.today()
    if period == 'today':
        start_date = end_date = today
    elif period == 'week':
        start_date = today
        end_date = today + timedelta(days=7)
    elif period == 'next_week':
        start_date = today + timedelta(days=8)
        end_date = today + timedelta(days=14)
    elif period == 'next_month':
        start_of_this_month = today.replace(day=1)
        start_date = (start_of_this_month.replace(day=28) + timedelta(days=4)).replace(day=1)
        end_of_next_next_month = (start_date.replace(day=28) + timedelta(days=4)).replace(day=1)
        end_date = end_of_next_next_month - timedelta(days=1)
    else: 
        start_date = today.replace(day=1)
        next_month_date = (start_date.replace(day=28) + timedelta(days=4)).replace(day=1)
        end_date = next_month_date - timedelta(days=1)

    start_date_str = start_date.strftime('%Y-%m-%d')
    end_date_str = end_date.strftime('%Y-%m-%d')

    conn = get_db()
    cursor = conn.cursor()
    
    query = """
        SELECT 
            latest_lr.domain_name,
            latest_wr.expiry_date_from_parse,
            latest_lr.category
        FROM (
            SELECT T1.domain_name, T1.category
            FROM lookup_results AS T1
            INNER JOIN (
                SELECT domain_name, MAX(timestamp) AS max_timestamp
                FROM lookup_results GROUP BY domain_name
            ) AS T2 ON T1.domain_name = T2.domain_name AND T1.timestamp = T2.max_timestamp
        ) AS latest_lr
        JOIN (
            SELECT domain_name, MAX(lookup_timestamp) as max_ts
            FROM whois_records WHERE expiry_date_from_parse IS NOT NULL
            GROUP BY domain_name
        ) as latest_wr_ts ON latest_lr.domain_name = latest_wr_ts.domain_name
        JOIN whois_records latest_wr ON latest_lr.domain_name = latest_wr.domain_name 
                                     AND latest_wr.lookup_timestamp = latest_wr_ts.max_ts
        WHERE latest_wr.expiry_date_from_parse BETWEEN ? AND ?
        ORDER BY latest_wr.expiry_date_from_parse ASC, latest_lr.domain_name ASC
    """

    try:
        cursor.execute(query, (start_date_str, end_date_str))
        domains = [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Error fetching unique expiring domains: {e}")
        return jsonify({"error": str(e)}), 500

    if export:
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['Domain Name', 'Expiry Date', 'Category'])
        for domain in domains:
            cw.writerow([domain['domain_name'], domain['expiry_date_from_parse'], domain['category']])
        output = si.getvalue()
        si.close()
        filename = f"expiring_domains_{period}_{today.strftime('%Y%m%d')}.csv"
        return Response(
            output,
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename={filename}"}
        )
    else:
        return jsonify(domains)

    if export:
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['Domain Name', 'Expiry Date', 'Category'])
        for domain in domains:
            cw.writerow([domain['domain_name'], domain['expiry_date_from_parse'], domain['category']])
        output = si.getvalue()
        si.close()
        filename = f"expiring_domains_{period}_{today.strftime('%Y%m%d')}.csv"
        return Response(
            output,
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename={filename}"}
        )
    else:
        return jsonify(domains)

@app.route('/run_batch_parse', methods=['POST'])
def run_batch_parse():
    target_type = request.form.get('parse_target_type')
    script_args = []
    log_message = "Parse WHOIS"

    allowed_target_types = ['category', 'selected_ids', 'no_parsed_data_yet', 'all_db_domains']
    if target_type not in allowed_target_types:
        return jsonify({"success": False, "message": "Invalid target type for Whois parsing."})

    if target_type == 'category':
        category = request.form.get('category_for_parse', '').strip()[:MAX_STRING_LENGTH]
        if not category:
            return jsonify({"success": False, "message": "No category selected for batch parsing."})
        script_args.extend(['--category', category])
        log_message = f"parsing for category '{category}'"
    elif target_type == 'selected_ids':
        domain_ids_csv = request.form.get('globally_selected_ids_for_script')
        safe_ids = is_safe_id_list(domain_ids_csv)
        if not safe_ids:
            return jsonify({"success": False, "message": "No items were selected for parsing."})
        script_args.extend(['--domain-ids', ",".join(map(str, safe_ids))])
        log_message = f"parsing for {len(safe_ids)} selected domains"
    elif target_type == 'no_parsed_data_yet':
        script_args.append('--no-parsed-data-yet')
        log_message = "parsing domains with no date info"
    elif target_type == 'all_db_domains':
        script_args.append('--all-domains-in-db')
        log_message = "parsing ALL domains"

    return _run_script_and_get_batch_id(PARSE_WHOIS_SCRIPT_PATH, script_args, log_message)
@app.route('/add_domain', methods=['POST'])
def add_domain():
    domain = request.form.get('domain_name', '').strip()[:MAX_STRING_LENGTH]
    if not domain:
        flash("Domain name cannot be empty.", "danger")
        return redirect(url_for('index'))
    if not DOMAIN_REGEX.match(domain):
        flash("Invalid domain name format provided.", "danger")
        return redirect(url_for('index'))
    
    batch_run_id = str(uuid.uuid4())
    stdout_log_path = os.path.join(STATUS_FILE_DIR, f"{batch_run_id}_stdout.log")
    stderr_log_path = os.path.join(STATUS_FILE_DIR, f"{batch_run_id}_stderr.log")
    script_args = [sys.executable, DNS_CHECKER_SCRIPT_PATH, '--domain', domain, '--batch-run-id', batch_run_id, '--run-type-override', 'single_domain_add']
    try:
        with open(stdout_log_path, 'w') as stdout_file, open(stderr_log_path, 'w') as stderr_file:
            subprocess.Popen(script_args, stdout=stdout_file, stderr=stderr_file, text=True, bufsize=1)
        time.sleep(0.1) 
        flash(f"Domain '{domain}' added and DNS check started (Batch ID: {batch_run_id}). Progress updates will appear.", "info")
    except Exception as e:
        flash(f"Error adding domain '{domain}': {e}", "danger")
    return redirect(url_for('index', _anchor='batch_progress_section'))

@app.route('/edit_domain_entry', methods=['POST'])
def edit_domain_entry():
    try:
        entry_id = int(request.form.get('entry_id', '0'))
    except ValueError:
        flash("Invalid entry ID.", "danger")
        return redirect(url_for('index'))

    new_domain_name = request.form.get('new_domain_name', '').strip()[:MAX_STRING_LENGTH]

    if entry_id <= 0:
        flash("Valid entry ID is required.", "danger")
        return redirect(url_for('index'))
    if not new_domain_name:
        flash("New domain name cannot be empty.", "danger")
        return redirect(url_for('index'))
    if not DOMAIN_REGEX.match(new_domain_name):
        flash("Invalid new domain name format.", "danger")
        return redirect(url_for('index'))
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT domain_name FROM lookup_results WHERE id = ?", (entry_id,))
        current_domain = cursor.fetchone()
        if not current_domain:
            flash(f"Entry with ID {entry_id} not found.", "danger")
            return redirect(url_for('index'))
        old_domain_name = current_domain['domain_name']
        cursor.execute("UPDATE lookup_results SET domain_name = ? WHERE id = ?", (new_domain_name, entry_id))
        conn.commit()
        flash(f"Domain entry ID {entry_id} updated from '{old_domain_name}' to '{new_domain_name}'.", "success")
        batch_run_id = str(uuid.uuid4())
        stdout_log_path = os.path.join(STATUS_FILE_DIR, f"{batch_run_id}_stdout.log")
        stderr_log_path = os.path.join(STATUS_FILE_DIR, f"{batch_run_id}_stderr.log")
        script_args = [sys.executable, DNS_CHECKER_SCRIPT_PATH, '--domain', new_domain_name, '--batch-run-id', batch_run_id, '--run-type-override', 'single_domain_edit_recheck']
        with open(stdout_log_path, 'w') as stdout_file, open(stderr_log_path, 'w') as stderr_file:
            subprocess.Popen(script_args, stdout=stdout_file, stderr=stderr_file, text=True, bufsize=1)
        time.sleep(0.1)
        flash(f"DNS check for updated domain '{new_domain_name}' started (Batch ID: {batch_run_id}).", "info")
    except sqlite3.Error as e:
        flash(f"Database error updating entry ID {entry_id}: {e}", "danger")
    return redirect(url_for('index'))

@app.route('/delete_domains_bulk', methods=['POST'])
def delete_domains_bulk():
    target_mode = request.form.get('target_mode')
    domain_names_to_delete = []

    if target_mode == 'selected_ids':
        selected_ids_csv = request.form.get('selected_ids')
        safe_ids = is_safe_id_list(selected_ids_csv)
        if not safe_ids:
            flash("No valid domains selected for deletion.", "warning")
            return redirect(url_for('index'))
        
        conn = get_db()
        cursor = conn.cursor()
        placeholders = ','.join('?' * len(safe_ids))
        cursor.execute(f"SELECT DISTINCT domain_name FROM lookup_results WHERE id IN ({placeholders})", safe_ids)
        domain_names_to_delete = [row['domain_name'] for row in cursor.fetchall()]

    elif target_mode == 'filtered':
        _, _, params_for_count, _, _, _, _, query_for_export, _ = \
            build_query_components(
                search_term=request.form.get('search_term'),
                search_by_param=request.form.get('search_by'),
                category_filter=None,
                multi_category_filter=request.form.getlist('multi_category_filter'),
                whois_privacy_filter=request.form.get('whois_privacy_filter'),
                start_date_str=request.form.get('start_date'),
                end_date_str=request.form.get('end_date'),
                created_date_filter=request.form.get('created_date_filter'),
                expiry_date_filter=request.form.get('expiry_date_filter'),
                updated_date_filter=request.form.get('updated_date_filter'),
                sort_by_url_key='id', sort_order='asc', page=1, per_page=100000
            )
        conn = get_db()
        cursor = conn.cursor()
        domain_name_query = query_for_export.replace(
            "SELECT lr.id, lr.timestamp, lr.domain_name, ...", 
            "SELECT lr.domain_name "
        )
        select_pattern = re.compile(r"SELECT.*?FROM", re.IGNORECASE | re.DOTALL)
        domain_name_query = select_pattern.sub("SELECT lr.domain_name FROM", query_for_export, 1)

        cursor.execute(domain_name_query, params_for_count)
        domain_names_to_delete = [row['domain_name'] for row in cursor.fetchall()]

    if not domain_names_to_delete:
        flash("No domains matched the criteria for deletion.", "warning")
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    try:
        placeholders = ','.join('?' for _ in domain_names_to_delete)
        cursor.execute(f"DELETE FROM lookup_results WHERE domain_name IN ({placeholders})", domain_names_to_delete)
        deleted_count = cursor.rowcount
        conn.commit()
        flash(f"Successfully deleted {len(domain_names_to_delete)} domains ({deleted_count} total entries).", "success")
    except sqlite3.Error as e:
        flash(f"Database error during bulk deletion: {e}", "danger")
    return redirect(url_for('index'))
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        placeholders = ','.join('?' for _ in safe_ids)
        cursor.execute(f"DELETE FROM lookup_results WHERE id IN ({placeholders})", safe_ids)
        deleted_count = cursor.rowcount
        conn.commit()
        flash(f"Successfully deleted {deleted_count} domain entries.", "success")
    except sqlite3.Error as e:
        flash(f"Database error during bulk deletion: {e}", "danger")
    return redirect(url_for('index')) 

@app.route('/update_category_bulk', methods=['POST'])
def update_category_bulk():
    target_mode = request.form.get('target_mode')
    new_category = request.form.get('new_category', '').strip()[:MAX_STRING_LENGTH]
    if not new_category:
        flash("New category cannot be empty.", "warning")
        return redirect(url_for('index'))

    domain_names_to_update = []

    if target_mode == 'selected_ids':
        selected_ids_csv = request.form.get('selected_ids')
        safe_ids = is_safe_id_list(selected_ids_csv)
        if not safe_ids:
            flash("No valid domains selected for category update.", "warning")
            return redirect(url_for('index'))
        
        conn = get_db()
        cursor = conn.cursor()
        placeholders = ','.join('?' * len(safe_ids))
        cursor.execute(f"SELECT DISTINCT domain_name FROM lookup_results WHERE id IN ({placeholders})", safe_ids)
        domain_names_to_update = [row['domain_name'] for row in cursor.fetchall()]

    elif target_mode == 'filtered':
        _, _, params_for_count, _, _, _, _, query_for_export, _ = \
            build_query_components(
                search_term=request.form.get('search_term'),
                search_by_param=request.form.get('search_by'),
                category_filter=None,
                multi_category_filter=request.form.getlist('multi_category_filter'),
                whois_privacy_filter=request.form.get('whois_privacy_filter'),
                start_date_str=request.form.get('start_date'),
                end_date_str=request.form.get('end_date'),
                created_date_filter=request.form.get('created_date_filter'),
                expiry_date_filter=request.form.get('expiry_date_filter'),
                updated_date_filter=request.form.get('updated_date_filter'),
                sort_by_url_key='id', sort_order='asc', page=1, per_page=100000
            )
        conn = get_db()
        cursor = conn.cursor()
        select_pattern = re.compile(r"SELECT.*?FROM", re.IGNORECASE | re.DOTALL)
        domain_name_query = select_pattern.sub("SELECT lr.domain_name FROM", query_for_export, 1)
        cursor.execute(domain_name_query, params_for_count)
        domain_names_to_update = [row['domain_name'] for row in cursor.fetchall()]

    if not domain_names_to_update:
        flash("No domains matched the criteria for category update.", "warning")
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    try:
        placeholders = ','.join('?' for _ in domain_names_to_update)
        id_query = f"""
            SELECT T1.id FROM lookup_results AS T1
            INNER JOIN (
                SELECT domain_name, MAX(timestamp) AS max_timestamp 
                FROM lookup_results WHERE domain_name IN ({placeholders}) GROUP BY domain_name
            ) AS T2 
            ON T1.domain_name = T2.domain_name AND T1.timestamp = T2.max_timestamp
        """
        cursor.execute(id_query, domain_names_to_update)
        ids_to_update = [row['id'] for row in cursor.fetchall()]

        if not ids_to_update:
            flash("Could not find latest entries for the selected domains.", "warning")
            return redirect(url_for('index'))

        id_placeholders = ','.join('?' * len(ids_to_update))
        cursor.execute(f"UPDATE lookup_results SET category = ? WHERE id IN ({id_placeholders})", (new_category, *ids_to_update))
        updated_count = cursor.rowcount
        conn.commit()
        flash(f"Successfully updated category for {updated_count} domains to '{new_category}'.", "success")
    except sqlite3.Error as e:
        flash(f"Database error during bulk category update: {e}", "danger")
        
    return redirect(url_for('index')) 

@app.route('/upload_domains_csv', methods=['POST'])
def upload_domains_csv():
    if 'csv_file' not in request.files:
        flash("No CSV file part.", "danger")
        return redirect(url_for('index'))
    csv_file = request.files['csv_file']
    if csv_file.filename == '':
        flash("No selected file.", "danger")
        return redirect(url_for('index'))
    
    filename = secure_filename(csv_file.filename) 
    if not (filename.endswith('.csv') or filename.endswith('.txt')):
        flash("Invalid file type. Please upload a CSV or TXT file.", "danger")
        return redirect(url_for('index'))

    domains_to_process = []
    try:
        if csv_file.content_length > 5 * 1024 * 1024: 
             flash("Uploaded file is too large (max 5MB).", "danger")
             return redirect(url_for('index'))

        stream = io.StringIO(csv_file.stream.read().decode("UTF8", errors="ignore"))
        for line_num, line in enumerate(stream):
            if line_num >= 10000: 
                flash("File too long, processing first 10000 lines.", "warning")
                break
            domain = line.strip().lower()[:MAX_STRING_LENGTH] 
            if domain and not domain.startswith("#"): 
                if DOMAIN_REGEX.match(domain): 
                    domains_to_process.append(domain)
                else:
                    print(f"Skipping invalid domain format in CSV: {domain}") 
        
        if not domains_to_process:
            flash("No valid domains found in the uploaded file.", "warning")
            return redirect(url_for('index'))
        
        temp_domains_file = os.path.join(STATUS_FILE_DIR, f"temp_domains_upload_{uuid.uuid4()}.txt")
        with open(temp_domains_file, 'w') as f:
            for domain in domains_to_process: f.write(domain + "\n")
        batch_run_id = str(uuid.uuid4())
        stdout_log_path = os.path.join(STATUS_FILE_DIR, f"{batch_run_id}_stdout.log")
        stderr_log_path = os.path.join(STATUS_FILE_DIR, f"{batch_run_id}_stderr.log")
        script_args = [sys.executable, DNS_CHECKER_SCRIPT_PATH, '--input-file', temp_domains_file, '--batch-run-id', batch_run_id, '--run-type-override', 'csv_import']
        with open(stdout_log_path, 'w') as stdout_file, open(stderr_log_path, 'w') as stderr_file:
            subprocess.Popen(script_args, stdout=stdout_file, stderr=stderr_file, text=True, bufsize=1)
        time.sleep(0.1)
        flash(f"CSV import of {len(domains_to_process)} domains started (Batch ID: {batch_run_id}). Progress updates will appear.", "info")
    except Exception as e:
        flash(f"Error processing CSV file: {e}", "danger")
        print(f"Exception during CSV upload: {e}")
        return redirect(url_for('index'))
    return redirect(url_for('index', _anchor='batch_progress_section'))

@app.route('/run_batch_whois', methods=['POST'])
def run_batch_whois():
    target_type = request.form.get('whois_target_type') 
    api_key = os.environ.get("WHOXY_API_KEY")
    if not api_key:
        return jsonify({"success": False, "message": "WHOXY_API_KEY not configured on the server."})

    script_args = ['--api-key', api_key]
    log_message = "WHOIS lookup"

    allowed_target_types = ['category', 'selected_ids', 'no_whois_yet', 'all_db_domains'] 
    if target_type not in allowed_target_types:
        return jsonify({"success": False, "message": "Invalid target type for WHOIS lookup."})

    if target_type == 'category':
        category = request.form.get('category_for_whois', '').strip()[:MAX_STRING_LENGTH]
        if not category:
            return jsonify({"success": False, "message": "No category selected for batch WHOIS."})
        script_args.extend(['--category', category])
        log_message = f"WHOIS lookup for category '{category}'"
    elif target_type == 'selected_ids':
        domain_ids_csv = request.form.get('globally_selected_ids_for_script')
        safe_ids = is_safe_id_list(domain_ids_csv) 
        if not safe_ids: 
            return jsonify({"success": False, "message": "No items were selected for WHOIS lookup."})
        script_args.extend(['--domain-ids', ",".join(map(str,safe_ids))])
        log_message = f"WHOIS lookup for {len(safe_ids)} selected domains"
    elif target_type == 'no_whois_yet':
        script_args.append('--no-whois-yet')
        log_message = "WHOIS lookup for domains with no record"
    elif target_type == 'all_db_domains': 
        script_args.append('--all-domains-in-db')
        log_message = "WHOIS lookup for ALL domains"
    
    return _run_script_and_get_batch_id(WHOIS_SCRIPT_PATH, script_args, log_message)

@app.route('/trigger_dns_check', methods=['POST'])
def trigger_dns_check():
    check_type = request.form.get('check_type')
    allowed_check_types = ['full_check', 'recheck_successful', 'recheck_category',
                           'checked_domains', 'new_domains_from_txt', 'single_domain']
    if check_type not in allowed_check_types:
        return jsonify({"success": False, "message": "Invalid DNS check type selected."})

    script_args = []
    log_message = "DNS Check"
    run_type_db = "unknown_trigger"

    record_types_form = request.form.getlist('record_types')
    dns_server = request.form.get('dns_server', '').strip()[:MAX_STRING_LENGTH]
    if record_types_form:
        script_args.extend(['--record-types'] + record_types_form)
    if dns_server:
        script_args.extend(['--dns-server', dns_server])

    if check_type == 'single_domain':
        domain_name_form = request.form.get('domain_name', '').strip()[:MAX_STRING_LENGTH]
        if not domain_name_form or not DOMAIN_REGEX.match(domain_name_form):
            return jsonify({"success": False, "message": "A valid domain name is required."})
        script_args.extend(['--domain', domain_name_form])
        log_message = f"DNS check for '{domain_name_form}'"
        run_type_db = "single_domain_check"
    
    elif check_type == 'full_check':
        input_file = request.form.get('input_file', DOMAINS_INPUT_FILE).strip()[:MAX_STRING_LENGTH]
        script_args.extend(['--input-file', input_file])
        log_message = f"full DNS check from '{input_file}'"
        run_type_db = "full_check"

    elif check_type == 'recheck_successful':
        script_args.append('--recheck-successful')
        log_message = "re-checking 'Successful' domains"
        run_type_db = "recheck_successful"

    elif check_type == 'recheck_category':
        category = request.form.get('category_for_recheck', '').strip()[:MAX_STRING_LENGTH]
        if not category:
            return jsonify({"success": False, "message": "Category is required."})
        script_args.extend(['--recheck-category', category])
        log_message = f"re-checking category '{category}'"
        run_type_db = f"recheck_category_{category.replace(' ', '_')}"

    elif check_type == 'checked_domains':
        selected_ids_csv = request.form.get('selected_dns_check_ids')
        safe_ids = is_safe_id_list(selected_ids_csv)
        if not safe_ids:
            return jsonify({"success": False, "message": "No domains were selected."})
        script_args.extend(['--domain-ids-from-ui', ",".join(map(str, safe_ids))])
        log_message = f"re-checking {len(safe_ids)} marked domains"
        run_type_db = "check_marked"

    elif check_type == 'new_domains_from_txt':
        script_args.append('--check-new-domains-from-file')
        input_file = request.form.get('input_file', DOMAINS_INPUT_FILE).strip()[:MAX_STRING_LENGTH]
        if input_file != DOMAINS_INPUT_FILE:
            script_args.extend(['--input-file', input_file])
        log_message = f"checking new domains from '{input_file}'"
        run_type_db = "check_new_domains_from_file"

    script_args.extend(['--run-type-override', run_type_db])
    
    return _run_script_and_get_batch_id(DNS_CHECKER_SCRIPT_PATH, script_args, log_message)

    if check_type == 'single_domain':
        domain_name_form = request.form.get('domain_name', '').strip()[:MAX_STRING_LENGTH]
        if not domain_name_form or not DOMAIN_REGEX.match(domain_name_form):
            return jsonify({"success": False, "message": "A valid domain name is required."})
        script_args.extend(['--domain', domain_name_form])
        log_message = f"DNS check for '{domain_name_form}'"
        run_type_db = "single_domain_check"
    elif check_type == 'full_check':
        input_file = request.form.get('input_file', DOMAINS_INPUT_FILE).strip()[:MAX_STRING_LENGTH]
        script_args.extend(['--input-file', input_file])
        log_message = f"full DNS check from '{input_file}'"
        run_type_db = "full_check"
    elif check_type == 'recheck_successful':
        script_args.append('--recheck-successful')
        log_message = "re-checking 'Successful' domains"
        run_type_db = "recheck_successful"
    elif check_type == 'recheck_category':
        category = request.form.get('category_for_recheck', '').strip()[:MAX_STRING_LENGTH]
        if not category:
            return jsonify({"success": False, "message": "Category is required."})
        script_args.extend(['--recheck-category', category])
        log_message = f"re-checking category '{category}'"
        run_type_db = f"recheck_category_{category.replace(' ', '_')}"
    elif check_type == 'checked_domains':
        selected_ids_csv = request.form.get('selected_dns_check_ids')
        safe_ids = is_safe_id_list(selected_ids_csv)
        if not safe_ids:
            return jsonify({"success": False, "message": "No domains were selected."})
        script_args.extend(['--domain-ids-from-ui', ",".join(map(str, safe_ids))])
        log_message = f"re-checking {len(safe_ids)} marked domains"
        run_type_db = "check_marked"
    elif check_type == 'new_domains_from_txt':
        script_args.append('--check-new-domains-from-file')
        input_file = request.form.get('input_file', DOMAINS_INPUT_FILE).strip()[:MAX_STRING_LENGTH]
        if input_file != DOMAINS_INPUT_FILE:
            script_args.extend(['--input-file', input_file])
        log_message = f"checking new domains from '{input_file}'"
        run_type_db = "check_new_domains_from_file"

    script_args.extend(['--run-type-override', run_type_db])
    return _run_script_and_get_batch_id(DNS_CHECKER_SCRIPT_PATH, script_args, log_message)

@app.route('/get_whois_data', methods=['GET'])
def get_whois_data():
    domain_name = request.args.get('domain', '').strip()[:MAX_STRING_LENGTH]
    if not domain_name or not DOMAIN_REGEX.match(domain_name): 
         return jsonify({"error": "Valid domain name parameter missing or invalid"}), 400
    conn = get_db(); cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM whois_records WHERE domain_name = ? ORDER BY lookup_timestamp DESC", (domain_name,))
        records = cursor.fetchall()
        return jsonify({"records": [dict(row) for row in records] if records else []})
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {e}"}), 500

@app.route('/export_csv', methods=['POST'])
def export_csv():
    export_mode = request.form.get('export_mode')
    if export_mode not in ['checked', 'filtered']:
        flash("Invalid export mode.", "danger"); return redirect(url_for('index'))

    selected_ids_csv_for_export = request.form.get('selected_ids') 

    search_term_from_session = session.get('filter_search_term', '')
    search_by_from_session = session.get('filter_search_by', 'domain_name')
    category_filter_from_session = session.get('filter_category_for_form', '') 
    multi_category_filter_from_session = session.get('filter_multi_category', [])
    whois_privacy_filter_from_session = session.get('filter_whois_privacy', '') 

    sort_by_from_session = session.get('filter_sort_by', 'timestamp')
    sort_order_from_session = session.get('filter_sort_order', 'desc')
    start_date_from_session = session.get('filter_start_date', '')
    end_date_from_session = session.get('filter_end_date', '')
    
    conn = get_db()
    cursor = conn.cursor()
    
    final_multi_category_for_query = multi_category_filter_from_session
    final_single_category_for_query = category_filter_from_session
    
    if export_mode == 'filtered' and category_filter_from_session:
        final_multi_category_for_query = None 
    elif export_mode == 'filtered' and not category_filter_from_session and multi_category_filter_from_session :
        final_single_category_for_query = '' 

    _, _, base_query_params, actual_db_col_sorted_key, actual_sort_order, _, \
    query_for_all_filtered_data, export_headers = \
        build_query_components(
            search_term=search_term_from_session,
            search_by_param=search_by_from_session,
            category_filter=final_single_category_for_query, 
            multi_category_filter=final_multi_category_for_query,
            sort_by_url_key=sort_by_from_session,
            sort_order=sort_order_from_session,
            page=1, per_page=-1, 
            start_date_str=start_date_from_session,
            end_date_str=end_date_from_session,
            whois_privacy_filter=whois_privacy_filter_from_session 
        )

    final_query_for_db = ""
    final_params_for_db = []

    actual_sql_sort_column = 'lr.timestamp' 
    if actual_db_col_sorted_key in VALID_SORT_COLUMNS_MAP:
        mapped = VALID_SORT_COLUMNS_MAP[actual_db_col_sorted_key]
        if '.' in mapped: actual_sql_sort_column = mapped
        else: actual_sql_sort_column = f"lr.{mapped}"

    if export_mode == 'checked':
        safe_ids_for_export = is_safe_id_list(selected_ids_csv_for_export)
        if safe_ids_for_export is False:
            flash("Invalid ID format in selection for export.", "danger"); return redirect(url_for('index'))
        if not safe_ids_for_export:
            flash("No domains selected for export.", "warning"); return redirect(url_for('index'))
        
        select_and_join_part_for_export = ( "SELECT lr.id, lr.timestamp, lr.domain_name, lr.nameservers_found, lr.raw_status, lr.details, lr.category, " "lr.a_records, lr.aaaa_records, lr.mx_records, lr.txt_records, lr.cname_record, lr.soa_record_details, " "lr.soa_serial_changed, lr.ns_consistent_with_self, latest_wr.whois_privacy_enabled " "FROM lookup_results lr " "LEFT JOIN (" "   SELECT domain_name, MAX(lookup_timestamp) as max_ts " "   FROM whois_records " "   GROUP BY domain_name" ") as latest_wr_ts ON lr.domain_name = latest_wr_ts.domain_name " "LEFT JOIN whois_records latest_wr ON lr.domain_name = latest_wr.domain_name AND latest_wr.lookup_timestamp = latest_wr_ts.max_ts " )
        placeholders = ','.join('?' * len(safe_ids_for_export))
        order_by_clause_str_for_checked = f"ORDER BY {actual_sql_sort_column} {actual_sort_order.upper()}" 
        final_query_for_db = f"{select_and_join_part_for_export} WHERE lr.id IN ({placeholders}) {order_by_clause_str_for_checked}"
        final_params_for_db = safe_ids_for_export
    elif export_mode == 'filtered':
        final_query_for_db = query_for_all_filtered_data 
        final_params_for_db = base_query_params 
    
    try:
        cursor.execute(final_query_for_db, final_params_for_db)
        results_for_csv = cursor.fetchall()
    except sqlite3.Error as e:
        flash(f"Database error during export: {e}", "danger")
        print(f"Export Query Error: {final_query_for_db} with params {final_params_for_db}")
        return redirect(url_for('index'))

    si = io.StringIO(); cw = csv.writer(si)
    cw.writerow(export_headers) 
    for row_proxy in results_for_csv: 
        row_values = []
        for col_name in export_headers:
            try:
                row_values.append(row_proxy[col_name])
            except IndexError: 
                print(f"Warning: Column '{col_name}' not found in export row. Appending None.")
                row_values.append(None) 
        cw.writerow(row_values)

    output = si.getvalue(); si.close()
    filename = f"dns_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename={filename}"})

@app.route('/stream_batch_progress')
def stream_batch_progress():
    batch_run_id_from_request = request.args.get('batch_run_id')
    try:
        if batch_run_id_from_request: uuid.UUID(batch_run_id_from_request)
    except ValueError:
        print(f"SSE: Invalid batch_run_id format received: {batch_run_id_from_request}")
        batch_run_id_from_request = None 

    def generate_progress():
        last_sent_data_str = ""
        if batch_run_id_from_request:
            specific_status_file = os.path.join(STATUS_FILE_DIR, f"status_{batch_run_id_from_request}.json")
            startup_grace_period_seconds = 10 
            grace_end_time = time.time() + startup_grace_period_seconds
            file_ever_existed = False
            while True:
                current_status_data_dict = {"batch_run_id": batch_run_id_from_request}
                file_exists_now = os.path.exists(specific_status_file)
                if file_exists_now:
                    file_ever_existed = True
                    try:
                        with open(specific_status_file, 'r') as sf: current_status_data_dict.update(json.load(sf))
                        if "batch_run_id" not in current_status_data_dict or not current_status_data_dict["batch_run_id"]:
                             current_status_data_dict["batch_run_id"] = batch_run_id_from_request
                    except (IOError, json.JSONDecodeError) as e:
                        current_status_data_dict["message"] = f"Error reading status file: {e}."; current_status_data_dict["status"] = "error_reading_status"
                else: 
                    if file_ever_existed: 
                        current_status_data_dict["message"] = f"Batch {batch_run_id_from_request} likely completed."; current_status_data_dict["status"] = "complete" 
                    elif time.time() > grace_end_time: 
                        current_status_data_dict["message"] = f"Status for {batch_run_id_from_request} not found. Check logs."; current_status_data_dict["status"] = "error_not_found" 
                    else: 
                        current_status_data_dict["message"] = f"Waiting for {batch_run_id_from_request} to start..."; current_status_data_dict["status"] = "pending"
                current_status_data_str = json.dumps(current_status_data_dict)
                if current_status_data_str != last_sent_data_str:
                    yield f"data: {current_status_data_str}\n\n"; last_sent_data_str = current_status_data_str
                if current_status_data_dict.get("status") in ["complete", "error_not_found", "error_reading_status", "error"] or current_status_data_dict.get("event") == "close":
                    final_event_data = {"message": "Batch ended.", "event": "close", "batch_run_id": batch_run_id_from_request, "final_status": current_status_data_dict.get("status")}
                    yield f"data: {json.dumps(final_event_data)}\n\n"; break
                time.sleep(2) 
        else: 
            yield f"data: {json.dumps({'message': 'No valid batch_run_id provided for progress streaming.', 'event': 'close', 'status': 'error_no_id'})}\n\n"
            
    return Response(stream_with_context(generate_progress()), mimetype='text/event-stream')

@app.route('/runs', methods=['GET'])
def runs():
    conn = get_db(); cursor = conn.cursor(); runs_data = []
    try:
        cursor.execute("SELECT run_id, run_timestamp, run_type, domains_processed, domains_changed_count FROM runs ORDER BY run_timestamp DESC")
        runs_data = cursor.fetchall()
    except sqlite3.Error as e: flash(f"Database error fetching runs: {e}", "danger")
    return render_template('run_history.html', runs=runs_data)

@app.route('/run_changes/<int:run_id>', methods=['GET'])
def run_changes(run_id):
    if run_id <= 0:
        flash("Invalid Run ID.", "danger")
        return redirect(url_for('runs'))
        
    conn = get_db(); cursor = conn.cursor(); run_details = None; changes_data = []
    try:
        cursor.execute("SELECT run_id, run_timestamp, run_type, domains_processed, domains_changed_count FROM runs WHERE run_id = ?", (run_id,))
        run_details = cursor.fetchone()
        if run_details:
            cursor.execute("SELECT domain_name, previous_category, new_category, change_timestamp FROM status_changes WHERE run_id = ? ORDER BY change_timestamp DESC", (run_id,))
            changes_data = cursor.fetchall()
        else: flash(f"Run with ID {run_id} not found.", "warning")
    except sqlite3.Error as e: flash(f"Database error fetching run changes: {e}", "danger")
    return render_template('run_changes.html', run_details=run_details, changes=changes_data)

if __name__ == '__main__':
    if not os.path.exists(STATUS_FILE_DIR):
        try: os.makedirs(STATUS_FILE_DIR); print(f"Created status directory: {STATUS_FILE_DIR}")
        except OSError as e: print(f"Error creating status directory {STATUS_FILE_DIR}: {e}. Exiting."); sys.exit(1)
    for f_name in os.listdir(STATUS_FILE_DIR): 
        if f_name.startswith(('status_', 'dns_check_', 'whois_')) or f_name.endswith(('_stdout.log', '_stderr.log')):
            try: os.remove(os.path.join(STATUS_FILE_DIR, f_name))
            except OSError as e: print(f"Warning: Could not remove old status/log file {f_name}: {e}")
    
    if not os.path.exists(DNS_CHECKER_SCRIPT_PATH): print(f"CRITICAL WARNING: DNS checker script '{DNS_CHECKER_SCRIPT_PATH}' not found.")
    if not os.path.exists(WHOIS_SCRIPT_PATH): print(f"CRITICAL WARNING: Whois script '{WHOIS_SCRIPT_PATH}' not found.")
    
    try:
        module_dir = os.path.dirname(os.path.abspath(__file__))
        if module_dir not in sys.path: sys.path.insert(0, module_dir)
        from dns_checker import init_db as init_main_db 
        print("Initializing database schema...")
        init_main_db()
        print("Database schema initialized.")
    except ImportError:
        print("CRITICAL ERROR: Could not import init_db from dns_checker.py."); sys.exit(1)
    except Exception as e: 
        print(f"CRITICAL WARNING: Error during init_db call: {e}")

    print("Starting Flask web server. Open http://127.0.0.1:5000 in your browser.")
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=True)
