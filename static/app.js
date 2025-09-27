// --- START OF FUNCTION DEFINITIONS ---
const CHECKED_ITEMS_STORAGE_KEY = 'dnsInventorySelectedItemsGlobal';
const COLUMN_VISIBILITY_STORAGE_KEY = 'dnsInventoryColumnVisibility';
const FILTER_COLLAPSE_STORAGE_KEY = 'dnsFilterSectionCollapsed';

const progressPopupOverlay = document.getElementById('progress-popup-overlay');
const progressPopupDisplay = document.getElementById('popup-batch-progress-display');
const progressPopupProgressBar = document.getElementById('popup-batch-progress-bar');
const progressPopupFill = document.getElementById('popup-batch-progress-fill');
const progressPopupSummary = document.getElementById('popup-batch-progress-summary');
const progressPopupDisconnectButton = document.getElementById('popup-disconnect-sse');
const progressPopupDetails = document.getElementById('popup-batch-progress-details');
const progressPopupTotalDomains = document.getElementById('popup-progress-total-domains');
const progressPopupCurrentDomain = document.getElementById('popup-progress-current-domain');
const progressPopupDomainsLeft = document.getElementById('popup-progress-domains-left');
const activeBatchIdPageDisplay = document.getElementById('active-batch-id-display');


function getSelectedItemsFromStorage() { return JSON.parse(sessionStorage.getItem(CHECKED_ITEMS_STORAGE_KEY) || '[]'); }
function setSelectedItemsInStorage(ids) { sessionStorage.setItem(CHECKED_ITEMS_STORAGE_KEY, JSON.stringify(ids)); }
function clearSelectedItemsStorage() { sessionStorage.removeItem(CHECKED_ITEMS_STORAGE_KEY); }

function getColumnVisibilityFromStorage() {
    const stored = localStorage.getItem(COLUMN_VISIBILITY_STORAGE_KEY);
    const defaultPrefs = {
        'col-select': true, 'col-id': true, 'col-timestamp': true, 'col-domain': true, 'col-ns': true,
        'col-a-aaaa': true, 'col-mx': true, 'col-other-recs': true, 'col-status': true,
        'col-details': true, 'col-category': true, 'col-privacy': true, 'col-actions': true,
        'col-ptr': false, 'col-dnssec': true, 'col-created': true, 'col-expiry': true, 'col-updated': true
    };
    const currentPrefs = stored ? JSON.parse(stored) : {};
    return {...defaultPrefs, ...currentPrefs};
}
function setColumnVisibilityInStorage(visibilityMap) { localStorage.setItem(COLUMN_VISIBILITY_STORAGE_KEY, JSON.stringify(visibilityMap));}

function applyColumnVisibility() {
    const visibilityMap = getColumnVisibilityFromStorage();
    const table = document.querySelector('.results-table table');
    if (!table) return;
    table.querySelectorAll('th[data-column-id], td[data-column-id]').forEach(cell => {
        const columnId = cell.dataset.columnId;
        const isVisible = visibilityMap.hasOwnProperty(columnId) ? visibilityMap[columnId] : true;
        cell.classList.toggle('hidden-column', !isVisible);
    });
}

function populateColumnSelector() {
    const dropdown = document.getElementById('column-selector-dropdown');
    const table = document.querySelector('.results-table table');
    if (!dropdown || !table) return;
    dropdown.innerHTML = '<strong>Show/Hide Columns:</strong><hr style="margin: 5px 0;">';
    const visibilityMap = getColumnVisibilityFromStorage();
    const headers = table.querySelectorAll('thead th[data-column-id]');

    headers.forEach(th => {
        const columnId = th.dataset.columnId;
        let columnText = th.innerText || th.textContent;
        const sortIcon = th.querySelector('.sort-icon');
        if (sortIcon) {
            columnText = columnText.replace(sortIcon.textContent, '');
        }
        columnText = columnText.trim();

        if (columnId === 'col-select' && columnText === "") {
            columnText = "Select";
        }

        if (columnId && columnText) {
            const isVisible = (visibilityMap.hasOwnProperty(columnId)) ? visibilityMap[columnId] : true;

            const label = document.createElement('label');
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.classList.add('column-toggle-cb');
            checkbox.dataset.columnId = columnId;
            checkbox.checked = isVisible;

            checkbox.addEventListener('change', function() {
                const currentVisibility = getColumnVisibilityFromStorage();
                currentVisibility[this.dataset.columnId] = this.checked;
                setColumnVisibilityInStorage(currentVisibility);
                applyColumnVisibility();
            });
            label.appendChild(checkbox);
            label.appendChild(document.createTextNode(` ${columnText}`));
            dropdown.appendChild(label);
        }
    });
}

function updateSelectedCount() {
    const count = getSelectedItemsFromStorage().length;
    const whoisDisp = document.getElementById('selected-whois-count-display');
    const dnsDisp = document.getElementById('selected-dns-check-count-display');
    if (whoisDisp) whoisDisp.textContent = `(${count} selected)`;
    if (dnsDisp) dnsDisp.textContent = `(${count} selected)`;

    const checkTypeModalEl = document.getElementById('check_type_modal');
    if (checkTypeModalEl && dnsDisp) {
        dnsDisp.style.display = (checkTypeModalEl.value === 'checked_domains') ? 'inline' : 'none';
    }
}

function syncSelectAllCheckbox() {
    const saCb = document.getElementById('select-all-checkbox');
    if (!saCb) return;
    const visCbs = Array.from(document.querySelectorAll('.row-checkbox'));
    if (visCbs.length === 0) { saCb.checked = false; saCb.indeterminate = false; return; }
    const stored = getSelectedItemsFromStorage();

    const actuallyVisibleRowsCheckboxes = visCbs.filter(cb => {
        const row = cb.closest('tr');
        return row && row.style.display !== 'none'; // Check actual display style
    });

    if (actuallyVisibleRowsCheckboxes.length === 0) {
        saCb.checked = false;
        saCb.indeterminate = false;
        return;
    }
    const numActuallyVisibleAndChecked = actuallyVisibleRowsCheckboxes.filter(cb => stored.includes(cb.value)).length;

    if (numActuallyVisibleAndChecked === 0) {
        saCb.checked = false; saCb.indeterminate = false;
    } else if (numActuallyVisibleAndChecked === actuallyVisibleRowsCheckboxes.length) {
        saCb.checked = true; saCb.indeterminate = false;
    } else {
        saCb.checked = false; saCb.indeterminate = true;
    }
}

function toggleDnsCheckInputsModal() {
    const checkTypeEl = document.getElementById('check_type_modal');
    if (!checkTypeEl) return;
    const checkType = checkTypeEl.value;

    const inputFileGroup = document.getElementById('input_file_group_modal');
    const categoryGroup = document.getElementById('category_group_modal');
    const singleDomainGroup = document.getElementById('single_domain_group_modal');
    const dnsCheckCountDisplay = document.getElementById('selected-dns-check-count-display');
    const diffDomainsCountDisplay = document.getElementById('diff-domains-count-display');


    if(inputFileGroup) inputFileGroup.style.display = 'none';
    if(categoryGroup) categoryGroup.style.display = 'none';
    if(singleDomainGroup) singleDomainGroup.style.display = 'none';
    if(dnsCheckCountDisplay) dnsCheckCountDisplay.style.display = 'none';
    if(diffDomainsCountDisplay) diffDomainsCountDisplay.style.display = 'none';


    if (checkType === 'full_check' || checkType === 'new_domains_from_txt') {
        if(inputFileGroup) inputFileGroup.style.display = 'block';
    }

    if (checkType === 'recheck_category') {
        if(categoryGroup) categoryGroup.style.display = 'block';
    } else if (checkType === 'single_domain') {
        if(singleDomainGroup) singleDomainGroup.style.display = 'block';
    } else if (checkType === 'checked_domains') {
        if(dnsCheckCountDisplay) dnsCheckCountDisplay.style.display = 'inline';
        updateSelectedCount();
    }

    if (checkType === 'new_domains_from_txt') {
        if(diffDomainsCountDisplay) {
            diffDomainsCountDisplay.textContent = 'Calculating...';
            diffDomainsCountDisplay.style.display = 'inline';
            fetch(AppConfig.url_for_new_domains_count)
                .then(response => response.json())
                .then(data => {
                    if(diffDomainsCountDisplay) {
                        if (data.success) {
                            diffDomainsCountDisplay.textContent = `(${data.count} new domains)`;
                        } else {
                            diffDomainsCountDisplay.textContent = '(Error fetching count)';
                        }
                    }
                })
                .catch(error => {
                   if(diffDomainsCountDisplay) diffDomainsCountDisplay.textContent = '(Error fetching count)';
                   console.error("Error fetching new domains count:", error);
                });
        }
    }
}
function toggleParseWhoisInputsModal() {
    const targetTypeEl = document.getElementById('parse_target_type_modal');
    if(!targetTypeEl) return;
    const targetType = targetTypeEl.value;

    const categoryGroup = document.getElementById('category_for_parse_group_modal');
    if (categoryGroup) {
        categoryGroup.style.display = (targetType === 'category') ? 'block' : 'none';
    }
}
function handleDnsCheckTypeChange() {
    toggleDnsCheckInputsModal();
}

function toggleWhoisBatchInputsModal() {
    const targetTypeEl = document.getElementById('whois_target_type_modal');
    if(!targetTypeEl) return;
    const targetType = targetTypeEl.value;

    const categoryGroup = document.getElementById('category_for_whois_group_modal');
    const selectedCountDisplay = document.getElementById('selected-whois-count-display');
    const noWhoisYetCountDisplay = document.getElementById('no-whois-yet-count-display');
    const allDbDomainsCountDisplay = document.getElementById('all-db-domains-count-display');


    if (categoryGroup) categoryGroup.style.display = 'none';
    if (selectedCountDisplay) selectedCountDisplay.style.display = 'none';
    if (noWhoisYetCountDisplay) noWhoisYetCountDisplay.style.display = 'none';
    if (allDbDomainsCountDisplay) allDbDomainsCountDisplay.style.display = 'none';


    if (targetType === 'category') {
        if (categoryGroup) categoryGroup.style.display = 'block';
    } else if (targetType === 'selected_ids') {
        if (selectedCountDisplay) selectedCountDisplay.style.display = 'inline';
        updateSelectedCount();
    } else if (targetType === 'no_whois_yet') {
         if (noWhoisYetCountDisplay) {
            noWhoisYetCountDisplay.textContent = 'Calculating...';
            noWhoisYetCountDisplay.style.display = 'inline';
            fetch(AppConfig.url_for_no_whois_count)
                .then(response => response.json())
                .then(data => {
                    if(noWhoisYetCountDisplay) {
                        if (data.success) { noWhoisYetCountDisplay.textContent = `(${data.count} domains without WHOIS)`;}
                        else { noWhoisYetCountDisplay.textContent = '(Error)'; }
                    }
                })
                .catch(error => { if(noWhoisYetCountDisplay) noWhoisYetCountDisplay.textContent = '(Error)'; console.error("Err no WHOIS count:", error); });
        }
    } else if (targetType === 'all_db_domains') {
        if (allDbDomainsCountDisplay) {
            allDbDomainsCountDisplay.textContent = `(${AppConfig.total_unique_domains} total domains in DB)`;
            allDbDomainsCountDisplay.style.display = 'inline';
        }
    }
}

function clearFiltersAndSelections() {
    clearSelectedItemsStorage();
    window.location.href = `${AppConfig.url_for_index}?clear_all_filters=true`;
}

let eventSource = null;
function startSseMonitoring(batchRunId) {
    if (progressPopupOverlay) progressPopupOverlay.style.display = 'flex';
    if (activeBatchIdPageDisplay) {
         activeBatchIdPageDisplay.textContent = `Monitoring Batch ID: ${batchRunId}`;
         activeBatchIdPageDisplay.style.display = 'block';
    }

    if (eventSource) eventSource.close();
    const url = `/stream_batch_progress?batch_run_id=${batchRunId}`;
    eventSource = new EventSource(url);

    if(progressPopupDisplay) progressPopupDisplay.textContent = 'Connecting...';
    if(progressPopupDetails) progressPopupDetails.style.display = 'none';
    if(progressPopupProgressBar) progressPopupProgressBar.style.display = 'none';
    if(progressPopupFill) { progressPopupFill.style.width = '0%'; progressPopupFill.textContent = '0%'; }
    if(progressPopupSummary) progressPopupSummary.textContent = '';
    if(progressPopupDisconnectButton) progressPopupDisconnectButton.style.display = 'block';

    eventSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        if(progressPopupDisplay) progressPopupDisplay.innerHTML = `<strong>Batch ID:</strong> ${data.batch_run_id || 'N/A'}<br>${data.message || 'No message'}`;

        if ((data.status === 'processing' || data.status === 'running') && data.total_domains !== undefined && data.processed_domains !== undefined) {
            if(progressPopupDetails) progressPopupDetails.style.display = 'block';
            if(progressPopupTotalDomains) progressPopupTotalDomains.textContent = data.total_domains;
            if(progressPopupCurrentDomain) progressPopupCurrentDomain.textContent = data.current_domain || 'N/A';
            if(progressPopupDomainsLeft) progressPopupDomainsLeft.textContent = data.total_domains - data.processed_domains;
            const progress = (data.total_domains > 0 ? (data.processed_domains / data.total_domains) * 100 : 0);
            if(progressPopupProgressBar) progressPopupProgressBar.style.display = 'block';
            if(progressPopupFill) { progressPopupFill.style.width = `${Math.min(100, progress)}%`; progressPopupFill.textContent = `${Math.round(Math.min(100,progress))}%`; }
            if(progressPopupSummary) progressPopupSummary.textContent = `Processed ${data.processed_domains} of ${data.total_domains} domains.`;
        } else if (data.status === 'starting' && data.total_domains !== undefined) {
             if(progressPopupDetails) progressPopupDetails.style.display = 'block';
             if(progressPopupTotalDomains) progressPopupTotalDomains.textContent = data.total_domains;
             if(progressPopupCurrentDomain) progressPopupCurrentDomain.textContent = data.current_domain || 'N/A';
             if(progressPopupDomainsLeft) progressPopupDomainsLeft.textContent = data.total_domains;
             if(progressPopupProgressBar) progressPopupProgressBar.style.display = 'block';
             if(progressPopupFill) { progressPopupFill.style.width = `0%`; progressPopupFill.textContent = `0%`; }
             if(progressPopupSummary) progressPopupSummary.textContent = `Starting... 0 of ${data.total_domains} domains processed.`;
        } else {
            if(progressPopupProgressBar) progressPopupProgressBar.style.display = 'none';
            if(progressPopupDetails) progressPopupDetails.style.display = 'none';
        }

        if (data.status === 'complete' || data.event === 'close' || data.status === 'error_not_found' || data.status === 'error' || data.status === "error_reading_status") {
            if (eventSource) eventSource.close(); eventSource = null;
            if(progressPopupDisplay) progressPopupDisplay.textContent = data.message || 'Batch process finished.';
            if(progressPopupSummary) progressPopupSummary.textContent = `Final Status: ${data.final_status || data.status || 'Complete'}`;
            if(progressPopupDisconnectButton) progressPopupDisconnectButton.style.display = 'none';
            if(activeBatchIdPageDisplay) activeBatchIdPageDisplay.style.display = 'none';
            localStorage.removeItem('active_batch_run_id');
        }
    };
    eventSource.onerror = function(err) {
        if(progressPopupDisplay) progressPopupDisplay.innerHTML = `<span style="color:red;">Error connecting to batch progress.</span>`;
        if(eventSource) eventSource.close(); eventSource = null;
        if(progressPopupDisconnectButton) progressPopupDisconnectButton.style.display = 'none';
        if(activeBatchIdPageDisplay) activeBatchIdPageDisplay.style.display = 'none';
        localStorage.removeItem('active_batch_run_id');
    };
}

function setupCollapsibleSection(headerElement, contentElement, storageKey, defaultCollapsed = false) {
    if (!headerElement || !contentElement) { return; }
    const toggleIcon = headerElement.querySelector('.toggle-icon');
    if (!toggleIcon) { return; }
    let isCollapsed = localStorage.getItem(storageKey) === 'true';
    if (localStorage.getItem(storageKey) === null) { isCollapsed = defaultCollapsed; }

    function applyCollapseState(collapsed) {
        contentElement.classList.toggle('hidden', collapsed);
        toggleIcon.textContent = collapsed ? '[+]' : '[–]';
    }
    applyCollapseState(isCollapsed);
    headerElement.addEventListener('click', () => {
        const currentlyCollapsed = contentElement.classList.contains('hidden');
        applyCollapseState(!currentlyCollapsed);
        localStorage.setItem(storageKey, !currentlyCollapsed);
    });
}

// --- END OF FUNCTION DEFINITIONS ---

document.addEventListener('DOMContentLoaded', function() {
    // --- SETUP AND INITIALIZATION (Define variables first) ---
    const modalOpeners = {
        'open-dns-check-modal': 'dnsCheckModal', 'open-whois-batch-modal': 'whoisBatchModal',
        'open-export-modal': 'exportModal', 'open-add-domain-modal': 'addDomainModal',
        'open-csv-upload-modal': 'csvUploadModal', 'open-bulk-categorize-modal': 'bulkCategorizeModal',
        'open-bulk-delete-modal': 'bulkDeleteModal',
        'open-parse-whois-modal': 'parseWhoisModal'
    };

    // This function handles forms that trigger a background job
    function handleAsyncFormSubmit(form, event) {
        event.preventDefault();
        const formData = new FormData(form);
        const submitButton = form.querySelector('button[type="submit"]');
        if (!submitButton) {
            console.error("Form does not have a submit button to disable.", form);
            return;
        }
        const originalButtonText = submitButton.textContent;
        submitButton.disabled = true;
        submitButton.textContent = 'Starting...';

        fetch(form.action, {
            method: 'POST',
            body: formData,
        })
        .then(response => response.json())
        .then(data => {
            if (data.success && data.batch_run_id) {
                localStorage.setItem('active_batch_run_id', data.batch_run_id);
                startSseMonitoring(data.batch_run_id);
                const modal = form.closest('.modal');
                if (modal) modal.style.display = 'none';
            } else {
                alert(`Error: ${data.message || 'An unknown error occurred.'}`);
            }
        })
        .catch(error => {
            console.error('Form submission error:', error);
            alert('An unexpected network error occurred. Please try again.');
        })
        .finally(() => {
            submitButton.disabled = false;
            submitButton.textContent = originalButtonText;
        });
    }

            const formEventHandlers = {
        // --- Async Forms (These return JSON and trigger the progress popup) ---
        'dns-check-form-modal': handleAsyncFormSubmit,
        'whois-batch-form-modal': handleAsyncFormSubmit,
        'parse-whois-form-modal': handleAsyncFormSubmit,

        // --- Sync Forms (These cause a full page reload) ---
        'add-domain-form-modal': function(form) { form.submit(); },
        'edit-domain-form-modal': function(form) { form.submit(); },
        'csv-upload-form-modal': function(form) { form.submit(); },
        
        'export-form-modal': function(form, event) {
            if (form.elements['export_mode'].value === 'checked') {
                form.elements['selected_ids'].value = getSelectedItemsFromStorage().join(',');
            } else {
                form.elements['selected_ids'].value = "";
            }
            form.submit();
        },
        'bulk-categorize-form-modal': function(form, event) {
             if (form.elements['target_mode'].value === 'selected_ids'){
                const ids = getSelectedItemsFromStorage();
                if (ids.length === 0) {
                    alert("Please select domains from the table first.");
                    return; 
                }
                form.elements['selected_ids'].value = ids.join(',');
             }
             form.submit();
        },
        'bulk-delete-form-modal': function(form, event) {
            if (form.elements['target_mode'].value === 'selected_ids'){
                const ids = getSelectedItemsFromStorage();
                if (ids.length === 0) {
                    alert("Please select domains from the table first.");
                    return;
                }
                form.elements['selected_ids'].value = ids.join(',');
             }
             form.submit();
        }
    };
 

    // --- UI INITIALIZATION ---
    populateColumnSelector();
    applyColumnVisibility();
    
    // This is the source of truth for checkbox state on page load.
    const storedSelections = getSelectedItemsFromStorage();
    
    document.querySelectorAll('.row-checkbox').forEach(cb => {
        // Check if the current checkbox's ID is in the stored array.
        if (storedSelections.includes(cb.value)) {
            cb.checked = true;
        }
    });
    
    updateSelectedCount();
    syncSelectAllCheckbox();

    // --- EVENT LISTENERS ---

    // Dropdown change listeners
    const dnsCheckTypeSelect = document.getElementById('check_type_modal');
    if (dnsCheckTypeSelect) { dnsCheckTypeSelect.addEventListener('change', handleDnsCheckTypeChange); toggleDnsCheckInputsModal(); }

    const whoisTargetTypeSelect = document.getElementById('whois_target_type_modal');
    if (whoisTargetTypeSelect) { whoisTargetTypeSelect.addEventListener('change', toggleWhoisBatchInputsModal); toggleWhoisBatchInputsModal(); }

    const parseTargetTypeSelect = document.getElementById('parse_target_type_modal');
    if(parseTargetTypeSelect) { parseTargetTypeSelect.addEventListener('change', toggleParseWhoisInputsModal); toggleParseWhoisInputsModal(); }

    // Column toggler
    const toggleBtn = document.getElementById('toggle-columns-btn');
    const columnDropdown = document.getElementById('column-selector-dropdown');
    if (toggleBtn && columnDropdown) {
        toggleBtn.addEventListener('click', function(event) { event.stopPropagation(); columnDropdown.classList.toggle('show'); });
        document.addEventListener('click', function(event) { if (columnDropdown.classList.contains('show') && !columnDropdown.contains(event.target) && event.target !== toggleBtn && !toggleBtn.contains(event.target) ) { columnDropdown.classList.remove('show'); } });
    }

    // Collapsible filter section
    setupCollapsibleSection(document.getElementById('filter-section-header'), document.getElementById('filter-content-wrapper'), FILTER_COLLAPSE_STORAGE_KEY, false);

    // Progress pop-up buttons
    const progressPopupCloseBtn = document.getElementById('progress-popup-close');
    if(progressPopupCloseBtn && progressPopupOverlay) { progressPopupCloseBtn.addEventListener('click', () => { progressPopupOverlay.style.display = 'none'; if (eventSource) { eventSource.close(); eventSource = null; if(activeBatchIdPageDisplay) activeBatchIdPageDisplay.style.display = 'none'; localStorage.removeItem('active_batch_run_id'); if(progressPopupDisconnectButton) progressPopupDisconnectButton.style.display = 'none'; } }); }
    const disconnectSseBtnPopup = document.getElementById('popup-disconnect-sse');
    if(disconnectSseBtnPopup) { disconnectSseBtnPopup.addEventListener('click', () => { if(eventSource) { eventSource.close();eventSource=null; if(progressPopupDisplay) progressPopupDisplay.textContent = 'Batch progress monitoring disconnected by user.'; if(progressPopupProgressBar) progressPopupProgressBar.style.display = 'none'; if(progressPopupDetails) progressPopupDetails.style.display = 'none'; if(progressPopupSummary) progressPopupSummary.textContent = ''; disconnectSseBtnPopup.style.display = 'none'; if(activeBatchIdPageDisplay) activeBatchIdPageDisplay.style.display = 'none'; localStorage.removeItem('active_batch_run_id'); setTimeout(() => { if (progressPopupOverlay) progressPopupOverlay.style.display = 'none'; }, 2000); } }); }

    // WHOIS button in table
    const whoisModalEl = document.getElementById("whoisModal");
    document.querySelectorAll('.whois-button').forEach(btn => {
        btn.addEventListener('click', function() {
            const domain = this.dataset.domain;
            const whoisDomainNameEl = document.getElementById('whoisDomainName');
            if (whoisDomainNameEl) whoisDomainNameEl.textContent = domain.toLowerCase();
            const container = document.getElementById('whoisDataContainer');
            if(container) container.innerHTML = '<p>Loading WHOIS data...</p>';
            const whoisErrorEl = document.getElementById('whoisError');
            if(whoisErrorEl) whoisErrorEl.style.display = 'none';
            if(whoisModalEl) whoisModalEl.style.display = "block";
            fetch(`/get_whois_data?domain=${domain}`).then(res => res.json()).then(data => { if (data.error) { if(whoisErrorEl) {whoisErrorEl.textContent = `Error: ${data.error}`; whoisErrorEl.style.display = 'block';} if(container) container.innerHTML = ''; } else if (data.records && data.records.length > 0) { let allRecordsHtml = ''; data.records.forEach((record) => { allRecordsHtml += `<button class="whois-accordion-button">`; allRecordsHtml += `Record from: ${record.lookup_timestamp || 'N/A'} (Registrar: ${record.whois_server || record.registrar_name || 'N/A'})`; allRecordsHtml += `</button>`; allRecordsHtml += `<div class="whois-accordion-panel"><ul>`; const orderedFields = ['api_status', 'api_status_reason', 'domain_registered', 'created_date_iso', 'updated_date_iso', 'expiry_date_iso', 'registrar_name', 'registrar_iana_id', 'registrar_url', 'registrar_email', 'registrar_phone', 'name_servers', 'domain_status', 'domain_owner', 'whois_server', 'whois_privacy_enabled']; const contactFieldsPrefixes = ['registrant_contact_', 'administrative_contact_', 'technical_contact_']; for (const field of orderedFields) { if (record[field] !== undefined && record[field] !== null && record[field] !== 'N/A' && record[field] !== '') { let v = record[field]; if (field === 'whois_privacy_enabled') { v = (v === 1 || v === '1' || String(v).toLowerCase() === 'true') ? 'Yes' : 'No'; } else if (typeof v === 'string' && (v.startsWith('[')||v.startsWith('{'))) { try { v = JSON.parse(v); if (Array.isArray(v)) v = v.join(', '); else if (typeof v === 'object') v = JSON.stringify(v,null,2); } catch(e){} } allRecordsHtml += `<li><strong>${field.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase())}:</strong> ${v}</li>`;}} contactFieldsPrefixes.forEach(p => { let seg = ''; for (const k in record) { if (k.startsWith(p) && record[k] !== undefined && record[k] !== null && record[k] !== 'N/A' && record[k] !== '') { seg += `<li><strong>${k.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase())}:</strong> ${record[k]}</li>`;}} if (seg) { allRecordsHtml += `</ul><h4>${p.replace('_',' ').replace('contact ','Contact').replace(/\b\w/g,c=>c.toUpperCase())}:</h4><ul>` + seg;}}); if (record.raw_whois_text && record.raw_whois_text !== 'N/A') { allRecordsHtml += `</ul><h4>Raw WHOIS:</h4><pre>${record.raw_whois_text}</pre><ul>`; } if (record.formatted_whois_text && record.formatted_whois_text !== 'N/A' && record.formatted_whois_text !== record.raw_whois_text) { allRecordsHtml += `</ul><h4>Formatted WHOIS:</h4><pre>${record.formatted_whois_text}</pre><ul>`;} allRecordsHtml += '</ul></div>'; }); if(container) container.innerHTML = allRecordsHtml; document.querySelectorAll('#whoisDataContainer .whois-accordion-button').forEach(accBtn => { accBtn.addEventListener('click', function() { this.classList.toggle('active'); const panel = this.nextElementSibling; if(panel) panel.style.display = (panel.style.display === "block" ? "none" : "block"); }); }); const firstAccBtn = container?.querySelector('.whois-accordion-button'); if(firstAccBtn) firstAccBtn.click(); } else { if(container) container.innerHTML = '<p>No WHOIS records found for this domain.</p>';} }).catch(err => { console.error('WHOIS fetch error:', err); if(whoisErrorEl){whoisErrorEl.textContent = `Failed to fetch: ${err}`; whoisErrorEl.style.display = 'block';} if(container) container.innerHTML = ''; });
        });
    });

    // Modal opening buttons
    for (const openerId in modalOpeners) {
        const openerButton = document.getElementById(openerId);
        if (openerButton) {
            openerButton.addEventListener('click', function() {
                const modalId = modalOpeners[openerId];
                const modalElement = document.getElementById(modalId);
                if (modalElement) modalElement.style.display = 'block';

                const selectedIds = getSelectedItemsFromStorage();
                const selectedIdsCsv = selectedIds.join(',');

                if (modalId === 'dnsCheckModal') {
                    const hiddenInput = document.getElementById('selected_dns_check_ids');
                    if (hiddenInput) hiddenInput.value = selectedIdsCsv;
                    toggleDnsCheckInputsModal();
                    updateSelectedCount();
                }
                if (modalId === 'whoisBatchModal') {
                    const hiddenInput = document.getElementById('globally_selected_ids_for_script');
                    if (hiddenInput) hiddenInput.value = selectedIdsCsv;
                    toggleWhoisBatchInputsModal();
                    updateSelectedCount();
                }
                if (modalId === 'parseWhoisModal') {
                    const hiddenInput = document.getElementById('globally_selected_ids_for_parse_script');
                    if (hiddenInput) hiddenInput.value = selectedIdsCsv;
                    toggleParseWhoisInputsModal();
                }
                if (modalId === 'bulkCategorizeModal' || modalId === 'bulkDeleteModal') {
                    const hiddenInput = modalElement.querySelector('input[name="selected_ids"]');
                    if (hiddenInput) hiddenInput.value = selectedIdsCsv;
                    if (modalId === 'bulkDeleteModal') {
                        document.getElementById('bulk-delete-count').textContent = selectedIds.length;
                    }
                }
            });
        }
    }

    // Individual row buttons and modal closing
    document.querySelectorAll('.edit-domain-button').forEach(button => { button.addEventListener('click', function() { const entryId = this.dataset.entryId; const domainName = this.dataset.domainName; const editEntryIdEl=document.getElementById('edit_entry_id'); const editDomainNameEl=document.getElementById('edit_domain_name'); const editModalEl=document.getElementById('editDomainModal'); if(editEntryIdEl) editEntryIdEl.value = entryId; if(editDomainNameEl) editDomainNameEl.value = domainName; if(editModalEl) editModalEl.style.display = 'block'; }); });
    document.querySelectorAll('.close-button').forEach(btn => { btn.onclick = function() { const modalEl = document.getElementById(this.dataset.modal); if(modalEl) modalEl.style.display = "none"; }});
    window.onclick = (event) => { document.querySelectorAll('.modal').forEach(m => { if (event.target == m) m.style.display = "none"; }); };

    // Table header sorting
    document.querySelectorAll('th[data-sort-by]').forEach(th => {
        th.addEventListener('click', function(event) {
            event.preventDefault();
            const sortBy = this.dataset.sortBy;
            const csb = AppConfig.current_sorting_by;
            const cso = AppConfig.current_sorting_order;
            let nso = (sortBy === csb && cso === 'asc' ? 'desc' : 'asc');
            const form = document.createElement('form'); form.method = 'POST'; form.action = AppConfig.url_for_index; form.style.display = 'none';
            function addHiddenInput(name, value) { const input = document.createElement('input'); input.type = 'hidden'; input.name = name; input.value = value; form.appendChild(input); }
            addHiddenInput('search_term', document.getElementById('search_term').value);
            addHiddenInput('search_by', document.getElementById('search_by').value);
            addHiddenInput('start_date', document.getElementById('start_date').value);
            addHiddenInput('end_date', document.getElementById('end_date').value);
            addHiddenInput('whois_privacy_filter', document.getElementById('whois_privacy_filter').value);
            addHiddenInput('per_page', document.getElementById('per_page').value);
            addHiddenInput('created_date_filter', document.getElementById('created_date_filter').value);
            addHiddenInput('expiry_date_filter', document.getElementById('expiry_date_filter').value);
            addHiddenInput('updated_date_filter', document.getElementById('updated_date_filter').value);
            document.querySelectorAll('#multi_category_filter option:checked').forEach(opt => { addHiddenInput('multi_category_filter', opt.value); });
            addHiddenInput('sort_by', sortBy);
            addHiddenInput('sort_order', nso);
            addHiddenInput('checked_ids_for_sort', getSelectedItemsFromStorage().join(','));
            document.body.appendChild(form); form.submit();
        });
    });

    // Checkbox logic
    const saCb = document.getElementById('select-all-checkbox');
    if(saCb) {
        saCb.addEventListener('click', function(event) {
            event.stopPropagation();
        });
        saCb.addEventListener('change', function() {
            let ids = getSelectedItemsFromStorage();
            document.querySelectorAll('.row-checkbox').forEach(cb => {
                const row = cb.closest('tr');
                if (row && !row.classList.contains('hidden-column') && row.style.display !== 'none') {
                    cb.checked = saCb.checked;
                    if(saCb.checked && !ids.includes(cb.value)) {
                        ids.push(cb.value);
                    } else if(!saCb.checked) {
                        ids = ids.filter(id => id !== cb.value);
                    }
                }
            });
            setSelectedItemsInStorage(ids);
            updateSelectedCount();
            syncSelectAllCheckbox();
        });
    }
    document.querySelectorAll('.row-checkbox').forEach(cb => { cb.addEventListener('change', function() { let ids = getSelectedItemsFromStorage(); if(this.checked && !ids.includes(this.value)) { ids.push(this.value); } else if(!this.checked) { ids = ids.filter(id => id !== this.value); } setSelectedItemsInStorage(ids); updateSelectedCount(); syncSelectAllCheckbox(); }); });

    // Form submissions
    const filterForm = document.getElementById('filter-form');
    if (filterForm) {
        filterForm.addEventListener('submit', function(e) {
            // Add checked IDs to the form before it's submitted via GET
            const hiddenInput = document.createElement('input');
            hiddenInput.type = 'hidden';
            hiddenInput.name = 'checked_ids_for_sort';
            hiddenInput.value = getSelectedItemsFromStorage().join(',');
            this.appendChild(hiddenInput);
        });
    }

    for (const formId in formEventHandlers) {
        const formEl = document.getElementById(formId);
        if (formEl) {
            formEl.addEventListener('submit', function(event) {
                event.preventDefault(); // Always prevent the default submission
                const handler = formEventHandlers[formId];
                if (handler) {
                    handler(this, event); // Let the specific handler do everything
                }
            });
        }
    }

    // JavaScript for stats
    document.querySelectorAll('.expiring-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const period = this.dataset.period;
            const modal = document.getElementById('expiringDomainsModal');
            const titleEl = document.getElementById('expiringModalTitle');
            const containerEl = document.getElementById('expiringDomainsContainer');
            const exportBtn = document.getElementById('expiring-export-btn');

            titleEl.textContent = `Domains Expiring ${this.textContent.split('(')[0].trim()}`;
            containerEl.innerHTML = '<p>Loading...</p>';
            exportBtn.href = `/expiring_domains?period=${period}&export=true`;
            modal.style.display = 'block';

            fetch(`/expiring_domains?period=${period}`)
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        containerEl.innerHTML = `<p style="color:red;">Error: ${data.error}</p>`;
                        return;
                    }
                    if (data.length === 0) {
                        containerEl.innerHTML = '<p>No domains found for this period.</p>';
                        return;
                    }
                    let tableHtml = '<table class="modal-table"><thead><tr><th>Domain</th><th>Expiry Date</th><th>Category</th></tr></thead><tbody>';
                    data.forEach(domain => {
                        tableHtml += `<tr><td>${domain.domain_name}</td><td>${domain.expiry_date_from_parse}</td><td>${domain.category || 'N/A'}</td></tr>`;
                    });
                    tableHtml += '</tbody></table>';
                    containerEl.innerHTML = tableHtml;
                })
                .catch(err => {
                    containerEl.innerHTML = `<p style="color:red;">Failed to fetch data.</p>`;
                    console.error(err);
                });
        });
    });
	        // --- Details Modal Logic ---
    const detailsModal = document.getElementById('detailsModal');
    const detailsModalTitle = document.getElementById('detailsModalTitle');
    const detailsModalContent = document.getElementById('detailsModalContent');

    // Helper function to safely parse JSON from data attributes
    function safeJsonParse(str, defaultVal = null) {
        if (!str || str === 'null' || str.trim() === '') {
            return defaultVal;
        }
        try {
            return JSON.parse(str);
        } catch (e) {
            console.error("JSON parsing error for string:", str, e);
            return defaultVal;
        }
    }

    document.querySelectorAll('.details-button').forEach(button => {
        button.addEventListener('click', function() {
            const domainName = this.dataset.domainName;
            const modalType = this.dataset.modalType;
            const detailsContainer = this.nextElementSibling; // The .hidden-details div
            
            let title = "Details";
            let contentHtml = '<dl class="details-list">';

            if (detailsContainer) {
                const dataType = detailsContainer.dataset.type;

                if (dataType === 'aaaa-data') {
                    title = `A/AAAA Records for ${domainName}`;
                    const aRecs = safeJsonParse(detailsContainer.dataset.a, []);
                    const aaaaRecs = safeJsonParse(detailsContainer.dataset.aaaa, []);
                    if (aRecs.length > 0) contentHtml += `<dt>A Records</dt><dd>${aRecs.join(', ')}</dd>`;
                    if (aaaaRecs.length > 0) contentHtml += `<dt>AAAA Records</dt><dd>${aaaaRecs.join(', ')}</dd>`;
                } 
                else if (dataType === 'ptr-data') {
                    title = `PTR Records for ${domainName}`;
                    const ptrData = safeJsonParse(detailsContainer.dataset.ptr, {});
                    for (const ip in ptrData) {
                        contentHtml += `<dt>${ip}</dt><dd>${Array.isArray(ptrData[ip]) ? ptrData[ip].join(', ') : ptrData[ip]}</dd>`;
                    }
                }
                else if (dataType === 'mx-data') {
                    title = `MX Records for ${domainName}`;
                    const mxData = safeJsonParse(detailsContainer.dataset.mx, []);
                    mxData.forEach(mx => {
                        contentHtml += `<dt>Pref ${mx.preference}</dt><dd>${mx.exchange}</dd>`;
                    });
                }
                else if (dataType === 'other-data') {
                    title = `Other Records for ${domainName}`;
                    const cname = safeJsonParse(detailsContainer.dataset.cname);
                    const txt = safeJsonParse(detailsContainer.dataset.txt, []);
                    const soa = safeJsonParse(detailsContainer.dataset.soa);
                    const srv = safeJsonParse(detailsContainer.dataset.srv, []);
                    const caa = safeJsonParse(detailsContainer.dataset.caa, []);
                    const dmarc = detailsContainer.dataset.dmarc;
                    const spf = detailsContainer.dataset.spf;
                    const soaChanged = detailsContainer.dataset.soaChanged;
                    const nsConsistency = detailsContainer.dataset.nsConsistency;

                    if(cname) contentHtml += `<dt>CNAME</dt><dd>${cname}</dd>`;
                    if(txt.length > 0) contentHtml += `<dt>TXT</dt><dd>${txt.join('<br>')}</dd>`;
                    if(soa) contentHtml += `<dt>SOA Serial</dt><dd>${soa.serial}</dd>`;
                    if(srv.length > 0) contentHtml += `<dt>SRV Records</dt><dd>${srv.map(r => r.target).join(', ')}</dd>`;
                    if(caa.length > 0) contentHtml += `<dt>CAA Records</dt><dd>${caa.map(r => r.value).join('; ')}</dd>`;
                    
                    if (soaChanged === '1') contentHtml += `<dt>SOA Serial Changed</dt><dd>✓ Yes</dd>`;
                    if (soaChanged === '0') contentHtml += `<dt>SOA Serial Changed</dt><dd>✗ No</dd>`;

                    if (nsConsistency) contentHtml += `<dt>NS Consistency</dt><dd>${nsConsistency}</dd>`;
                    
                    if(dmarc === '1') contentHtml += `<dt>DMARC</dt><dd>Present</dd>`;
                    if(dmarc === '0') contentHtml += `<dt>DMARC</dt><dd>Not Present</dd>`;
                    
                    if(spf === '1') contentHtml += `<dt>SPF</dt><dd>Present</dd>`;
                    if(spf === '0') contentHtml += `<dt>SPF</dt><dd>Not Present</dd>`;
                }
            }

            contentHtml += '</dl>';
            
            detailsModalTitle.textContent = title;
            detailsModalContent.innerHTML = contentHtml;
            detailsModal.style.display = 'block';
        });
    });

    // Pagination link handling to preserve state
    console.log("Setting up pagination link listeners...");
    const paginationLinks = document.querySelectorAll('.pagination-link');
    console.log(`Found ${paginationLinks.length} pagination links.`);

    paginationLinks.forEach(link => {
        link.addEventListener('click', function(event) {
            event.preventDefault();
            console.log("Pagination link clicked! Href is:", this.href);

            const url = new URL(this.href);
            // Append the currently selected IDs to the URL's query parameters
            const selectedIds = getSelectedItemsFromStorage().join(',');
            if (selectedIds) {
                url.searchParams.set('checked_ids_for_sort', selectedIds);
            }
            
            // Navigate to the new URL
            window.location.href = url.toString();
        });
    });
    
    // SSE (Server-Sent Events) for progress updates
    let batchIdToMonitor = null;
    const flashedMessages = AppConfig.flashed_messages;
    for (const msg of flashedMessages) {
        const messageText = msg[1];
        if (messageText && messageText.includes('Batch ID:')) {
            const match = messageText.match(/Batch ID: ([a-fA-F0-9-]+)/);
            if (match && match[1]) {
                batchIdToMonitor = match[1];
                localStorage.setItem('active_batch_run_id', batchIdToMonitor);
                break;
            }
        }
    }
    if (!batchIdToMonitor) {
        const stored = localStorage.getItem('active_batch_run_id');
        if (stored) {
            batchIdToMonitor = stored;
        }
    }

    if (batchIdToMonitor) {
         startSseMonitoring(batchIdToMonitor);
    } else {
        if(progressPopupOverlay) progressPopupOverlay.style.display = 'none';
    }
});