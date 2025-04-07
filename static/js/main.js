function searchCVE() {
    const searchInput = document.getElementById('searchInput');
    const cveId = searchInput.value.trim();
    
    if (cveId) {
        window.location.href = `/api/cves?cve_id=${encodeURIComponent(cveId)}`;
    }
}

function changePerPage() {
    const perPageSelect = document.getElementById('perPageSelect');
    const perPage = perPageSelect.value;
    const currentUrl = new URL(window.location.href);
    
    currentUrl.searchParams.set('per_page', perPage);
    window.location.href = currentUrl.toString();
}

function sortBy(field) {
    const currentUrl = new URL(window.location.href);
    const currentSortBy = currentUrl.searchParams.get('sort_by');
    const currentSortOrder = currentUrl.searchParams.get('sort_order');
    
    let newSortOrder = 'desc';
    if (currentSortBy === field && currentSortOrder === 'desc') {
        newSortOrder = 'asc';
    }
    
    currentUrl.searchParams.set('sort_by', field);
    currentUrl.searchParams.set('sort_order', newSortOrder);
    window.location.href = currentUrl.toString();
}

function applyFilters() {
    const cveId = document.getElementById('cveIdFilter').value;
    const year = document.getElementById('yearFilter').value;
    const score = document.getElementById('scoreFilter').value;
    const days = document.getElementById('daysFilter').value;
    
    const currentUrl = new URL(window.location.href);
    
    if (cveId) currentUrl.searchParams.set('cve_id', cveId);
    else currentUrl.searchParams.delete('cve_id');
    
    if (year) currentUrl.searchParams.set('year', year);
    else currentUrl.searchParams.delete('year');
    
    if (score) currentUrl.searchParams.set('score', score);
    else currentUrl.searchParams.delete('score');
    
    if (days) currentUrl.searchParams.set('last_modified_days', days);
    else currentUrl.searchParams.delete('last_modified_days');
    
    // Reset to first page when filtering
    currentUrl.searchParams.set('page', '1');
    
    window.location.href = currentUrl.toString();
}

function syncData() {
    fetch('/api/sync')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Data synchronized successfully!');
                window.location.reload();
            } else {
                alert('Error synchronizing data: ' + data.message);
            }
        })
        .catch(error => {
            alert('Error synchronizing data: ' + error);
        });
}

// Add event listeners
document.addEventListener('DOMContentLoaded', function() {
    // Set the current per_page value in the select
    const urlParams = new URLSearchParams(window.location.search);
    const currentPerPage = urlParams.get('per_page') || '10';
    document.getElementById('perPageSelect').value = currentPerPage;
    
    // Add enter key support for search
    document.getElementById('searchInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            searchCVE();
        }
    });
    
    // Set filters
    if (document.getElementById('cveIdFilter')) {
        document.getElementById('cveIdFilter').value = urlParams.get('cve_id') || '';
        document.getElementById('yearFilter').value = urlParams.get('year') || '';
        document.getElementById('scoreFilter').value = urlParams.get('score') || '';
        document.getElementById('daysFilter').value = urlParams.get('last_modified_days') || '';
    }
}); 