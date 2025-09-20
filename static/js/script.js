let currentTaskId = null;
let pollInterval = null;

// DOM Elements
const inputSection = document.getElementById('input-section');
const progressSection = document.getElementById('progress-section');
const resultsSection = document.getElementById('results-section');
const urlInput = document.getElementById('url-input');
const startScanBtn = document.getElementById('start-scan-btn');
const cancelScanBtn = document.getElementById('cancel-scan-btn');
const newScanBtn = document.getElementById('new-scan-btn');
const progressFill = document.getElementById('progress-fill');
const progressPercentage = document.getElementById('progress-percentage');
const progressStatus = document.getElementById('progress-status');

// Initialize event listeners
document.addEventListener('DOMContentLoaded', function() {
    initializeEventListeners();
});

function initializeEventListeners() {
    // Start scan button
    startScanBtn.addEventListener('click', handleStartScan);

    // Cancel scan button
    if (cancelScanBtn) {
        cancelScanBtn.addEventListener('click', handleCancelScan);
    }

    // New scan button
    if (newScanBtn) {
        newScanBtn.addEventListener('click', handleNewScan);
    }

    // URL input enter key
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            handleStartScan();
        }
    });

    // Tab navigation
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            handleTabClick(this);
        });
    });
}

function handleStartScan() {
    const url = urlInput.value.trim();

    if (!url) {
        showAlert('Please enter a URL to scan');
        return;
    }

    if (!isValidUrl(url)) {
        showAlert('Please enter a valid URL (must start with http:// or https://)');
        return;
    }

    const selectedOptions = getSelectedOptions();

    if (selectedOptions.length === 0) {
        showAlert('Please select at least one scan category');
        return;
    }

    startScan(url, selectedOptions);
}

function isValidUrl(url) {
    return url.startsWith('http://') || url.startsWith('https://');
}

function getSelectedOptions() {
    const checkboxes = document.querySelectorAll('input[type="checkbox"]:checked');
    return Array.from(checkboxes).map(checkbox => checkbox.value);
}

function startScan(url, options) {
    // Switch to progress view
    showSection('progress');

    // Reset progress
    updateProgress(0, 'Initializing scan...');

    // Make API request
    fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            url: url,
            options: options
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.task_id) {
            currentTaskId = data.task_id;
            pollScanStatus();
        } else {
            showAlert('Error starting scan: ' + (data.error || 'Unknown error'));
            showSection('input');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('Network error: ' + error.message);
        showSection('input');
    });
}

function pollScanStatus() {
    if (!currentTaskId) return;

    pollInterval = setInterval(() => {
        fetch(`/status/${currentTaskId}`)
        .then(response => response.json())
        .then(data => {
            updateProgress(data.progress || 0, data.current || 'Processing...');

            if (data.state === 'SUCCESS') {
                clearInterval(pollInterval);
                showResults(data.result);
            } else if (data.state === 'FAILURE') {
                clearInterval(pollInterval);
                showAlert('Scan failed: ' + (data.result || 'Unknown error'));
                showSection('input');
            }
        })
        .catch(error => {
            console.error('Polling error:', error);
        });
    }, 2000);
}

function updateProgress(progress, status) {
    progressFill.style.width = progress + '%';
    progressPercentage.textContent = Math.round(progress) + '%';
    progressStatus.textContent = status;
}

function showResults(results) {
    showSection('results');

    // Update severity summary
    updateSeveritySummary(results.summary || {});

    // Update results content
    updateResultsContent(results.findings || {});
}

function updateSeveritySummary(summary) {
    document.getElementById('critical-count').textContent = summary.critical || 0;
    document.getElementById('high-count').textContent = summary.high || 0;
    document.getElementById('medium-count').textContent = summary.medium || 0;
    document.getElementById('low-count').textContent = summary.low || 0;
    document.getElementById('info-count').textContent = summary.info || 0;
}

function updateResultsContent(findings) {
    const resultsContent = document.getElementById('results-content');

    // Clear existing content
    resultsContent.innerHTML = '';

    // Show first category by default
    const categories = Object.keys(findings);
    if (categories.length > 0) {
        const firstCategory = categories[0];
        displayFindings(findings[firstCategory] || []);

        // Update tab buttons
        updateTabButtons(firstCategory.toLowerCase().replace(/[^a-z0-9]/g, '-'));
    }

    // Store findings data for tab switching
    window.scanResults = findings;
}

function displayFindings(findings) {
    const resultsContent = document.getElementById('results-content');
    resultsContent.innerHTML = '';

    if (findings.length === 0) {
        resultsContent.innerHTML = '<p class="no-findings">No issues found in this category.</p>';
        return;
    }

    findings.forEach(finding => {
        const findingElement = createFindingElement(finding);
        resultsContent.appendChild(findingElement);
    });
}

function createFindingElement(finding) {
    const findingDiv = document.createElement('div');
    findingDiv.className = 'finding-item';

    findingDiv.innerHTML = `
        <div class="finding-header">
            <h4>${finding.title || 'Untitled Finding'}</h4>
            <span class="severity-tag ${finding.severity.toLowerCase()}">${finding.severity.toUpperCase()}</span>
        </div>
        <p class="finding-description">${finding.description || 'No description available.'}</p>
    `;

    return findingDiv;
}

function handleTabClick(button) {
    const tabName = button.getAttribute('data-tab');

    // Update active tab
    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
    button.classList.add('active');

    // Show corresponding results
    if (window.scanResults) {
        const categoryKey = findCategoryKey(tabName);
        if (categoryKey && window.scanResults[categoryKey]) {
            displayFindings(window.scanResults[categoryKey]);
        }
    }
}

function findCategoryKey(tabName) {
    const mapping = {
        'security-headers': 'Security Headers',
        'tls-analysis': 'TLS/SSL Analysis',
        'vulnerabilities': 'Vulnerabilities',
        'advanced-checks': 'Advanced Checks',
        'content-analysis': 'Content Analysis',
        'port-scanning': 'Port Scanning'
    };

    return mapping[tabName] || tabName;
}

function updateTabButtons(activeTab) {
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('data-tab') === activeTab) {
            btn.classList.add('active');
        }
    });
}

function handleCancelScan() {
    if (pollInterval) {
        clearInterval(pollInterval);
    }
    currentTaskId = null;
    showSection('input');
}

function handleNewScan() {
    if (pollInterval) {
        clearInterval(pollInterval);
    }
    currentTaskId = null;

    // Reset form
    urlInput.value = '';

    // Reset checkboxes to default (all checked)
    document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
        checkbox.checked = true;
    });

    showSection('input');
}

function showSection(sectionName) {
    // Hide all sections
    inputSection.style.display = 'none';
    progressSection.style.display = 'none';
    resultsSection.style.display = 'none';

    // Show requested section
    switch (sectionName) {
        case 'input':
            inputSection.style.display = 'block';
            break;
        case 'progress':
            progressSection.style.display = 'block';
            break;
        case 'results':
            resultsSection.style.display = 'block';
            break;
    }
}

function showAlert(message) {
    // Simple alert for now - can be replaced with custom modal
    alert(message);
}

// Initialize the app
document.addEventListener('DOMContentLoaded', function() {
    showSection('input');
});