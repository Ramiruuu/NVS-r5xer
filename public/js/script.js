// State management
let currentScanId = null;
let isScanning = false;

// DOM Elements
const targetInput = document.getElementById('target');
const scanTypeSelect = document.getElementById('scan-type');
const portStartInput = document.getElementById('port-start');
const portEndInput = document.getElementById('port-end');
const serviceDetectionCheck = document.getElementById('service-detection');
const osDetectionCheck = document.getElementById('os-detection');
const vulnScanCheck = document.getElementById('vuln-scan');
const scanBtn = document.querySelector('.scan-btn');
const progressBar = document.getElementById('scan-progress');
const resultsList = document.getElementById('scan-results-list');
const openPortsCount = document.getElementById('open-ports-count');
const vulnSummary = document.getElementById('vuln-summary');
const vulnList = document.getElementById('vuln-list');
const resultsSummary = document.getElementById('results-summary');

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadRecentScans();
});

// Start scan function
async function startScan() {
    // Get input values
    const target = targetInput.value.trim();
    const scanType = scanTypeSelect.value;
    const portStart = parseInt(portStartInput.value);
    const portEnd = parseInt(portEndInput.value);
    
    // Validate inputs
    if (!target) {
        showError('Please enter a target IP or hostname');
        return;
    }
    
    if (portStart > portEnd) {
        showError('Start port must be less than end port');
        return;
    }
    
    if (portStart < 1 || portEnd > 65535) {
        showError('Ports must be between 1 and 65535');
        return;
    }
    
    // Update UI for scanning
    isScanning = true;
    scanBtn.innerHTML = '<span class="btn-icon">⏳</span> Scanning...';
    scanBtn.disabled = true;
    progressBar.style.width = '0%';
    resultsList.innerHTML = '';
    vulnSummary.style.display = 'none';
    
    // Show scanning message
    if (resultsSummary) {
        resultsSummary.innerHTML = '<div class="info-message">Scanning target... This may take a moment.</div>';
    }
    
    try {
        // Make API call
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                target: target,
                scan_type: scanType,
                port_start: portStart,
                port_end: portEnd
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentScanId = data.job_id;
            displayResults(data.results);
            progressBar.style.width = '100%';
            
            if (resultsSummary) {
                resultsSummary.innerHTML = '<div class="success-message">Scan completed successfully!</div>';
            }
            
            // Save to recent scans
            saveToRecentScans(target, data.job_id);
        } else {
            showError(data.error || 'Scan failed');
        }
    } catch (error) {
        console.error('Scan error:', error);
        showError('Failed to connect to server. Please try again.');
    } finally {
        // Reset button
        isScanning = false;
        scanBtn.innerHTML = '<span class="btn-icon">⚡</span> Start Scan';
        scanBtn.disabled = false;
    }
}

// Display results function
function displayResults(results) {
    resultsList.innerHTML = '';
    
    let openPorts = 0;
    let criticalVulns = [];
    let highVulns = [];
    
    results.forEach(result => {
        if (result.state === 'open') {
            openPorts++;
        }
        
        const row = document.createElement('div');
        row.className = `result-row ${result.state}`;
        
        // Create CVE badges
        let cveHtml = '-';
        if (result.cves && result.cves.length > 0) {
            cveHtml = result.cves.map(cve => {
                // Track vulnerabilities by severity
                if (cve.severity === 'CRITICAL') {
                    criticalVulns.push({
                        port: result.port,
                        service: result.service,
                        cve: cve.id
                    });
                } else if (cve.severity === 'HIGH') {
                    highVulns.push({
                        port: result.port,
                        service: result.service,
                        cve: cve.id
                    });
                }
                
                return `<span class="cve-badge severity-${cve.severity.toLowerCase()}" onclick="showCveDetails('${cve.id}')">${cve.id}</span>`;
            }).join('');
        }
        
        row.innerHTML = `
            <span>${result.port}</span>
            <span style="color: ${getStateColor(result.state)}">${result.state}</span>
            <span>${result.service}</span>
            <span>${result.version}</span>
            <span>${cveHtml}</span>
        `;
        
        resultsList.appendChild(row);
    });
    
    // Update open ports count
    openPortsCount.textContent = openPorts;
    
    // Show vulnerability summary if found
    if (criticalVulns.length > 0 || highVulns.length > 0) {
        vulnSummary.style.display = 'block';
        
        let vulnHtml = '';
        
        if (criticalVulns.length > 0) {
            vulnHtml += '<div class="vuln-section"><h5>🔴 CRITICAL VULNERABILITIES</h5>';
            criticalVulns.forEach(v => {
                vulnHtml += `<div class="vuln-item critical">Port ${v.port} (${v.service}): ${v.cve}</div>`;
            });
            vulnHtml += '</div>';
        }
        
        if (highVulns.length > 0) {
            vulnHtml += '<div class="vuln-section"><h5>🟠 HIGH VULNERABILITIES</h5>';
            highVulns.forEach(v => {
                vulnHtml += `<div class="vuln-item high">Port ${v.port} (${v.service}): ${v.cve}</div>`;
            });
            vulnHtml += '</div>';
        }
        
        vulnList.innerHTML = vulnHtml;
    }
}

// Helper function to get state color
function getStateColor(state) {
    switch(state) {
        case 'open': return '#00ff9d';
        case 'filtered': return '#ffaa00';
        case 'closed': return '#666';
        default: return '#fff';
    }
}

// Show CVE details
async function showCveDetails(cveId) {
    try {
        const response = await fetch(`/api/vulnerabilities?cve_id=${cveId}`);
        const data = await response.json();
        
        if (data.length > 0) {
            const cve = data[0];
            alert(`
CVE: ${cve.cve_id}
Severity: ${cve.severity}
Port: ${cve.port}
Service: ${cve.service}
Description: ${cve.description}
Solution: ${cve.solution}
            `);
        }
    } catch (error) {
        console.error('Error fetching CVE details:', error);
    }
}

// Set preset function
function setPreset(type) {
    switch(type) {
        case 'quick':
            portStartInput.value = 1;
            portEndInput.value = 1000;
            scanTypeSelect.value = 'tcp';
            break;
        case 'full':
            portStartInput.value = 1;
            portEndInput.value = 65535;
            scanTypeSelect.value = 'comprehensive';
            break;
        case 'common':
            portStartInput.value = 1;
            portEndInput.value = 1024;
            scanTypeSelect.value = 'syn';
            break;
    }
}

// Load recent scans
function loadRecentScans() {
    const recentScans = JSON.parse(localStorage.getItem('recentScans') || '[]');
    const recentScansDiv = document.getElementById('recent-scans');
    
    if (recentScansDiv) {
        if (recentScans.length === 0) {
            recentScansDiv.innerHTML = '<p class="no-data">No recent scans</p>';
        } else {
            recentScansDiv.innerHTML = recentScans.map(scan => `
                <div class="recent-scan-item" onclick="loadScan(${scan.id})">
                    <span class="scan-target">${scan.target}</span>
                    <span class="scan-time">${scan.time}</span>
                </div>
            `).join('');
        }
    }
}

// Save to recent scans
function saveToRecentScans(target, jobId) {
    const recentScans = JSON.parse(localStorage.getItem('recentScans') || '[]');
    
    recentScans.unshift({
        id: jobId,
        target: target,
        time: new Date().toLocaleTimeString()
    });
    
    // Keep only last 5 scans
    if (recentScans.length > 5) {
        recentScans.pop();
    }
    
    localStorage.setItem('recentScans', JSON.stringify(recentScans));
    loadRecentScans();
}

// Load a previous scan
async function loadScan(jobId) {
    try {
        const response = await fetch(`/api/scan/${jobId}`);
        const data = await response.json();
        
        targetInput.value = data.target;
        displayResults(data.results);
        
        // Scroll to results
        document.querySelector('.scan-results').scrollIntoView({ behavior: 'smooth' });
    } catch (error) {
        console.error('Error loading scan:', error);
    }
}

// Show error message
function showError(message) {
    if (resultsSummary) {
        resultsSummary.innerHTML = `<div class="error-message">❌ ${message}</div>`;
    } else {
        alert(message);
    }
}

// Export results
function exportResults() {
    if (!currentScanId) {
        alert('No scan results to export');
        return;
    }
    
    fetch(`/api/scan/${currentScanId}`)
        .then(response => response.json())
        .then(data => {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `scan-${data.target}-${new Date().toISOString()}.json`;
            a.click();
        })
        .catch(error => console.error('Export error:', error));
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + Enter to start scan
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        if (!isScanning) {
            startScan();
        }
    }
    
    // Escape to cancel scan
    if (e.key === 'Escape' && isScanning) {
        // Add cancel logic here if needed
    }
});

// Add tooltips
function addTooltips() {
    const tooltips = {
        'target': 'Enter IP address or hostname (e.g., 192.168.1.1 or scanme.org)',
        'scan-type': 'TCP Connect: Full connection\nSYN Stealth: Half-open scan\nUDP: UDP port scan',
        'service-detection': 'Attempt to identify service versions',
        'os-detection': 'Detect operating system (requires admin privileges)',
        'vuln-scan': 'Check for known vulnerabilities'
    };
    
    Object.keys(tooltips).forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.setAttribute('title', tooltips[id]);
        }
    });
}

// Initialize tooltips
addTooltips();