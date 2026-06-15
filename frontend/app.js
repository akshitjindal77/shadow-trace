const API_BASE = 'http://localhost:8000/api';
const PAGE = document.body.dataset.page;
const STATUS_STEPS = [
  { id: 'breach', label: 'Breach Check' },
  { id: 'username', label: 'Username Scan' },
  { id: 'email', label: 'Email Reputation' },
  { id: 'domain', label: 'Domain Intelligence' },
  { id: 'dorks', label: 'Exposure Search' },
  { id: 'footprint', label: 'Footprint Score' }
];

const RISK_COLORS = {
  LOW: '#3fb950',
  MODERATE: '#e3b341',
  HIGH: '#d29922',
  CRITICAL: '#f85149'
};

const getQueryParam = (name) => {
  return new URLSearchParams(window.location.search).get(name);
};

const showError = (element, message) => {
  element.textContent = message;
  element.classList.remove('hidden');
};

const hideError = (element) => {
  element.classList.add('hidden');
};

const safeGet = (obj, path, fallback = null) => {
  return path.split('.').reduce((acc, key) => {
    if (acc && Object.prototype.hasOwnProperty.call(acc, key)) {
      return acc[key];
    }
    return null;
  }, obj) ?? fallback;
};

const buildStatusItems = () => {
  const list = document.getElementById('status-list');
  list.innerHTML = STATUS_STEPS.map(step => `
    <li class="status-item" data-step="${step.id}">
      <span>${step.label}</span>
      <span class="status-badge">pending</span>
    </li>
  `).join('');
};

const updateStatusStep = (id, label, state) => {
  const item = document.querySelector(`[data-step="${id}"]`);
  if (!item) return;
  const badge = item.querySelector('.status-badge');
  item.querySelector('span').textContent = label;
  badge.textContent = state;
  badge.style.background = state === 'running' ? 'rgba(88,166,255,0.14)' : 'rgba(255,255,255,0.08)';
  badge.style.color = state === 'running' ? '#58a6ff' : '#8b949e';
};

const setScanButtonState = (button, disabled, text) => {
  button.disabled = disabled;
  button.textContent = text;
};

const initIndexPage = () => {
  const input = document.getElementById('scan-input');
  const buttons = Array.from(document.querySelectorAll('.toggle-btn'));
  const consent = document.getElementById('consent-checkbox');
  const scanButton = document.getElementById('scan-button');
  const statusArea = document.getElementById('status-area');
  const statusText = document.getElementById('status-text');
  const errorBox = document.getElementById('error-box');

  let selectedType = 'email';
  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      buttons.forEach(item => item.classList.remove('active'));
      btn.classList.add('active');
      selectedType = btn.dataset.type;
      input.placeholder = `Enter ${selectedType} to scan`;
    });
  });

  buildStatusItems();

  const resetStatus = () => {
    statusText.textContent = 'Waiting to start...';
    document.querySelectorAll('.status-item').forEach(item => {
      item.querySelector('.status-badge').textContent = 'pending';
      item.querySelector('.status-badge').style.color = '#8b949e';
    });
    statusArea.classList.add('hidden');
    hideError(errorBox);
  };

  const runProgressSimulation = () => {
    statusArea.classList.remove('hidden');
    statusText.textContent = 'Scan running...';
    STATUS_STEPS.forEach((step, index) => {
      setTimeout(() => updateStatusStep(step.id, step.label, 'running'), index * 520);
      setTimeout(() => updateStatusStep(step.id, step.label, 'complete'), index * 520 + 1000);
    });
  };

  const createScan = async (value, type) => {
    const response = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input_value: value, input_type: type, consent: true })
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || 'Scan failed, please try again.');
    }
    return response.json();
  };

  scanButton.addEventListener('click', async () => {
    const value = input.value.trim();
    if (!value) {
      showError(errorBox, 'Please enter an email, username, or domain.');
      return;
    }
    if (!consent.checked) {
      showError(errorBox, 'Consent is required to run a scan.');
      return;
    }

    resetStatus();
    setScanButtonState(scanButton, true, 'Scanning...');
    runProgressSimulation();

    try {
      const result = await createScan(value, selectedType);
      window.location.href = `dashboard.html?scan_id=${encodeURIComponent(result.scan_id)}`;
    } catch (error) {
      showError(errorBox, error.message);
      statusText.textContent = 'Scan failed';
      setScanButtonState(scanButton, false, 'Start Scan');
    }
  });
};

const getRiskColor = (level) => {
  return RISK_COLORS[level?.toUpperCase()] || '#58a6ff';
};

const createRiskBadge = (level) => {
  const formatted = level?.toUpperCase() || 'LOW';
  const badge = document.createElement('span');
  badge.className = `badge-risk badge-risk-${formatted.toLowerCase()}`;
  badge.textContent = formatted;
  return badge;
};

const initDashboardPage = async () => {
  const scanId = getQueryParam('scan_id');
  const errorBox = document.getElementById('dashboard-error');
  if (!scanId) {
    window.location.href = 'index.html';
    return;
  }

  const summaryInput = document.getElementById('summary-input');
  const summaryType = document.getElementById('summary-type');
  const summaryTimestamp = document.getElementById('summary-timestamp');
  const summaryDuration = document.getElementById('summary-duration');
  const statBreaches = document.getElementById('stat-breaches');
  const statPlatforms = document.getElementById('stat-platforms');
  const statDorks = document.getElementById('stat-dorks');
  const findingBreaches = document.getElementById('finding-breaches-count');
  const findingPlatforms = document.getElementById('finding-platforms-count');
  const findingDorks = document.getElementById('finding-dorks-count');
  const platformList = document.getElementById('platform-list');
  const breachList = document.getElementById('breach-list');
  const dorkList = document.getElementById('dork-list');
  const recommendationsList = document.getElementById('recommendations-list');
  const riskScoreNode = document.getElementById('risk-score');
  const riskBadge = document.getElementById('risk-badge');
  const exportButton = document.getElementById('export-button');
  const deleteButton = document.getElementById('delete-button');
  const scanAgainBtn = document.getElementById('scan-again-btn');
  const gaugeCanvas = document.getElementById('risk-gauge');

  const fetchResults = async () => {
    const response = await fetch(`${API_BASE}/results/${encodeURIComponent(scanId)}`);
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || 'Could not load scan results.');
    }
    return response.json();
  };

  try {
    const data = await fetchResults();
    const riskLevel = (data.risk_level || 'LOW').toUpperCase();
    const riskScore = Number(data.overall_risk_score || 0);
    const findings = data.findings || {};

    summaryInput.textContent = data.input_value || '-';
    summaryType.textContent = data.input_type || '-';
    summaryTimestamp.textContent = data.scan_timestamp ? new Date(data.scan_timestamp).toLocaleString() : '-';
    summaryDuration.textContent = `${Number(data.scan_duration_seconds || 0).toFixed(1)}s`;

    statBreaches.textContent = data.breach_count ?? 0;
    statPlatforms.textContent = data.platforms_found ?? 0;
    statDorks.textContent = data.dork_results_count ?? 0;

    findingBreaches.textContent = data.breach_count ?? 0;
    findingPlatforms.textContent = data.platforms_found ?? 0;
    findingDorks.textContent = data.dork_results_count ?? 0;

    const emailDisclaimer = document.getElementById('email-disclaimer');
    if (data.input_type === 'email') {
      emailDisclaimer.classList.remove('hidden');
    } else {
      emailDisclaimer.classList.add('hidden');
    }

    platformList.innerHTML = '';
    const platformItems = safeGet(findings, 'username_enum.data.platforms', []) || [];
    console.debug('Platform items loaded for dashboard:', platformItems);
    const visiblePlatforms = platformItems.filter(p => p.found || p.profile_url);
    if (visiblePlatforms.length === 0) {
      platformList.innerHTML = '<p class="muted-text">No platform matches were found.</p>';
    } else {
      visiblePlatforms.forEach(platform => {
        const platformName = platform.platform || platform.name || 'Unknown platform';
        const profileLink = platform.profile_url || platform.url || null;
        const linkHtml = profileLink
          ? `<div><a href="${profileLink}" target="_blank" rel="noreferrer">View profile</a></div>`
          : '<div class="muted-text">Profile link not available.</div>';

        const card = document.createElement('div');
        card.className = 'item-card';
        card.innerHTML = `
          <strong>${platformName}</strong>
          ${linkHtml}
        `;
        platformList.appendChild(card);
      });
    }

    breachList.innerHTML = '';
    const breachItems = safeGet(findings, 'breaches.data.breaches', []) || safeGet(findings, 'breaches.breaches', []) || [];
    if (breachItems.length === 0) {
      breachList.innerHTML = '<p class="muted-text">No breaches were detected.</p>';
    } else {
      breachItems.forEach(item => {
        const card = document.createElement('div');
        card.className = 'item-card';
        card.innerHTML = `
          <strong>${item.name || item.Title || 'Unknown breach'}</strong>
          <small>${item.breach_date || item.Date || 'Date unavailable'}</small>
          <p>${(item.data_classes || item.dataClasses || []).slice(0, 4).join(', ') || 'Sensitive data exposed'}</p>
        `;
        breachList.appendChild(card);
      });
    }

    dorkList.innerHTML = '';
    const dorkQueries = safeGet(findings, 'dorks.data.queries', []) || safeGet(findings, 'dorks.queries', []) || [];
    if (dorkQueries.length === 0) {
      dorkList.innerHTML = '<p class="muted-text">No indexed exposures were detected.</p>';
    } else {
      dorkQueries.forEach(result => {
        const card = document.createElement('div');
        card.className = 'item-card';
        const label = (result.risk_level || 'LOW').toUpperCase();
        card.innerHTML = `
          <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;">
            <strong>${result.query_string || result.title || 'Search result'}</strong>
            <span class="badge-risk badge-risk-${label.toLowerCase()}">${label}</span>
          </div>
          <div style="margin-top:10px; color: var(--muted); font-size:0.92rem;">${result.url ? `<a href='${result.url}' target='_blank' rel='noreferrer'>Open link</a>` : 'No direct link available'}</div>
        `;
        dorkList.appendChild(card);
      });
    }

    recommendationsList.innerHTML = '';
    const recs = data.recommendations || [];
    if (recs.length === 0) {
      recommendationsList.innerHTML = '<p class="muted-text">No recommendations available.</p>';
    } else {
      recs.forEach(rec => {
        const item = document.createElement('div');
        item.className = 'recommendation-item';
        item.innerHTML = `
          <div class="recommendation-header">
            <strong>${rec.action || rec.title || 'Take action'}</strong>
            <span class="category-badge">${rec.category || 'general'}</span>
          </div>
          <div class="recommendation-body">${rec.reason || rec.description || 'Review this finding.'}</div>
        `;
        recommendationsList.appendChild(item);
      });
    }

    riskScoreNode.textContent = String(riskScore);
    riskBadge.replaceWith(createRiskBadge(riskLevel));

    new Chart(gaugeCanvas, {
      type: 'doughnut',
      data: {
        datasets: [{
          data: [riskScore, Math.max(0, 100 - riskScore)],
          backgroundColor: [getRiskColor(riskLevel), '#30363d'],
          borderWidth: 0
        }]
      },
      options: {
        cutout: '75%',
        rotation: 270,
        circumference: 180,
        responsive: false,
        plugins: {
          legend: { display: false },
          tooltip: { enabled: false }
        }
      }
    });

    exportButton.addEventListener('click', () => {
      window.open(`${API_BASE}/export/${encodeURIComponent(scanId)}`, '_blank');
    });

    deleteButton.addEventListener('click', async () => {
      if (!confirm('Delete this scan and its stored results?')) return;
      const response = await fetch(`${API_BASE}/scan/${encodeURIComponent(scanId)}`, { method: 'DELETE' });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        showError(errorBox, body.detail || 'Failed to delete scan.');
        return;
      }
      window.location.href = 'index.html';
    });

    scanAgainBtn.addEventListener('click', () => {
      window.location.href = 'index.html';
    });
  } catch (error) {
    showError(errorBox, error.message);
  }
};

const initHistoryPage = async () => {
  const tableBody = document.getElementById('history-table-body');
  const filterType = document.getElementById('filter-type');
  const prevPage = document.getElementById('prev-page');
  const nextPage = document.getElementById('next-page');
  const pageIndicator = document.getElementById('page-indicator');
  const errorBox = document.getElementById('history-error');

  let items = [];
  let currentPage = 1;
  const pageSize = 8;

  const fetchHistory = async () => {
    const response = await fetch(`${API_BASE}/history`);
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || 'Could not load history.');
    }
    return response.json();
  };

  const getColorClass = (score) => {
    if (score >= 75) return 'badge-risk-critical';
    if (score >= 50) return 'badge-risk-high';
    if (score >= 30) return 'badge-risk-moderate';
    return 'badge-risk-low';
  };

  const renderRow = (scan) => {
    const tr = document.createElement('tr');
    const riskClass = getColorClass(scan.overall_risk_score);
    const level = scan.risk_level?.toUpperCase?.() || 'LOW';
    tr.innerHTML = `
      <td>${scan.input_value || '-'}</td>
      <td>${scan.input_type || '-'}</td>
      <td><span class="badge-risk ${riskClass}">${scan.overall_risk_score ?? 0}</span></td>
      <td>${level}</td>
      <td>${scan.scan_timestamp ? new Date(scan.scan_timestamp).toLocaleString() : '-'}</td>
      <td class="table-action">
        <button class="secondary-btn" data-action="view" data-id="${scan.scan_id}">View</button>
        <button class="secondary-btn" data-action="export" data-id="${scan.scan_id}">Export</button>
        <button class="danger-btn" data-action="delete" data-id="${scan.scan_id}">Delete</button>
      </td>
    `;
    return tr;
  };

  const applyFilters = () => {
    const type = filterType.value;
    let filtered = items;
    if (type !== 'all') {
      filtered = items.filter(scan => scan.input_type === type);
    }
    const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
    currentPage = Math.min(currentPage, totalPages);

    const start = (currentPage - 1) * pageSize;
    const pageItems = filtered.slice(start, start + pageSize);
    tableBody.innerHTML = '';
    pageItems.forEach(scan => tableBody.appendChild(renderRow(scan)));
    pageIndicator.textContent = `Page ${currentPage} of ${totalPages}`;
    prevPage.disabled = currentPage <= 1;
    nextPage.disabled = currentPage >= totalPages;
  };

  tableBody.addEventListener('click', async (event) => {
    const button = event.target.closest('button');
    if (!button) return;
    const action = button.dataset.action;
    const scanId = button.dataset.id;
    if (!action || !scanId) return;

    if (action === 'view') {
      window.location.href = `dashboard.html?scan_id=${encodeURIComponent(scanId)}`;
      return;
    }
    if (action === 'export') {
      window.open(`${API_BASE}/export/${encodeURIComponent(scanId)}`, '_blank');
      return;
    }
    if (action === 'delete') {
      if (!confirm('Delete this scan permanently?')) return;
      const response = await fetch(`${API_BASE}/scan/${encodeURIComponent(scanId)}`, { method: 'DELETE' });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        showError(errorBox, body.detail || 'Failed to delete scan.');
        return;
      }
      items = items.filter(scan => scan.scan_id !== scanId);
      applyFilters();
    }
  });

  filterType.addEventListener('change', () => {
    currentPage = 1;
    applyFilters();
  });

  prevPage.addEventListener('click', () => {
    currentPage -= 1;
    applyFilters();
  });

  nextPage.addEventListener('click', () => {
    currentPage += 1;
    applyFilters();
  });

  try {
    items = await fetchHistory();
    applyFilters();
  } catch (error) {
    showError(errorBox, error.message);
  }
};

window.addEventListener('DOMContentLoaded', () => {
  if (PAGE === 'index') initIndexPage();
  if (PAGE === 'dashboard') initDashboardPage();
  if (PAGE === 'history') initHistoryPage();
});
