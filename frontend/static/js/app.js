/**
 * CloudGuard dashboard — vanilla JS, no build step. Talks to the FastAPI
 * backend via fetch(). Kept dependency-free intentionally so the whole
 * frontend can be served as static files by the API itself.
 */
const API = '/api';
const SEVERITY_COLORS = {
  critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)',
  low: 'var(--sev-low)', info: 'var(--sev-info)',
};

let state = { latestScan: null, findings: [], compliance: [] };

function $(sel) { return document.querySelector(sel); }
function $all(sel) { return document.querySelectorAll(sel); }
function setLoading(on) { $('#loadingLine').classList.toggle('active', on); }

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!res.ok && res.status !== 202) {
    const text = await res.text();
    throw new Error(`${res.status}: ${text}`);
  }
  return res.status === 202 ? null : res.json();
}

// -- navigation -----------------------------------------------------------
$all('.nav button').forEach(btn => {
  btn.addEventListener('click', () => {
    $all('.nav button').forEach(b => b.classList.remove('active'));
    $all('.view').forEach(v => v.classList.remove('active'));
    btn.classList.add('active');
    $(`#view-${btn.dataset.view}`).classList.add('active');
  });
});

// -- scan trigger -----------------------------------------------------------
$('#scanBtn').addEventListener('click', async () => {
  const btn = $('#scanBtn');
  btn.disabled = true;
  btn.textContent = '⏳ Scanning…';
  setLoading(true);
  try {
    const scan = await api('/scans/sync', {
      method: 'POST',
      body: JSON.stringify({ region: 'us-east-1', provider: $('#scanProvider').value }),
    });
    state.latestScan = scan;
    await loadAll();
  } catch (err) {
    alert('Scan failed: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '▶ Run scan';
    setLoading(false);
  }
});

$('#exportBtn').addEventListener('click', () => {
  if (!state.latestScan) { alert('Run a scan first.'); return; }
  window.open(`${API}/reports/${state.latestScan.id}/html`, '_blank');
});

// -- data loading -----------------------------------------------------------
async function loadDashboard() {
  const dash = await api('/dashboard');
  state.latestScan = dash.latest_scan;

  $('#statTotalScans').textContent = dash.total_scans;

  if (!dash.latest_scan) {
    renderGauge($('#gauge'), 0, '—');
    $('#gaugeCaption').textContent = 'No scans yet. Click "Run scan" to assess your account.';
    $('#modePill').textContent = 'NO DATA';
    return;
  }

  const scan = dash.latest_scan;
  $('#modePill').textContent = scan.mode.toUpperCase() + ' MODE';
  $('#modePill').className = 'mode-pill mode-pill--' + scan.mode;

  renderGauge($('#gauge'), scan.risk_score, scan.risk_grade);
  $('#gaugeCaption').textContent =
    `${scan.total_findings} open finding${scan.total_findings === 1 ? '' : 's'} found in the last scan, completed ${fmtDate(scan.completed_at)}.`;

  $('#statOpenFindings').textContent = scan.total_findings;
  $('#statCritical').textContent = (scan.severity_counts || {}).critical || 0;
  $('#statLastScan').textContent = fmtDate(scan.completed_at);
  $('#statDuration').textContent = scan.duration_seconds.toFixed(2) + 's';

  // severity strip
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  $('#severityStrip').innerHTML = order.map(sev => `
    <div class="sev-chip" style="border-top-color:${SEVERITY_COLORS[sev]}">
      <div class="sev-chip__count" style="color:${SEVERITY_COLORS[sev]}">${(scan.severity_counts || {})[sev] || 0}</div>
      <div class="sev-chip__label">${sev}</div>
    </div>`).join('');

  // provider bars
  const providers = Object.entries(scan.provider_scores || {}).sort((a, b) => a[1] - b[1]);
  $('#providerBars').innerHTML = providers.map(([provider, score]) => {
    const color = score >= 80 ? 'var(--grade-a)' : score >= 60 ? 'var(--grade-c)' : 'var(--grade-f)';
    return `<div class="service-bar-row">
      <div class="label">${provider.toUpperCase()}</div>
      <div class="service-bar-track"><div class="service-bar-fill" style="width:${score}%;background:${color}"></div></div>
      <div class="val">${score}</div>
    </div>`;
  }).join('') || '<div class="empty-state"><p>No provider data yet.</p></div>';

  // service bars
  const services = Object.entries(scan.service_scores || {}).sort((a, b) => a[1] - b[1]);
  $('#serviceBars').innerHTML = services.map(([svc, score]) => {
    const color = score >= 80 ? 'var(--grade-a)' : score >= 60 ? 'var(--grade-c)' : 'var(--grade-f)';
    return `<div class="service-bar-row">
      <div class="label">${svc}</div>
      <div class="service-bar-track"><div class="service-bar-fill" style="width:${score}%;background:${color}"></div></div>
      <div class="val">${score}</div>
    </div>`;
  }).join('') || '<div class="empty-state"><p>No category data yet.</p></div>';

  // top findings preview
  const findings = await api(`/scans/${scan.id}/findings`);
  const top = [...findings].sort((a, b) => b.severity_weight - a.severity_weight).slice(0, 6);
  $('#topFindingsBody').innerHTML = top.length
    ? `<table class="findings"><tbody>${top.map(rowHtml).join('')}</tbody></table>`
    : '<div class="empty-state"><h3>Account looks clean</h3><p>No findings in the most recent scan.</p></div>';
}

function severityBadge(sev) {
  // Medium's amber is too light for white text.
  const text = sev === 'medium' ? '#22262b' : '#ffffff';
  return `<span class="badge" style="background:${SEVERITY_COLORS[sev]};color:${text}">${sev}</span>`;
}

function rowHtml(f) {
  const compliance = (f.compliance || []).slice(0, 2)
    .map(c => `<span class="compliance-tag">${c.control_id}</span>`).join('');
  return `<tr>
    <td>${severityBadge(f.severity)}</td>
    <td>
      <div class="finding-title">${escapeHtml(f.title)}</div>
      <div class="finding-desc">${escapeHtml(f.description)}</div>
    </td>
    <td>
      <div class="resource-id">${escapeHtml(f.resource_name)}</div>
      <div class="region-tag">${escapeHtml(f.region)}</div>
      <span class="provider-tag">${escapeHtml((f.provider || 'aws').toUpperCase())}</span>
    </td>
    <td>${compliance || '<span class="region-tag">—</span>'}</td>
    <td>
      <select class="status-select" data-finding-id="${f.id}">
        <option value="open" ${f.status === 'open' ? 'selected' : ''}>Open</option>
        <option value="resolved" ${f.status === 'resolved' ? 'selected' : ''}>Resolved</option>
        <option value="risk_accepted" ${f.status === 'risk_accepted' ? 'selected' : ''}>Risk accepted</option>
        <option value="suppressed" ${f.status === 'suppressed' ? 'selected' : ''}>Suppressed</option>
      </select>
    </td>
  </tr>`;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}

function shortFramework(framework) {
  if (!framework) return '';
  if (framework.includes('Azure')) return 'CIS Azure v3.0.0';
  if (framework.includes('AWS')) return 'CIS AWS v3.0';
  return framework;
}

async function loadFindings() {
  const findings = await api('/findings?limit=1000');
  state.findings = findings;

  const types = [...new Set(findings.map(f => f.resource_type))].sort();
  const select = $('#resourceFilter');
  select.innerHTML = '<option value="">All resource types</option>' +
    types.map(t => `<option value="${t}">${t.replace(/_/g, ' ')}</option>`).join('');

  renderFindingsTable();
}

function renderFindingsTable() {
  const search = $('#findingSearch').value.toLowerCase();
  const sevFilter = $('#severityFilter').value;
  const providerFilter = $('#providerFilter').value;
  const typeFilter = $('#resourceFilter').value;

  const filtered = state.findings.filter(f => {
    if (sevFilter && f.severity !== sevFilter) return false;
    if (providerFilter && (f.provider || 'aws') !== providerFilter) return false;
    if (typeFilter && f.resource_type !== typeFilter) return false;
    if (search && !(`${f.title} ${f.resource_name}`.toLowerCase().includes(search))) return false;
    return true;
  }).sort((a, b) => b.severity_weight - a.severity_weight);

  $('#findingsTableBody').innerHTML = filtered.map(rowHtml).join('');
  $('#findingsEmpty').style.display = filtered.length ? 'none' : 'block';

  $all('.status-select').forEach(sel => {
    sel.addEventListener('change', async (e) => {
      const id = e.target.dataset.findingId;
      try {
        await api(`/findings/${id}`, { method: 'PATCH', body: JSON.stringify({ status: e.target.value }) });
      } catch (err) {
        alert('Could not update finding: ' + err.message);
      }
    });
  });
}

['findingSearch', 'severityFilter', 'providerFilter', 'resourceFilter'].forEach(id => {
  $('#' + id).addEventListener('input', renderFindingsTable);
});

async function loadCompliance() {
  const data = await api('/compliance/summary');
  state.compliance = data.controls;
  $('#complianceGrid').innerHTML = data.controls.length
    ? data.controls.map(c => `
      <div class="control-row" style="border-left-color:${SEVERITY_COLORS[c.highest_severity]}">
        <div class="control-id">${c.control_id}<span class="framework-tag">${escapeHtml(shortFramework(c.framework))}</span></div>
        <div class="control-title">${escapeHtml(c.control_title)}</div>
        <div>${severityBadge(c.highest_severity)}</div>
        <div class="count">${c.open_findings} open</div>
      </div>`).join('')
    : '<div class="empty-state"><h3>No compliance data yet</h3><p>Run a scan to see control coverage.</p></div>';
}

async function loadAll() {
  setLoading(true);
  try {
    await loadDashboard();
    await loadFindings();
    await loadCompliance();
  } catch (err) {
    console.error(err);
  } finally {
    setLoading(false);
  }
}

loadAll();
