const GRAPH_COLORS = {
  service: '#0b6e4f',
  data_store: '#205493',
  threat: '#b1261e',
  control: '#8f3fa0',
  finding: '#c35c00',
};

function setBanner(message, tone = 'info') {
  const banner = document.getElementById('statusBanner');
  banner.textContent = message;
  if (tone === 'error') {
    banner.style.background = '#fdecea';
    banner.style.color = '#8a1d17';
  } else if (tone === 'ok') {
    banner.style.background = '#e9f7ef';
    banner.style.color = '#1e6f43';
  } else {
    banner.style.background = '#eef5f8';
    banner.style.color = '#1e445f';
  }
}

function buildHeaders() {
  const headers = {};
  const token = document.getElementById('authToken').value.trim();
  const role = document.getElementById('devRole').value.trim();
  if (token) {
    headers.Authorization = token.toLowerCase().startsWith('bearer ') ? token : `Bearer ${token}`;
  } else if (role) {
    headers['x-role'] = role;
  }
  return headers;
}

async function apiGet(path) {
  const res = await fetch(path, { headers: buildHeaders() });
  if (!res.ok) {
    let detail = `${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      detail = `${res.status}`;
    }
    throw new Error(`request failed (${path}): ${detail}`);
  }
  return res.json();
}

function severityClass(sev) {
  const normalized = String(sev || '').toLowerCase();
  return `sev-${normalized}`;
}

function renderKpis(health, risk) {
  document.getElementById('kpiHealth').textContent = health?.status || '-';
  document.getElementById('kpiDecision').textContent = risk?.decision?.result || '-';
  document.getElementById('kpiScore').textContent = String(risk?.score ?? '-');
  document.getElementById('kpiFindings').textContent = String((risk?.findings || []).length);
}

function renderCoverage(compliance) {
  const root = document.getElementById('coveragePanel');
  root.innerHTML = '';
  const frameworks = compliance?.frameworks || {};
  Object.entries(frameworks).forEach(([name, stats]) => {
    const row = document.createElement('div');
    row.className = 'coverage-row';
    const pct = Number(stats.percent || 0);
    const label = document.createElement('span');
    label.textContent = name;

    const progress = document.createElement('div');
    progress.className = 'progress';
    const progressFill = document.createElement('span');
    progressFill.style.width = `${pct}%`;
    progress.appendChild(progressFill);

    const value = document.createElement('strong');
    value.textContent = `${pct}%`;

    row.appendChild(label);
    row.appendChild(progress);
    row.appendChild(value);
    root.appendChild(row);
  });
  if (Object.keys(frameworks).length === 0) {
    const empty = document.createElement('span');
    empty.className = 'muted';
    empty.textContent = 'No compliance data for selected release.';
    root.appendChild(empty);
  }
}

function renderFindings(risk) {
  const tbody = document.getElementById('findingsTableBody');
  tbody.innerHTML = '';
  const findings = risk?.findings || [];
  if (!findings.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 4;
    cell.textContent = 'No findings for this release.';
    row.appendChild(cell);
    tbody.appendChild(row);
    return;
  }

  findings.slice(0, 150).forEach((f) => {
    const row = document.createElement('tr');

    const idCell = document.createElement('td');
    idCell.textContent = f.id || '-';

    const sourceCell = document.createElement('td');
    sourceCell.textContent = f.source || '-';

    const sevCell = document.createElement('td');
    sevCell.className = severityClass(f.severity);
    sevCell.textContent = f.severity || '-';

    const statusCell = document.createElement('td');
    statusCell.textContent = f.status || '-';

    row.appendChild(idCell);
    row.appendChild(sourceCell);
    row.appendChild(sevCell);
    row.appendChild(statusCell);
    tbody.appendChild(row);
  });
}

function renderLegend(nodeTypes) {
  const legend = document.getElementById('legend');
  legend.innerHTML = '';
  nodeTypes.forEach((type) => {
    const el = document.createElement('span');
    el.className = 'legend-item';
    const dot = document.createElement('span');
    dot.className = 'legend-dot';
    dot.style.background = GRAPH_COLORS[type] || '#5b6b77';
    const label = document.createElement('span');
    label.textContent = type;
    el.appendChild(dot);
    el.appendChild(label);
    legend.appendChild(el);
  });
}

function renderGraph(graph) {
  const svg = document.getElementById('graphCanvas');
  svg.innerHTML = '';

  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];

  if (!nodes.length) {
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', '20');
    text.setAttribute('y', '35');
    text.setAttribute('fill', '#607283');
    text.textContent = 'No graph data for selected service.';
    svg.appendChild(text);
    renderLegend([]);
    return;
  }

  const width = 900;
  const height = 430;
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(width, height) * 0.34;

  const nodePos = new Map();
  nodes.forEach((node, idx) => {
    const a = (Math.PI * 2 * idx) / Math.max(nodes.length, 1);
    const x = cx + Math.cos(a) * radius;
    const y = cy + Math.sin(a) * radius;
    nodePos.set(node.id, { x, y, node });
  });

  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  const marker = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
  marker.setAttribute('id', 'arrow');
  marker.setAttribute('markerWidth', '8');
  marker.setAttribute('markerHeight', '8');
  marker.setAttribute('refX', '7');
  marker.setAttribute('refY', '4');
  marker.setAttribute('orient', 'auto');
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', 'M0,0 L8,4 L0,8 z');
  path.setAttribute('fill', '#8aa0b3');
  marker.appendChild(path);
  defs.appendChild(marker);
  svg.appendChild(defs);

  edges.forEach((edge) => {
    const source = nodePos.get(edge.source);
    const target = nodePos.get(edge.target);
    if (!source || !target) return;

    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', source.x);
    line.setAttribute('y1', source.y);
    line.setAttribute('x2', target.x);
    line.setAttribute('y2', target.y);
    line.setAttribute('stroke', '#8aa0b3');
    line.setAttribute('stroke-width', '1.2');
    line.setAttribute('marker-end', 'url(#arrow)');
    svg.appendChild(line);
  });

  nodes.forEach((node) => {
    const pos = nodePos.get(node.id);

    const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', pos.x);
    circle.setAttribute('cy', pos.y);
    circle.setAttribute('r', '18');
    circle.setAttribute('fill', GRAPH_COLORS[node.node_type] || '#5b6b77');
    circle.setAttribute('opacity', '0.95');
    group.appendChild(circle);

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', pos.x);
    text.setAttribute('y', pos.y + 34);
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('font-size', '11');
    text.setAttribute('fill', '#2b3f50');
    text.textContent = node.label;
    group.appendChild(text);

    const risk = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    risk.setAttribute('x', pos.x);
    risk.setAttribute('y', pos.y + 5);
    risk.setAttribute('text-anchor', 'middle');
    risk.setAttribute('font-size', '10');
    risk.setAttribute('fill', '#ffffff');
    risk.textContent = String(node.risk_score ?? '');
    group.appendChild(risk);

    svg.appendChild(group);
  });

  renderLegend(Array.from(new Set(nodes.map((n) => n.node_type))).sort());
}

async function loadReleaseData() {
  const releaseId = document.getElementById('releaseId').value.trim();
  const serviceId = document.getElementById('serviceId').value.trim();

  if (!releaseId) {
    setBanner('release id is required', 'error');
    return;
  }

  setBanner('Loading release, compliance, and graph...', 'info');
  try {
    const [health, risk, compliance, graph] = await Promise.all([
      apiGet('/health'),
      apiGet(`/api/v1/risk/release/${encodeURIComponent(releaseId)}`),
      apiGet(`/api/v1/compliance/release/${encodeURIComponent(releaseId)}`),
      apiGet(`/api/v1/graph/service/${encodeURIComponent(serviceId)}`),
    ]);

    renderKpis(health, risk);
    renderCoverage(compliance);
    renderFindings(risk);
    renderGraph(graph);

    document.getElementById('releaseOut').textContent = JSON.stringify({ risk, compliance }, null, 2);
    setBanner('Release snapshot loaded', 'ok');
  } catch (err) {
    setBanner(err.message, 'error');
  }
}

async function refreshGraphOnly() {
  const serviceId = document.getElementById('serviceId').value.trim();
  if (!serviceId) {
    setBanner('service id is required', 'error');
    return;
  }

  setBanner('Refreshing graph...', 'info');
  try {
    const graph = await apiGet(`/api/v1/graph/service/${encodeURIComponent(serviceId)}`);
    renderGraph(graph);
    setBanner('Graph refreshed', 'ok');
  } catch (err) {
    setBanner(err.message, 'error');
  }
}

async function loadJob() {
  const jobId = document.getElementById('jobId').value.trim();
  if (!jobId) {
    setBanner('job id is required', 'error');
    return;
  }

  setBanner('Loading job...', 'info');
  try {
    const job = await apiGet(`/api/v1/jobs/${encodeURIComponent(jobId)}`);
    document.getElementById('jobOut').textContent = JSON.stringify(job, null, 2);
    setBanner(`Job ${job.status}`, job.status === 'failed' ? 'error' : 'ok');
  } catch (err) {
    setBanner(err.message, 'error');
  }
}

function register() {
  document.getElementById('loadRelease').addEventListener('click', loadReleaseData);
  document.getElementById('refreshGraph').addEventListener('click', refreshGraphOnly);
  document.getElementById('loadJob').addEventListener('click', loadJob);
}

register();
loadReleaseData();
