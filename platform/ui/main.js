async function getJson(path) {
  const response = await fetch(path, { headers: { "x-role": "platform_admin" } });
  return response.json();
}

async function loadHealth() {
  const data = await getJson('/health');
  document.getElementById('health').innerText = data.status || 'unknown';
}

async function loadRelease() {
  const releaseId = document.getElementById('releaseId').value;
  const risk = await getJson(`/api/v1/risk/release/${releaseId}`);
  const compliance = await getJson(`/api/v1/compliance/release/${releaseId}`);
  document.getElementById('decision').innerText = risk.decision?.result || '-';
  document.getElementById('score').innerText = String(risk.score ?? '-');
  document.getElementById('releaseOut').innerText = JSON.stringify({ risk, compliance }, null, 2);
}

async function loadJob() {
  const jobId = document.getElementById('jobId').value;
  if (!jobId) return;
  const job = await getJson(`/api/v1/jobs/${jobId}`);
  document.getElementById('jobOut').innerText = JSON.stringify(job, null, 2);
}

document.getElementById('loadRelease').addEventListener('click', loadRelease);
document.getElementById('loadJob').addEventListener('click', loadJob);

loadHealth();
loadRelease();
