"use strict";

let miniMapInstance = null;
let miniMapSequence = 0;
let toastTimer = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function valueOrUnknown(value, fallback = "Unknown") {
  return value === null || value === undefined || value === "" ? fallback : value;
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value) || 0);
}

function formatTime(value) {
  if (!value) return "N/A";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function scoreClass(score) {
  if (Number(score) > 50) return "badge-danger";
  if (Number(score) > 20) return "badge-warning";
  return "badge-success";
}

function rowThreatClass(score) {
  if (Number(score) > 50) return "row-high";
  if (Number(score) > 20) return "row-medium";
  return "row-low";
}

function scoreBadge(score) {
  return `<span class="badge ${scoreClass(score)}">${Number(score) || 0}</span>`;
}

function emptyRow(columns, message) {
  return `<tr><td class="empty-state" colspan="${columns}">${escapeHtml(message)}</td></tr>`;
}

async function apiFetch(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error || `Request failed (${response.status})`);
  }
  return response.json();
}

function showToast(message) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 3500);
}

function renderStats(stats) {
  document.getElementById("stat-total").textContent = formatNumber(stats.total_events);
  document.getElementById("stat-unique").textContent = formatNumber(stats.unique_attackers);
  document.getElementById("stat-known").textContent = formatNumber(stats.known_attackers);
  document.getElementById("stat-countries").textContent = formatNumber(stats.total_countries);
  document.getElementById("stat-region").textContent =
    stats.attacks_by_region?.[0]?.region || "N/A";

  const usernames = document.getElementById("top-usernames");
  usernames.innerHTML = stats.top_usernames?.length
    ? stats.top_usernames.map((item) => `
      <tr><td class="mono">${escapeHtml(item.username)}</td><td>${formatNumber(item.count)}</td></tr>
    `).join("")
    : emptyRow(2, "No username attempts captured yet");

  const passwords = document.getElementById("top-passwords");
  passwords.innerHTML = stats.top_passwords?.length
    ? stats.top_passwords.map((item) => `
      <tr><td class="mono">${escapeHtml(item.password)}</td><td>${formatNumber(item.count)}</td></tr>
    `).join("")
    : emptyRow(2, "No password attempts captured yet");
}

function bindIpLinks(container = document) {
  container.querySelectorAll("[data-attacker-ip]").forEach((element) => {
    element.addEventListener("click", () => openAttackerModal(element.dataset.attackerIp));
  });
}

function renderEvents(events) {
  const table = document.getElementById("events-table");
  table.innerHTML = events.length
    ? events.map((event) => `
      <tr class="${rowThreatClass(event.abuse_score)}">
        <td>${escapeHtml(formatTime(event.timestamp))}</td>
        <td><button class="ip-link" data-attacker-ip="${escapeHtml(event.ip_address)}">${escapeHtml(event.ip_address)}</button></td>
        <td><span class="flag">${escapeHtml(event.country_flag || "")}</span>${escapeHtml(valueOrUnknown(event.country))}</td>
        <td>${escapeHtml(valueOrUnknown(event.city))}</td>
        <td><span class="badge service-badge">${escapeHtml(event.service)}</span></td>
        <td class="mono">${escapeHtml(valueOrUnknown(event.username_tried, "-"))}</td>
        <td class="mono">${escapeHtml(valueOrUnknown(event.password_tried, "-"))}</td>
        <td>${scoreBadge(event.abuse_score)}</td>
      </tr>
    `).join("")
    : emptyRow(8, "Waiting for the first honeypot interaction");
  bindIpLinks(table);
}

function asList(value) {
  if (Array.isArray(value)) return value;
  return String(value || "").split(",").filter(Boolean);
}

function renderProfiles(profiles) {
  const table = document.getElementById("profiles-table");
  table.innerHTML = profiles.length
    ? profiles.map((profile) => `
      <tr class="${profile.is_flagged ? "row-high" : rowThreatClass(profile.abuse_score)}"
          data-profile-ip="${escapeHtml(profile.ip_address)}">
        <td><button class="ip-link" data-attacker-ip="${escapeHtml(profile.ip_address)}">${escapeHtml(profile.ip_address)}</button></td>
        <td><span class="flag">${escapeHtml(profile.country_flag || "")}</span>${escapeHtml(valueOrUnknown(profile.country))}</td>
        <td>${escapeHtml(valueOrUnknown(profile.city))}</td>
        <td>${escapeHtml(valueOrUnknown(profile.region))}</td>
        <td>${escapeHtml(formatTime(profile.first_seen))}</td>
        <td>${escapeHtml(formatTime(profile.last_seen))}</td>
        <td>${formatNumber(profile.total_attempts)}</td>
        <td>${asList(profile.services_targeted).map((service) =>
          `<span class="badge service-badge">${escapeHtml(service)}</span>`).join(" ") || "-"}</td>
        <td>${scoreBadge(profile.abuse_score)}</td>
        <td>${profile.is_flagged
          ? '<span class="badge badge-danger">Flagged</span>'
          : '<span class="badge badge-success">Watching</span>'}</td>
      </tr>
    `).join("")
    : emptyRow(10, "Attacker profiles will appear after enrichment");
  bindIpLinks(table);
  table.querySelectorAll("[data-profile-ip]").forEach((row) => {
    row.addEventListener("click", (event) => {
      if (!event.target.closest("button")) openAttackerModal(row.dataset.profileIp);
    });
  });
}

function renderAlerts(alerts) {
  const list = document.getElementById("alerts-list");
  if (!alerts.length) {
    list.innerHTML = '<div class="empty-state">No high-risk alerts detected</div>';
    return;
  }
  list.innerHTML = alerts.map((event) => {
    const reason = Number(event.abuse_score) > 50
      ? `AbuseIPDB confidence score is ${Number(event.abuse_score)}`
      : "Repeated activity crossed the alert threshold";
    return `
      <article class="alert-item">
        <div class="alert-icon">!</div>
        <div class="alert-main">
          <strong><button class="ip-link" data-attacker-ip="${escapeHtml(event.ip_address)}">${escapeHtml(event.ip_address)}</button></strong>
          <span>${escapeHtml(formatTime(event.timestamp))} &middot; ${escapeHtml(event.service)}</span>
        </div>
        <div class="alert-reason">
          <span class="flag">${escapeHtml(event.country_flag || "")}</span>
          ${escapeHtml(valueOrUnknown(event.city))}, ${escapeHtml(valueOrUnknown(event.country))}
          &middot; ${escapeHtml(reason)}
        </div>
        ${scoreBadge(event.abuse_score)}
      </article>
    `;
  }).join("");
  bindIpLinks(list);
}

function coordinateLabel(value, positive, negative) {
  const number = coordinateNumber(value);
  if (number === null) return "Unknown";
  return `${Math.abs(number).toFixed(4)}\u00B0 ${number >= 0 ? positive : negative}`;
}

function coordinateNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function closeAttackerModal() {
  const modal = document.getElementById("attacker-modal");
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
  if (miniMapInstance) {
    miniMapInstance.remove();
    miniMapInstance = null;
  }
}

async function openAttackerModal(ipAddress) {
  const modal = document.getElementById("attacker-modal");
  const body = document.getElementById("modal-body");
  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
  body.innerHTML = '<div class="loading"><span class="spinner"></span> Loading attacker profile</div>';

  try {
    const profile = await apiFetch(`/api/attacker/${encodeURIComponent(ipAddress)}`);
    const mapId = `mini-map-${++miniMapSequence}`;
    const latitude = coordinateNumber(profile.latitude);
    const longitude = coordinateNumber(profile.longitude);
    const hasCoordinates = latitude !== null && longitude !== null;
    body.innerHTML = `
      <header class="modal-header">
        <p class="eyebrow">Attacker profile</p>
        <h2 id="modal-title"><span class="flag">${escapeHtml(profile.country_flag || "")}</span>${escapeHtml(profile.ip_address)} &middot; ${escapeHtml(valueOrUnknown(profile.country))}</h2>
      </header>
      <div class="modal-grid">
        <div>
          <section class="location-card">
            <div class="location-title"><span class="flag">${escapeHtml(profile.country_flag || "")}</span>${escapeHtml(valueOrUnknown(profile.country))}</div>
            <dl class="detail-list">
              <dt>Region</dt><dd>${escapeHtml(valueOrUnknown(profile.region))}</dd>
              <dt>City</dt><dd>${escapeHtml(valueOrUnknown(profile.city))}</dd>
              <dt>ISP</dt><dd>${escapeHtml(valueOrUnknown(profile.isp))}</dd>
              <dt>Org</dt><dd>${escapeHtml(valueOrUnknown(profile.org))}</dd>
              <dt>Timezone</dt><dd>${escapeHtml(valueOrUnknown(profile.timezone))}</dd>
              <dt>ZIP</dt><dd>${escapeHtml(valueOrUnknown(profile.zip_code))}</dd>
              <dt>Coords</dt><dd>${escapeHtml(coordinateLabel(profile.latitude, "N", "S"))},
                ${escapeHtml(coordinateLabel(profile.longitude, "E", "W"))}</dd>
            </dl>
          </section>
          ${hasCoordinates ? `<div id="${mapId}" class="mini-map"></div>` : ""}
        </div>
        <section class="profile-stats">
          <div class="profile-stat"><span>First seen</span><strong>${escapeHtml(formatTime(profile.first_seen))}</strong></div>
          <div class="profile-stat"><span>Last seen</span><strong>${escapeHtml(formatTime(profile.last_seen))}</strong></div>
          <div class="profile-stat"><span>Total attempts</span><strong>${formatNumber(profile.total_attempts)}</strong></div>
          <div class="profile-stat"><span>Services targeted</span><strong>${escapeHtml(asList(profile.services_targeted).join(", ") || "N/A")}</strong></div>
          <div class="profile-stat"><span>Abuse score</span><strong>${scoreBadge(profile.abuse_score)}</strong></div>
          <div class="profile-stat"><span>Status</span><strong>${profile.is_flagged
            ? '<span class="badge badge-danger">Flagged</span>'
            : '<span class="badge badge-success">Watching</span>'}</strong></div>
        </section>
      </div>
      <section class="modal-history">
        <h3>Recent history</h3>
        <div class="table-scroll">
          <table>
            <thead><tr><th>Time</th><th>Service</th><th>Username</th><th>Password</th><th>Command / Request</th></tr></thead>
            <tbody>
              ${(profile.events || []).length
                ? profile.events.map((event) => `
                  <tr>
                    <td>${escapeHtml(formatTime(event.timestamp))}</td>
                    <td><span class="badge service-badge">${escapeHtml(event.service)}</span></td>
                    <td class="mono">${escapeHtml(valueOrUnknown(event.username_tried, "-"))}</td>
                    <td class="mono">${escapeHtml(valueOrUnknown(event.password_tried, "-"))}</td>
                    <td class="mono">${escapeHtml(valueOrUnknown(event.command_tried, "-"))}</td>
                  </tr>`).join("")
                : emptyRow(5, "No event history available")}
            </tbody>
          </table>
        </div>
      </section>
    `;

    if (hasCoordinates && window.L) {
      miniMapInstance = L.map(mapId, {
        center: [latitude, longitude],
        zoom: 10,
        zoomControl: false,
        attributionControl: false,
        dragging: false,
        scrollWheelZoom: false,
        doubleClickZoom: false,
        boxZoom: false,
        keyboard: false,
        tap: false,
      });
      if (typeof window.addSentinelTiles === "function") {
        window.addSentinelTiles(miniMapInstance);
      } else {
        L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
          maxZoom: 19,
          attribution: "&copy; OpenStreetMap contributors",
        }).addTo(miniMapInstance);
      }
      L.circleMarker([latitude, longitude], {
        radius: 7,
        color: "#ef6a62",
        fillColor: "#ef6a62",
        fillOpacity: 0.9,
      }).addTo(miniMapInstance);
    }
  } catch (error) {
    body.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
  }
}

async function refreshDashboard() {
  try {
    const [stats, events, profiles, alerts] = await Promise.all([
      apiFetch("/api/stats"),
      apiFetch("/api/events?limit=50"),
      apiFetch("/api/attackers"),
      apiFetch("/api/alerts"),
    ]);
    renderStats(stats);
    renderEvents(events);
    renderProfiles(profiles);
    renderAlerts(alerts);
    if (typeof window.updateDashboardCharts === "function") {
      window.updateDashboardCharts(stats);
    }
  } catch (error) {
    showToast(`Dashboard refresh failed: ${error.message}`);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".tab-button").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".tab-button").forEach((item) => item.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      document.getElementById(button.dataset.tab).classList.add("active");
      if (button.dataset.tab === "attack-map") {
        requestAnimationFrame(() => {
          if (typeof window.activateAttackMap === "function") {
            window.activateAttackMap();
          }
        });
      }
    });
  });

  document.querySelectorAll("[data-close-modal]").forEach((element) => {
    element.addEventListener("click", closeAttackerModal);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeAttackerModal();
  });

  refreshDashboard();
  setInterval(refreshDashboard, 10000);
});

window.apiFetch = apiFetch;
window.escapeHtml = escapeHtml;
window.openAttackerModal = openAttackerModal;
window.showToast = showToast;
