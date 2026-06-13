"use strict";

function locationEmptyRow(columns, message) {
  return `<tr><td class="empty-state" colspan="${columns}">${window.escapeHtml(message)}</td></tr>`;
}

function renderLocationSummary(data) {
  document.getElementById("location-summary").innerHTML = `
    <div class="summary-item"><span>Coverage</span><strong>Attacks from ${Number(data.total_countries) || 0} countries</strong></div>
    <div class="summary-item"><span>Most active region</span><strong>${window.escapeHtml(data.most_active_region || "N/A")}</strong></div>
    <div class="summary-item"><span>Most active timezone</span><strong>${window.escapeHtml(data.most_active_timezone || "N/A")}</strong></div>
  `;
}

function renderCountryLeaderboard(data) {
  const table = document.getElementById("country-leaderboard");
  const total = (data.countries || []).reduce((sum, country) => sum + Number(country.count || 0), 0);
  if (!data.countries?.length) {
    table.innerHTML = locationEmptyRow(7, "No geolocated attack data is available yet");
    return;
  }

  table.innerHTML = data.countries.map((country, index) => {
    const percentage = total ? (Number(country.count) / total) * 100 : 0;
    const topCity = country.cities?.[0]?.city || "Unknown";
    const cityChips = country.cities?.length
      ? country.cities.map((city) => `
          <div class="city-chip"><strong>${window.escapeHtml(city.city)}</strong>${Number(city.count) || 0} attacks</div>
        `).join("")
      : '<div class="city-chip"><strong>No city data</strong>Location is country-level only</div>';
    return `
      <tr class="country-row" data-country-row="${index}" tabindex="0">
        <td><span class="flag">${window.escapeHtml(country.flag || "")}</span></td>
        <td>${window.escapeHtml(country.country)}</td>
        <td>${window.escapeHtml(country.region || "Unknown")}</td>
        <td>${Number(country.count) || 0}</td>
        <td>${window.escapeHtml(topCity)}</td>
        <td>${percentage.toFixed(1)}%</td>
        <td><div class="progress-track"><div class="progress-fill" style="width:${Math.max(2, percentage)}%"></div></div></td>
      </tr>
      <tr class="city-detail" data-country-detail="${index}" hidden>
        <td colspan="7"><div class="city-detail-inner">${cityChips}</div></td>
      </tr>
    `;
  }).join("");

  table.querySelectorAll("[data-country-row]").forEach((row) => {
    const toggle = () => {
      const detail = table.querySelector(`[data-country-detail="${row.dataset.countryRow}"]`);
      detail.hidden = !detail.hidden;
      row.setAttribute("aria-expanded", String(!detail.hidden));
    };
    row.addEventListener("click", toggle);
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        toggle();
      }
    });
  });
}

function renderTopCities(data) {
  const table = document.getElementById("top-cities");
  table.innerHTML = data.top_cities?.length
    ? data.top_cities.map((city) => `
      <tr>
        <td>${window.escapeHtml(city.city)}</td>
        <td><span class="flag">${window.escapeHtml(city.flag || "")}</span>${window.escapeHtml(city.country || "Unknown")}</td>
        <td>${Number(city.count) || 0}</td>
        <td>${window.escapeHtml(city.isp || "Unknown")}</td>
      </tr>
    `).join("")
    : locationEmptyRow(4, "No city-level data is available yet");
}

async function refreshLocations() {
  try {
    const data = await window.apiFetch("/api/locations");
    renderLocationSummary(data);
    renderCountryLeaderboard(data);
    renderTopCities(data);
  } catch (error) {
    window.showToast(`Location refresh failed: ${error.message}`);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  refreshLocations();
  setInterval(refreshLocations, 30000);
});

