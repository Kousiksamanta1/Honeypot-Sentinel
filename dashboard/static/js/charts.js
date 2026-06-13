"use strict";

const dashboardCharts = {};

function chartColors() {
  const styles = getComputedStyle(document.documentElement);
  return {
    accent: styles.getPropertyValue("--accent").trim(),
    accentBright: styles.getPropertyValue("--accent-bright").trim(),
    secondary: styles.getPropertyValue("--secondary").trim(),
    danger: styles.getPropertyValue("--danger").trim(),
    warning: styles.getPropertyValue("--warning").trim(),
    success: styles.getPropertyValue("--success").trim(),
    panel: styles.getPropertyValue("--panel").trim(),
    border: styles.getPropertyValue("--border").trim(),
    heading: styles.getPropertyValue("--heading").trim(),
    text: styles.getPropertyValue("--text").trim(),
    muted: styles.getPropertyValue("--muted").trim(),
  };
}

function chartBaseOptions() {
  const colors = chartColors();
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 350 },
    plugins: {
      legend: {
        labels: { color: colors.muted, boxWidth: 12, usePointStyle: true },
      },
      tooltip: {
        backgroundColor: colors.panel,
        borderColor: colors.border,
        borderWidth: 1,
        titleColor: colors.heading,
        bodyColor: colors.text,
      },
    },
    scales: {
      x: {
        ticks: { color: colors.muted },
        grid: { color: "rgba(42, 56, 51, 0.55)" },
      },
      y: {
        beginAtZero: true,
        ticks: { color: colors.muted, precision: 0 },
        grid: { color: "rgba(42, 56, 51, 0.55)" },
      },
    },
  };
}

function initializeCharts() {
  if (!window.Chart) return;
  const colors = chartColors();
  dashboardCharts.countries = new Chart(document.getElementById("countries-chart"), {
    type: "bar",
    data: {
      labels: [],
      datasets: [{
        label: "Attacks",
        data: [],
        backgroundColor: "rgba(213, 169, 79, 0.68)",
        borderColor: colors.accentBright,
        borderWidth: 1,
        borderRadius: 4,
      }],
    },
    options: chartBaseOptions(),
  });

  const serviceOptions = chartBaseOptions();
  delete serviceOptions.scales;
  serviceOptions.plugins.legend.position = "bottom";
  dashboardCharts.services = new Chart(document.getElementById("services-chart"), {
    type: "doughnut",
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: [
          colors.secondary,
          colors.accent,
          colors.warning,
          colors.danger,
        ],
        borderColor: colors.panel,
        borderWidth: 3,
      }],
    },
    options: { ...serviceOptions, cutout: "68%" },
  });

  dashboardCharts.hourly = new Chart(document.getElementById("hourly-chart"), {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "Attacks",
        data: [],
        borderColor: colors.secondary,
        backgroundColor: "rgba(66, 184, 160, 0.11)",
        fill: true,
        tension: 0.35,
        pointRadius: 2,
        pointHoverRadius: 5,
      }],
    },
    options: chartBaseOptions(),
  });
}

function updateDashboardCharts(stats) {
  if (!dashboardCharts.countries) return;

  dashboardCharts.countries.data.labels = (stats.top_countries || []).map(
    (item) => `${item.flag || ""} ${item.country}`.trim()
  );
  dashboardCharts.countries.data.datasets[0].data = (stats.top_countries || []).map(
    (item) => item.count
  );
  dashboardCharts.countries.update();

  dashboardCharts.services.data.labels = (stats.top_services || []).map(
    (item) => item.service
  );
  dashboardCharts.services.data.datasets[0].data = (stats.top_services || []).map(
    (item) => item.count
  );
  dashboardCharts.services.update();

  dashboardCharts.hourly.data.labels = (stats.events_per_hour || []).map((item) => {
    const date = new Date(item.hour);
    return Number.isNaN(date.getTime())
      ? item.hour
      : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  });
  dashboardCharts.hourly.data.datasets[0].data = (stats.events_per_hour || []).map(
    (item) => item.count
  );
  dashboardCharts.hourly.update();
}

document.addEventListener("DOMContentLoaded", initializeCharts);
window.updateDashboardCharts = updateDashboardCharts;
