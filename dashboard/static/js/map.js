"use strict";

let markerLayer = null;
let mapRefreshTimer = null;
let mapInitializing = false;

const TILE_PROVIDERS = [
  {
    name: "CARTO",
    url: "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
    options: {
      attribution: "&copy; OpenStreetMap contributors &copy; CARTO",
      subdomains: "abcd",
      maxZoom: 19,
    },
  },
  {
    name: "OpenStreetMap",
    url: "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
    options: {
      attribution: "&copy; OpenStreetMap contributors",
      maxZoom: 19,
    },
  },
];

function setMapStatus(state, message) {
  const status = document.getElementById("map-status");
  const text = document.getElementById("map-status-text");
  if (!status || !text) return;
  status.dataset.state = state;
  text.textContent = message;
}

function addSentinelTiles(map, callbacks = {}) {
  let activeLayer = null;
  let providerIndex = 0;
  let errorCount = 0;
  let settled = false;
  let providerTimer = null;

  const settle = (provider) => {
    if (settled) return;
    settled = true;
    clearTimeout(providerTimer);
    callbacks.onReady?.(provider.name);
  };

  const loadProvider = (index) => {
    const provider = TILE_PROVIDERS[index];
    if (!provider) {
      callbacks.onError?.("Map tiles could not be loaded. Check your internet connection.");
      return;
    }

    providerIndex = index;
    errorCount = 0;
    settled = false;
    if (activeLayer) map.removeLayer(activeLayer);
    activeLayer = L.tileLayer(provider.url, provider.options);
    activeLayer.once("load", () => settle(provider));
    activeLayer.on("tileerror", () => {
      errorCount += 1;
      if (errorCount >= 3 && providerIndex + 1 < TILE_PROVIDERS.length) {
        clearTimeout(providerTimer);
        loadProvider(providerIndex + 1);
      } else if (errorCount >= 6) {
        clearTimeout(providerTimer);
        callbacks.onError?.("Map tiles could not be loaded. Check your internet connection.");
      }
    });
    activeLayer.addTo(map);

    clearTimeout(providerTimer);
    providerTimer = setTimeout(() => {
      if (!settled && providerIndex + 1 < TILE_PROVIDERS.length) {
        loadProvider(providerIndex + 1);
      }
    }, 7000);
  };

  loadProvider(0);
  return () => clearTimeout(providerTimer);
}

function markerColor(item) {
  if (Number(item.abuse_score) > 50 || Number(item.is_known_attacker) === 1) {
    return "#ef6a62";
  }
  if (Number(item.abuse_score) > 20) return "#e1a447";
  return "#42b8a0";
}

function createPopup(item, marker) {
  const container = document.createElement("div");
  container.className = "map-popup";

  const title = document.createElement("h3");
  title.textContent = `${item.flag || ""} ${item.country || "Unknown"}`.trim();
  container.appendChild(title);

  [
    `${item.city || "Unknown city"}, ${item.region || "Unknown region"}`,
    `ISP: ${item.isp || "Unknown"}`,
    `Organisation: ${item.org || "Unknown"}`,
    `Timezone: ${item.timezone || "Unknown"}`,
    `Attacks: ${Number(item.count) || 0}`,
    `Abuse score: ${Number(item.abuse_score) || 0}`,
  ].forEach((text) => {
    const line = document.createElement("p");
    line.textContent = text;
    container.appendChild(line);
  });

  const actions = document.createElement("div");
  actions.className = "map-actions";
  const profileButton = document.createElement("button");
  profileButton.className = "action-button";
  profileButton.textContent = "View Full Profile";
  profileButton.addEventListener("click", () => window.openAttackerModal(item.ip));

  const zoomButton = document.createElement("button");
  zoomButton.className = "action-button";
  zoomButton.textContent = "Street Zoom";
  zoomButton.addEventListener("click", () => {
    window.attackMapInstance.setView(marker.getLatLng(), 12);
    marker.closePopup();
  });
  actions.append(profileButton, zoomButton);
  container.appendChild(actions);
  return container;
}

async function refreshAttackMap() {
  if (!window.attackMapInstance || !markerLayer) return;
  try {
    const points = await window.apiFetch("/api/map");
    markerLayer.clearLayers();
    let plotted = 0;

    points.forEach((item) => {
      if (item.lat === null || item.lon === null) return;
      const latitude = Number(item.lat);
      const longitude = Number(item.lon);
      if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) return;

      const color = markerColor(item);
      const marker = L.circleMarker([latitude, longitude], {
        radius: Math.min(22, 5 + Math.sqrt(Number(item.count) || 1) * 2.2),
        color,
        weight: 1.5,
        fillColor: color,
        fillOpacity: 0.72,
      });
      marker.bindPopup(createPopup(item, marker), { maxWidth: 310 });
      marker.addTo(markerLayer);
      plotted += 1;
    });

    if (plotted === 0) {
      setMapStatus(
        "empty",
        "Map is online. Public attacker locations will appear after GeoIP enrichment."
      );
    } else {
      setMapStatus("ready", `${plotted} attacker location${plotted === 1 ? "" : "s"} plotted`);
    }
  } catch (error) {
    setMapStatus("error", `Attack data could not be loaded: ${error.message}`);
    window.showToast(`Map refresh failed: ${error.message}`);
  }
}

function initializeAttackMap() {
  if (window.attackMapInstance || mapInitializing) return;
  mapInitializing = true;

  if (!window.L) {
    setMapStatus("error", "Leaflet did not load. Check your internet connection and refresh.");
    mapInitializing = false;
    return;
  }

  const container = document.getElementById("main-map");
  if (!container || container.clientWidth === 0 || container.clientHeight === 0) {
    mapInitializing = false;
    setTimeout(activateAttackMap, 100);
    return;
  }

  try {
    window.attackMapInstance = L.map(container, {
      center: [22, 0],
      zoom: 2,
      minZoom: 2,
      worldCopyJump: true,
      preferCanvas: true,
    });
    markerLayer = L.layerGroup().addTo(window.attackMapInstance);
    addSentinelTiles(window.attackMapInstance, {
      onReady: () => refreshAttackMap(),
      onError: (message) => setMapStatus("error", message),
    });
    mapRefreshTimer = setInterval(refreshAttackMap, 30000);
    setTimeout(() => window.attackMapInstance.invalidateSize(true), 50);
  } catch (error) {
    window.attackMapInstance = null;
    setMapStatus("error", `Map initialization failed: ${error.message}`);
  } finally {
    mapInitializing = false;
  }
}

function activateAttackMap() {
  if (!window.attackMapInstance) {
    setMapStatus("loading", "Loading map tiles and attacker locations");
    setTimeout(initializeAttackMap, 40);
    return;
  }
  setTimeout(() => {
    window.attackMapInstance.invalidateSize(true);
    refreshAttackMap();
  }, 50);
}

window.addSentinelTiles = addSentinelTiles;
window.activateAttackMap = activateAttackMap;
window.refreshAttackMap = refreshAttackMap;

window.addEventListener("beforeunload", () => {
  if (mapRefreshTimer) clearInterval(mapRefreshTimer);
});
