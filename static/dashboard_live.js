const dashboard = document.querySelector("[data-dashboard-live]");

if (dashboard) {
  const liveLabel = document.querySelector("#dashboard-live-label");

  function setValue(name, value) {
    const element = dashboard.querySelector(`[data-dashboard-value="${name}"]`);
    if (!element) return;
    element.textContent = name === "loss"
      ? `R ${Number(value || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
      : Number(value || 0).toLocaleString();
  }

  function renderBreakdown(containerId, emptyId, items, key, total) {
    const container = document.getElementById(containerId);
    const empty = document.getElementById(emptyId);
    container.replaceChildren();
    empty.hidden = items.length > 0;

    for (const item of items) {
      const row = document.createElement("div");
      row.className = "category-item";
      const heading = document.createElement("div");
      const label = document.createElement("span");
      const count = document.createElement("strong");
      label.textContent = item[key] || "Unclassified";
      count.textContent = Number(item.total).toLocaleString();
      heading.append(label, count);
      const track = document.createElement("div");
      track.className = "category-track";
      const bar = document.createElement("i");
      bar.style.width = `${total ? (item.total / total) * 100 : 0}%`;
      track.append(bar);
      row.append(heading, track);
      container.append(row);
    }
  }

  function renderRecent(reports) {
    const body = document.getElementById("dashboard-recent-body");
    const table = document.getElementById("dashboard-recent-table");
    const empty = document.getElementById("dashboard-recent-empty");
    body.replaceChildren();
    table.hidden = reports.length === 0;
    empty.hidden = reports.length > 0;

    for (const report of reports) {
      const row = document.createElement("tr");
      const referenceCell = document.createElement("td");
      const reference = document.createElement("a");
      reference.className = "report-id";
      reference.href = report.url;
      reference.textContent = `#${String(report.id).padStart(4, "0")}`;
      const date = document.createElement("small");
      date.className = "cell-sub";
      date.textContent = report.created_at;
      referenceCell.append(reference, date);

      const incidentCell = document.createElement("td");
      const category = document.createElement("strong");
      category.textContent = report.scam_type;
      const location = document.createElement("small");
      location.className = "cell-sub";
      location.textContent = `${report.province} · ${report.platform}`;
      incidentCell.append(category, location);

      const riskCell = document.createElement("td");
      const risk = document.createElement("span");
      risk.className = `risk-badge risk-badge-${String(report.risk_level).toLowerCase()}`;
      risk.textContent = report.risk_level;
      riskCell.append(risk);

      const statusCell = document.createElement("td");
      const status = document.createElement("span");
      status.className = "status-text";
      status.textContent = report.status;
      statusCell.append(status);

      const actionCell = document.createElement("td");
      const action = document.createElement("a");
      action.className = "row-arrow";
      action.href = report.url;
      action.setAttribute("aria-label", "Open report");
      action.textContent = "→";
      actionCell.append(action);
      row.append(referenceCell, incidentCell, riskCell, statusCell, actionCell);
      body.append(row);
    }
  }

  async function refreshDashboard() {
    try {
      const response = await fetch(dashboard.dataset.liveUrl, { cache: "no-store" });
      if (!response.ok) throw new Error("Dashboard refresh failed");
      const data = await response.json();
      for (const name of ["total", "high", "medium", "open_cases", "loss"]) {
        setValue(name, data[name]);
      }
      renderRecent(data.recent);
      renderBreakdown("dashboard-category-list", "dashboard-category-empty", data.categories, "scam_type", data.total);
      renderBreakdown("dashboard-province-list", "dashboard-province-empty", data.province_counts, "province", data.total);
      const updated = new Date(data.updated_at).toLocaleTimeString();
      liveLabel.textContent = `Live · Updated ${updated}`;
    } catch {
      liveLabel.textContent = "Live update unavailable · retrying";
    }
  }

  refreshDashboard();
  window.setInterval(refreshDashboard, 15000);
}