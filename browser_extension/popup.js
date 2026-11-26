const BASE_URL = "http://127.0.0.1:8990";

document.addEventListener("DOMContentLoaded", async () => {
  const statusBadge = document.getElementById("statusBadge");
  const tokenInput = document.getElementById("tokenInput");
  const btnSaveToken = document.getElementById("btnSaveToken");
  const btnAutoPair = document.getElementById("btnAutoPair");
  const chkAutoIntercept = document.getElementById("chkAutoIntercept");
  const numMinSize = document.getElementById("numMinSize");
  const chkMediaSniffer = document.getElementById("chkMediaSniffer");
  const mediaSection = document.getElementById("mediaSection");
  const mediaList = document.getElementById("mediaList");
  const urlInput = document.getElementById("urlInput");
  const btnSendUrl = document.getElementById("btnSendUrl");
  const msgLabel = document.getElementById("msgLabel");

  async function refreshConnectionStatus(token) {
    try {
      const ping = await fetch(`${BASE_URL}/api/ping`, {
        method: "GET",
        headers: token ? { "X-OmniFetch-Token": token } : {}
      });
      if (ping.ok) {
        statusBadge.textContent = "Connected";
        statusBadge.className = "badge online";
      } else if (ping.status === 401) {
        statusBadge.textContent = "Token Required";
        statusBadge.className = "badge offline";
      } else {
        statusBadge.textContent = "Offline";
        statusBadge.className = "badge offline";
      }
    } catch (err) {
      statusBadge.textContent = "Offline";
      statusBadge.className = "badge offline";
    }
  }

  async function refreshDetectedMedia() {
    if (!chkMediaSniffer.checked) {
      mediaSection.classList.add("hidden");
      return;
    }
    mediaSection.classList.remove("hidden");
    try {
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!activeTab) {
        mediaList.innerHTML = '<div class="media-empty">No active tab.</div>';
        return;
      }
      chrome.runtime.sendMessage({ action: "getTabMedia", tabId: activeTab.id }, (res) => {
        const items = (res && res.items) ? res.items : [];
        mediaList.innerHTML = "";
        if (items.length === 0) {
          mediaList.innerHTML = '<div class="media-empty">No media streams detected yet. Play or reload media.</div>';
          return;
        }
        for (const item of items) {
          const row = document.createElement("div");
          row.className = "media-item";

          const meta = document.createElement("div");
          meta.className = "media-meta";
          const szMb = item.sizeBytes > 0 ? ` (${(item.sizeBytes / (1024 * 1024)).toFixed(1)} MB)` : "";
          meta.textContent = `${item.filename} [${item.contentType}${szMb}]`;
          meta.title = item.url;

          const btn = document.createElement("button");
          btn.textContent = "Send";
          btn.className = "btn-mini";
          btn.addEventListener("click", () => {
            chrome.runtime.sendMessage(
              {
                action: "sendMediaItem",
                url: item.url,
                filename: item.filename,
                referer: activeTab.url || "",
                tabId: activeTab.id
              },
              (sendRes) => {
                if (sendRes && sendRes.ok) {
                  showMsg("Media sent to OmniFetch!");
                } else {
                  showMsg("Media send failed (check token/bridge)", true);
                }
              }
            );
          });

          row.appendChild(meta);
          row.appendChild(btn);
          mediaList.appendChild(row);
        }
      });
    } catch (e) {
      mediaList.innerHTML = '<div class="media-empty">Unable to read active tab media.</div>';
    }
  }

  // Load saved preferences & check connection status
  chrome.storage.local.get(["token", "autoIntercept", "minSizeMb", "mediaSniffer"], async (res) => {
    if (res.token) tokenInput.value = res.token;
    chkAutoIntercept.checked = !!res.autoIntercept;
    numMinSize.value = res.minSizeMb !== undefined ? res.minSizeMb : 0;
    chkMediaSniffer.checked = !!res.mediaSniffer;

    await refreshConnectionStatus(res.token);
    await refreshDetectedMedia();
  });

  // Save Token manually
  btnSaveToken.addEventListener("click", () => {
    const val = tokenInput.value.trim();
    chrome.storage.local.set({ token: val }, async () => {
      showMsg("Token saved!");
      await refreshConnectionStatus(val);
    });
  });

  // Safe 1-Click Auto-Pair (when 60s window open in OmniFetch Settings)
  btnAutoPair.addEventListener("click", async () => {
    try {
      const resp = await fetch(`${BASE_URL}/api/pair`, { method: "POST" });
      const data = await resp.json().catch(() => ({}));
      if (resp.ok && data.token) {
        tokenInput.value = data.token;
        chrome.storage.local.set({ token: data.token }, async () => {
          showMsg("Paired cleanly with OmniFetch!");
          await refreshConnectionStatus(data.token);
        });
      } else {
        showMsg(data.error || "Open 'Pair Brave Extension (60s)' in Settings first.", true);
      }
    } catch (e) {
      showMsg("OmniFetch is offline", true);
    }
  });

  // Auto-intercept settings
  chkAutoIntercept.addEventListener("change", () => {
    chrome.storage.local.set({ autoIntercept: chkAutoIntercept.checked });
  });

  numMinSize.addEventListener("change", () => {
    const val = parseInt(numMinSize.value, 10);
    chrome.storage.local.set({ minSizeMb: isNaN(val) ? 0 : Math.max(0, val) });
  });

  // Media sniffer toggle
  chkMediaSniffer.addEventListener("change", () => {
    chrome.storage.local.set({ mediaSniffer: chkMediaSniffer.checked }, () => {
      refreshDetectedMedia();
    });
  });

  // Quick URL Send
  btnSendUrl.addEventListener("click", async () => {
    const rawUrl = urlInput.value.trim();
    if (!rawUrl) return;

    const config = await chrome.storage.local.get(["token"]);
    const token = config.token || "";

    try {
      const resp = await fetch(`${BASE_URL}/api/handoff`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-OmniFetch-Token": token
        },
        body: JSON.stringify({ url: rawUrl, userAgent: navigator.userAgent })
      });

      if (resp.ok) {
        showMsg("Sent to OmniFetch!");
        urlInput.value = "";
      } else {
        showMsg("Handoff failed (Unauthorized)", true);
      }
    } catch (e) {
      showMsg("OmniFetch bridge offline", true);
    }
  });

  function showMsg(text, isError = false) {
    msgLabel.textContent = text;
    msgLabel.style.color = isError ? "#f87171" : "#34d399";
    setTimeout(() => {
      msgLabel.textContent = "";
    }, 3500);
  }
});
