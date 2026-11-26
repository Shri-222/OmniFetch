/**
 * OmniFetch Brave Extension - Background Service Worker
 * Handles context menu link/image handoff and smart auto-intercept.
 * Coexists cleanly with CyberShield Middle Wall.
 */

const DEFAULT_PORT = 8990;
const BASE_URL = `http://127.0.0.1:${DEFAULT_PORT}`;

// Register Context Menu on Install
chrome.runtime.onInstalled.addListener(() => {
  // Remove existing menu items if any to avoid duplicate id errors on reload
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "omnifetch_download_link",
      title: "Download with OmniFetch",
      contexts: ["link", "image", "video", "audio"]
    });
  });

  // Default configuration
  chrome.storage.local.get(["token", "autoIntercept", "minSizeMb", "mediaSniffer"], (res) => {
    if (!res.token) chrome.storage.local.set({ token: "" });
    if (res.autoIntercept === undefined) chrome.storage.local.set({ autoIntercept: false });
    if (res.minSizeMb === undefined) chrome.storage.local.set({ minSizeMb: 0 });
    if (res.mediaSniffer === undefined) chrome.storage.local.set({ mediaSniffer: false });
  });
});

// ---------------------------------------------------------------------------
// Opt-in Media Stream Sniffer (Passive webRequest.onHeadersReceived)
// ---------------------------------------------------------------------------
const tabMediaMap = new Map(); // tabId -> Map<url, mediaEntry>
const MEDIA_MIME_PREFIXES = [
  "video/mp4",
  "video/webm",
  "video/x-matroska",
  "audio/mpeg",
  "audio/mp4",
  "application/vnd.apple.mpegurl",
  "application/x-mpegurl"
];
const MEDIA_EXT_REGEX = /\.(mp4|mkv|webm|m3u8|mp3|aac|flac)(?:[?#].*)?$/i;
let mediaSnifferEnabled = false;

chrome.storage.local.get(["mediaSniffer"], (res) => {
  mediaSnifferEnabled = !!res.mediaSniffer;
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.mediaSniffer) {
    mediaSnifferEnabled = !!changes.mediaSniffer.newValue;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabMediaMap.delete(tabId);
});

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (!mediaSnifferEnabled) return;
    if (details.tabId < 0 || !details.url || details.url.startsWith("http://127.0.0.1")) return;
    if (details.type === "main_frame") {
      tabMediaMap.delete(details.tabId);
      return;
    }

    let contentType = "";
    let contentLength = 0;
    if (details.responseHeaders) {
      for (const h of details.responseHeaders) {
        const name = (h.name || "").toLowerCase();
        if (name === "content-type" && h.value) {
          contentType = h.value.split(";")[0].trim().toLowerCase();
        } else if (name === "content-length" && h.value) {
          const parsed = parseInt(h.value, 10);
          if (!isNaN(parsed)) contentLength = parsed;
        }
      }
    }

    const mimeMatch = MEDIA_MIME_PREFIXES.some((m) => contentType.startsWith(m));
    const extMatch = MEDIA_EXT_REGEX.test(details.url);
    if (!mimeMatch && !extMatch) return;

    let tabStore = tabMediaMap.get(details.tabId);
    if (!tabStore) {
      tabStore = new Map();
      tabMediaMap.set(details.tabId, tabStore);
    }
    if (tabStore.has(details.url) || tabStore.size >= 30) return;

    let filename = "media_stream";
    try {
      const parsed = new URL(details.url);
      const leaf = parsed.pathname.split("/").filter(Boolean).pop();
      if (leaf) filename = decodeURIComponent(leaf);
    } catch (e) {}

    tabStore.set(details.url, {
      url: details.url,
      filename: filename,
      contentType: contentType || "media",
      sizeBytes: contentLength
    });
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.action) return;
  if (msg.action === "getTabMedia") {
    const store = tabMediaMap.get(msg.tabId);
    sendResponse({ items: store ? Array.from(store.values()) : [] });
    return true;
  }
  if (msg.action === "sendMediaItem") {
    handoffLink(msg.url, msg.referer || "", msg.tabId || null, msg.filename || null)
      .then((ok) => sendResponse({ ok }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }
});

// Handle Context Menu Click (Links and Images)
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "omnifetch_download_link") {
    // 1. Linked-image priority: When right-clicking an image, ALWAYS prefer info.srcUrl over info.linkUrl
    let targetUrl = null;
    let suggestedFilename = null;

    if (info.mediaType === "image" && info.srcUrl) {
      targetUrl = info.srcUrl;
    } else {
      targetUrl = info.linkUrl || info.srcUrl || info.pageUrl;
    }

    if (targetUrl) {
      if (info.srcUrl) {
        try {
          const parsed = new URL(info.srcUrl);
          const leaf = parsed.pathname.split("/").filter(Boolean).pop();
          if (leaf && leaf.includes(".")) {
            suggestedFilename = decodeURIComponent(leaf);
          }
        } catch (e) {
          // ignore URL parsing error
        }
      }

      // Always pass the active tab URL as referer to avoid hotlink 403 Forbidden
      const referer = (tab && tab.url) ? tab.url : (info.pageUrl || "");
      await handoffLink(targetUrl, referer, tab ? tab.id : null, suggestedFilename);
    }
  }
});

// Helper: Collect comprehensive cookies including multi-domain Google authentication
async function collectCookiesForUrl(url) {
  let cookieHeader = "";
  try {
    const cookieMap = new Map();

    // 1. Direct URL cookies (including HttpOnly)
    try {
      const directCookies = await chrome.cookies.getAll({ url: url });
      if (directCookies && directCookies.length > 0) {
        for (const c of directCookies) {
          cookieMap.set(c.name, c.value);
        }
      }
    } catch (e) {
      // Ignore if permission denied on non-http schemes
    }

    // 2. Google Drive / Docs multi-domain authentication cookies
    if (url.includes("google.com") || url.includes("googleusercontent.com")) {
      const googleDomains = [
        ".google.com",
        "drive.google.com",
        "docs.google.com",
        ".googleusercontent.com"
      ];
      for (const domain of googleDomains) {
        try {
          const domainCookies = await chrome.cookies.getAll({ domain: domain });
          if (domainCookies && domainCookies.length > 0) {
            for (const c of domainCookies) {
              if (!cookieMap.has(c.name)) {
                cookieMap.set(c.name, c.value);
              }
            }
          }
        } catch (e) {
          // Ignore domain-level errors
        }
      }
    }

    if (cookieMap.size > 0) {
      cookieHeader = Array.from(cookieMap.entries())
        .map(([name, value]) => `${name}=${value}`)
        .join("; ");
    }
  } catch (err) {
    // Fallback gracefully
  }
  return cookieHeader;
}

// Sends link to OmniFetch authenticated bridge and returns true only on 200 OK
async function handoffLink(url, referer = "", tabId = null, filename = null, replaceTaskId = null) {
  const config = await chrome.storage.local.get(["token"]);
  const token = config.token || "";

  const cookieHeader = await collectCookiesForUrl(url);

  const payload = {
    url: url,
    filename: filename || null,
    cookies: cookieHeader,
    referer: referer || "",
    userAgent: navigator.userAgent
  };

  let endpoint = `${BASE_URL}/api/handoff`;
  if (replaceTaskId) {
    endpoint += `?replace_task_id=${encodeURIComponent(replaceTaskId)}`;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 4000);
  try {
    const resp = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-OmniFetch-Token": token
      },
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    if (resp.ok) {
      flashBadge("OK", "#10b981");
      return true;
    } else {
      flashBadge("AUTH", "#ef4444");
      return false;
    }
  } catch (err) {
    flashBadge("OFF", "#6b7280");
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

// Smart Auto-Intercept for browser downloads
chrome.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
  handleAutoIntercept(downloadItem, suggest);
  return true; // Indicates asynchronous response
});

async function handleAutoIntercept(downloadItem, suggest) {
  let resolved = false;
  const safeSuggest = () => {
    if (!resolved) {
      resolved = true;
      try {
        suggest();
      } catch (e) {}
    }
  };

  try {
    const config = await chrome.storage.local.get(["autoIntercept", "minSizeMb", "token"]);
    if (!config.autoIntercept) {
      safeSuggest();
      return;
    }

    // Skip intercepting challenge/anti-bot error pages (e.g. .within.website or text/html)
    const targetUrl = downloadItem.finalUrl || downloadItem.url || "";
    const mime = (downloadItem.mime || "").toLowerCase();
    if (targetUrl.includes(".within.website") || mime === "text/html" || mime === "text/plain; charset=utf-8") {
      safeSuggest();
      return;
    }

    // Ping OmniFetch bridge to ensure it is running, authorized, and check pending refresh target
    let pingData = null;
    try {
      const ping = await fetch(`${BASE_URL}/api/ping`, {
        method: "GET",
        headers: config.token ? { "X-OmniFetch-Token": config.token } : {}
      });
      if (ping.ok) {
        pingData = await ping.json();
      }
    } catch (e) {
      pingData = null;
    }

    if (!pingData) {
      // OmniFetch is closed or unauthorized: let browser download proceed untouched
      safeSuggest();
      return;
    }

    // Check size threshold if specified (0 = intercept all)
    const minSize = config.minSizeMb !== undefined ? config.minSizeMb : 0;
    const thresholdBytes = minSize * 1024 * 1024;
    if (minSize > 0 && downloadItem.fileSize > 0 && downloadItem.fileSize < thresholdBytes) {
      safeSuggest();
      return;
    }

    // Intercept: extract target URL and suggested filename
    let suggestedFilename = downloadItem.filename;
    if (suggestedFilename) {
      // Clean path if browser returned full path
      suggestedFilename = suggestedFilename.split(/[\\/]/).filter(Boolean).pop();
    }

    // Resolve referer: use downloadItem referrer or fallback to active tab URL
    let referer = downloadItem.referrer || "";
    if (!referer) {
      try {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (activeTab && activeTab.url) {
          referer = activeTab.url;
        }
      } catch (e) {}
    }

    // CRITICAL SAFE INTERCEPT RULE: Verify POST /api/handoff returns 200 OK BEFORE cancelling browser download
    const pendingRefreshId = pingData.pending_refresh_task_id || null;
    const handoffOk = await handoffLink(targetUrl, referer, null, suggestedFilename, pendingRefreshId);
    if (!handoffOk) {
      // Do NOT cancel Brave download if OmniFetch rejected, failed, or timed out
      safeSuggest();
      return;
    }

    // Handoff succeeded (200 OK): now safely cancel browser download and erase from history
    try {
      await chrome.downloads.cancel(downloadItem.id);
      await chrome.downloads.erase({ id: downloadItem.id });
    } catch (e) {}

    safeSuggest();
  } catch (err) {
    safeSuggest();
  }
}

function flashBadge(text, color) {
  chrome.action.setBadgeText({ text: text });
  chrome.action.setBadgeBackgroundColor({ color: color });
  setTimeout(() => {
    chrome.action.setBadgeText({ text: "" });
  }, 3000);
}
