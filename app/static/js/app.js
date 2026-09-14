/**
 * CyberToolkit dashboard interactions (Part 6).
 * Talks to Flask with fetch(). Scoring, hashing, integrity, and IP lookup
 * stay in Python.
 */
(function () {
  "use strict";

  var GENERIC_ERROR =
    "Something went wrong. Please check your input and try again.";

  function $(id) {
    return document.getElementById(id);
  }

  function setHidden(el, hidden) {
    if (el) {
      el.hidden = hidden;
    }
  }

  function setText(el, text) {
    if (el) {
      el.textContent = text;
    }
  }

  function scrollToId(id) {
    var target = $(id);
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function hideWorkspaces() {
    setHidden($("password-form"), true);
    setHidden($("password-error"), true);
    setHidden($("password-result"), true);
    setHidden($("hash-form"), true);
    setHidden($("hash-error"), true);
    setHidden($("hash-result"), true);
    setHidden($("integrity-form"), true);
    setHidden($("integrity-error"), true);
    setHidden($("integrity-result"), true);
    setHidden($("ip-form"), true);
    setHidden($("ip-error"), true);
    setHidden($("ip-result"), true);
    setHidden($("log-form"), true);
    setHidden($("log-error"), true);
    setHidden($("log-result"), true);
    setHidden($("tool-panel-body"), true);
    setText($("password-error"), "");
    setText($("hash-error"), "");
    setText($("integrity-error"), "");
    setText($("ip-error"), "");
    setText($("log-error"), "");
  }

  function clearPasswordField() {
    var input = $("password-input");
    if (input) {
      input.value = "";
    }
  }

  function openTool(key) {
    var panel = $("tool-panel");
    var title = $("tool-panel-title");
    var intro = $("tool-panel-intro");
    if (!panel || !title) {
      return;
    }

    hideWorkspaces();

    if (key === "password") {
      title.textContent = "Password Analyzer";
      setText(
        intro,
        "Flask sends your input to the Python Password Analyzer. Strength is not calculated in JavaScript."
      );
      setHidden($("password-form"), false);
    } else if (key === "hash") {
      title.textContent = "Hash Calculator";
      setText(
        intro,
        "Text is hashed in Python with hashlib. The browser never implements SHA-256, SHA-512, or MD5."
      );
      setHidden($("hash-form"), false);
      updateMd5Warning();
    } else if (key === "integrity") {
      title.textContent = "File Integrity Checker";
      setText(
        intro,
        "Files are stored only under data/monitored/. Flask hashes them with SHA-256. The browser cannot ask for arbitrary server paths."
      );
      setHidden($("integrity-form"), false);
      loadIntegrityFiles();
    } else if (key === "ip") {
      title.textContent = "IP Information";
      setText(
        intro,
        "Python validates and classifies the address. Public IPs may be looked up externally; private addresses are not sent to the API."
      );
      setHidden($("ip-form"), false);
    } else if (key === "log") {
      title.textContent = "Log Analyzer";
      setText(
        intro,
        "Flask reads an authorized log locally with the Python Log Analyzer. Entries are not executed, and logs are not sent off this computer."
      );
      setHidden($("log-form"), false);
      loadLogFiles();
    } else {
      return;
    }

    panel.hidden = false;
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function closeTool() {
    var panel = $("tool-panel");
    hideWorkspaces();
    clearPasswordField();
    if (panel) {
      panel.hidden = true;
    }
  }

  function handleApiError(response, data) {
    if (data && typeof data.error === "string" && data.error) {
      return data.error;
    }
    return GENERIC_ERROR;
  }

  function parseJsonSafe(response) {
    return response.json().catch(function () {
      return {};
    });
  }

  function setCheck(id, ok, label) {
    var item = $(id);
    if (!item) {
      return;
    }
    item.classList.remove("is-yes", "is-no");
    item.classList.add(ok ? "is-yes" : "is-no");
    item.textContent = label;
  }

  function displayPasswordResult(data) {
    setHidden($("password-error"), true);
    setHidden($("password-result"), false);
    setText($("password-strength"), (data.strength || "").toUpperCase());
    setText(
      $("password-length"),
      "Length: " + data.length + " · Character classes: " + data.class_count + " / 4"
    );
    setCheck("check-length", data.length >= 8, "Length");
    setCheck("check-uppercase", data.uppercase, "Uppercase");
    setCheck("check-lowercase", data.lowercase, "Lowercase");
    setCheck("check-digit", data.digit, "Number");
    setCheck("check-special", data.special, "Special character");

    var list = $("password-suggestions");
    if (list) {
      list.textContent = "";
      var tips = data.suggestions || [];
      tips.forEach(function (tip) {
        var li = document.createElement("li");
        li.textContent = tip;
        list.appendChild(li);
      });
    }
  }

  function analyzePassword(event) {
    event.preventDefault();
    var input = $("password-input");
    var password = input ? input.value : "";
    setHidden($("password-result"), true);
    setHidden($("password-error"), true);

    fetch("/api/password/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: password }),
    })
      .then(function (response) {
        return parseJsonSafe(response).then(function (data) {
          return { response: response, data: data };
        });
      })
      .then(function (result) {
        if (!result.response.ok) {
          setText(
            $("password-error"),
            handleApiError(result.response, result.data)
          );
          setHidden($("password-error"), false);
          return;
        }
        displayPasswordResult(result.data);
        clearPasswordField();
      })
      .catch(function () {
        setText($("password-error"), GENERIC_ERROR);
        setHidden($("password-error"), false);
      });
  }

  function updateMd5Warning() {
    var select = $("hash-algorithm");
    var warning = $("md5-warning");
    if (!select || !warning) {
      return;
    }
    warning.hidden = select.value !== "md5";
  }

  function displayHashResult(data) {
    setHidden($("hash-error"), true);
    setHidden($("hash-result"), false);
    setText($("hash-algorithm-result"), data.algorithm || "");
    setText($("hash-value"), data.hash || "");
    var warning = $("hash-warning");
    if (data.warning) {
      setText(warning, data.warning);
      setHidden(warning, false);
    } else {
      setText(warning, "");
      setHidden(warning, true);
    }
  }

  function calculateHash(event) {
    event.preventDefault();
    var textEl = $("hash-text");
    var algoEl = $("hash-algorithm");
    setHidden($("hash-result"), true);
    setHidden($("hash-error"), true);

    fetch("/api/hash/calculate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: textEl ? textEl.value : "",
        algorithm: algoEl ? algoEl.value : "",
      }),
    })
      .then(function (response) {
        return parseJsonSafe(response).then(function (data) {
          return { response: response, data: data };
        });
      })
      .then(function (result) {
        if (!result.response.ok) {
          setText($("hash-error"), handleApiError(result.response, result.data));
          setHidden($("hash-error"), false);
          return;
        }
        displayHashResult(result.data);
      })
      .catch(function () {
        setText($("hash-error"), GENERIC_ERROR);
        setHidden($("hash-error"), false);
      });
  }

  function copyHash() {
    var value = $("hash-value");
    var text = value ? value.textContent : "";
    if (!text || !navigator.clipboard) {
      return;
    }
    navigator.clipboard.writeText(text).catch(function () {
      /* Ignore clipboard permission errors. */
    });
  }

  function loadIntegrityFiles() {
    var select = $("integrity-file-list");
    if (!select) {
      return;
    }
    fetch("/api/integrity/files")
      .then(function (response) {
        return parseJsonSafe(response).then(function (data) {
          return { response: response, data: data };
        });
      })
      .then(function (result) {
        select.textContent = "";
        var files = (result.data && result.data.files) || [];
        if (!files.length) {
          var empty = document.createElement("option");
          empty.value = "";
          empty.textContent = "None registered yet";
          select.appendChild(empty);
          return;
        }
        files.forEach(function (item) {
          var option = document.createElement("option");
          option.value = item.name;
          option.textContent = item.name;
          select.appendChild(option);
        });
      })
      .catch(function () {
        select.textContent = "";
        var failed = document.createElement("option");
        failed.value = "";
        failed.textContent = "Unable to load files";
        select.appendChild(failed);
      });
  }

  function displayIntegrityResult(data) {
    setHidden($("integrity-error"), true);
    setHidden($("integrity-result"), false);
    setText($("integrity-status"), data.label || data.status || "");
    setText($("integrity-meta"), data.name ? "File: " + data.name : "");
    var hash = data.current_hash || data.sha256 || data.original_hash || "";
    setText($("integrity-hash"), hash);
    var scan = $("integrity-scan");
    if (scan) {
      scan.textContent = "";
    }
  }

  function displayIntegrityScan(files) {
    setHidden($("integrity-error"), true);
    setHidden($("integrity-result"), false);
    setText($("integrity-status"), "Integrity Check Results");
    setText(
      $("integrity-meta"),
      files.length ? "" : "No files are being monitored."
    );
    setText($("integrity-hash"), "");
    var scan = $("integrity-scan");
    if (!scan) {
      return;
    }
    scan.textContent = "";
    files.forEach(function (item) {
      var li = document.createElement("li");
      li.className = "scan-item";
      li.textContent =
        (item.name || "") + " — " + (item.label || item.status || "");
      scan.appendChild(li);
    });
  }

  function registerIntegrityFile() {
    var input = $("integrity-file");
    setHidden($("integrity-result"), true);
    setHidden($("integrity-error"), true);
    if (!input || !input.files || !input.files[0]) {
      setText($("integrity-error"), "No file selected.");
      setHidden($("integrity-error"), false);
      return;
    }
    var body = new FormData();
    body.append("file", input.files[0]);
    fetch("/api/integrity/register", { method: "POST", body: body })
      .then(function (response) {
        return parseJsonSafe(response).then(function (data) {
          return { response: response, data: data };
        });
      })
      .then(function (result) {
        if (!result.response.ok) {
          setText(
            $("integrity-error"),
            handleApiError(result.response, result.data)
          );
          setHidden($("integrity-error"), false);
          return;
        }
        displayIntegrityResult(result.data);
        loadIntegrityFiles();
      })
      .catch(function () {
        setText($("integrity-error"), GENERIC_ERROR);
        setHidden($("integrity-error"), false);
      });
  }

  function checkIntegrityFile() {
    var input = $("integrity-file");
    var select = $("integrity-file-list");
    setHidden($("integrity-result"), true);
    setHidden($("integrity-error"), true);

    var request;
    if (input && input.files && input.files[0]) {
      var body = new FormData();
      body.append("file", input.files[0]);
      request = fetch("/api/integrity/check", { method: "POST", body: body });
    } else if (select && select.value) {
      request = fetch("/api/integrity/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: select.value }),
      });
    } else {
      setText($("integrity-error"), "No file selected.");
      setHidden($("integrity-error"), false);
      return;
    }

    request
      .then(function (response) {
        return parseJsonSafe(response).then(function (data) {
          return { response: response, data: data };
        });
      })
      .then(function (result) {
        if (!result.response.ok) {
          setText(
            $("integrity-error"),
            handleApiError(result.response, result.data)
          );
          setHidden($("integrity-error"), false);
          return;
        }
        displayIntegrityResult(result.data);
      })
      .catch(function () {
        setText($("integrity-error"), GENERIC_ERROR);
        setHidden($("integrity-error"), false);
      });
  }

  function checkAllIntegrityFiles() {
    setHidden($("integrity-result"), true);
    setHidden($("integrity-error"), true);
    fetch("/api/integrity/check-all", { method: "POST" })
      .then(function (response) {
        return parseJsonSafe(response).then(function (data) {
          return { response: response, data: data };
        });
      })
      .then(function (result) {
        if (!result.response.ok) {
          setText(
            $("integrity-error"),
            handleApiError(result.response, result.data)
          );
          setHidden($("integrity-error"), false);
          return;
        }
        displayIntegrityScan(result.data.files || []);
      })
      .catch(function () {
        setText($("integrity-error"), GENERIC_ERROR);
        setHidden($("integrity-error"), false);
      });
  }

  function appendIpField(list, label, value) {
    var li = document.createElement("li");
    var shown =
      value === null || value === undefined || value === ""
        ? "Not available"
        : String(value);
    li.textContent = label + ": " + shown;
    list.appendChild(li);
  }

  function displayIpResult(data) {
    setHidden($("ip-error"), true);
    setHidden($("ip-result"), false);
    var list = $("ip-fields");
    if (list) {
      list.textContent = "";
      appendIpField(list, "IP Address", data.ip);
      appendIpField(list, "Version", data.version);
      appendIpField(list, "Type", data.type);
      appendIpField(list, "Hostname", data.hostname);
      appendIpField(list, "Country", data.country);
      appendIpField(list, "Region", data.region);
      appendIpField(list, "City", data.city);
      appendIpField(list, "ISP", data.isp);
      appendIpField(list, "Organization", data.org);
      appendIpField(list, "ASN", data.asn);
      appendIpField(list, "Timezone", data.timezone);
    }
    var note = data.privacy_note || data.note || data.error || "";
    setText($("ip-note"), note);
  }

  function analyzeIp(event) {
    event.preventDefault();
    var input = $("ip-input");
    setHidden($("ip-result"), true);
    setHidden($("ip-error"), true);
    fetch("/api/ip/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip: input ? input.value : "" }),
    })
      .then(function (response) {
        return parseJsonSafe(response).then(function (data) {
          return { response: response, data: data };
        });
      })
      .then(function (result) {
        if (!result.response.ok && result.response.status === 400) {
          setText($("ip-error"), handleApiError(result.response, result.data));
          setHidden($("ip-error"), false);
          return;
        }
        if (!result.response.ok && result.data && result.data.ip) {
          displayIpResult(result.data);
          return;
        }
        if (!result.response.ok) {
          setText($("ip-error"), handleApiError(result.response, result.data));
          setHidden($("ip-error"), false);
          return;
        }
        displayIpResult(result.data);
      })
      .catch(function () {
        setText($("ip-error"), GENERIC_ERROR);
        setHidden($("ip-error"), false);
      });
  }

  function loadLogFiles() {
    var select = $("log-file-list");
    if (!select) {
      return;
    }
    fetch("/api/log/files")
      .then(function (response) {
        return parseJsonSafe(response);
      })
      .then(function (data) {
        var current = select.value;
        select.textContent = "";
        var placeholder = document.createElement("option");
        placeholder.value = "";
        placeholder.textContent = "Choose a server log";
        select.appendChild(placeholder);
        var files = (data && data.files) || [];
        files.forEach(function (name) {
          var option = document.createElement("option");
          option.value = name;
          option.textContent = name;
          select.appendChild(option);
        });
        if (current) {
          select.value = current;
        }
      })
      .catch(function () {
        /* Keep the existing dropdown if listing fails. */
      });
  }

  function logSource() {
    var input = $("log-file");
    var select = $("log-file-list");
    if (input && input.files && input.files[0]) {
      var body = new FormData();
      body.append("file", input.files[0]);
      return { body: body, json: null };
    }
    if (select && select.value) {
      return { body: null, json: { filename: select.value } };
    }
    return null;
  }

  function appendStat(list, label, value) {
    var li = document.createElement("li");
    li.textContent = label + ": " + value;
    list.appendChild(li);
  }

  function displayLogAnalysis(data) {
    setHidden($("log-error"), true);
    setHidden($("log-result"), false);
    var stats = $("log-stats");
    var security = $("log-security");
    var ips = $("log-ips");
    var matches = $("log-matches");
    if (stats) {
      stats.textContent = "";
      appendStat(stats, "File", data.name || "");
      appendStat(stats, "Total Entries", data.total_entries);
      appendStat(stats, "INFO", data.info);
      appendStat(stats, "WARNING", data.warnings);
      appendStat(stats, "ERROR", data.errors);
    }
    if (security) {
      security.textContent = "";
      appendStat(security, "Failed Login Attempts", data.failed_logins);
      appendStat(security, "Successful Logins", data.successful_logins);
      appendStat(
        security,
        "Potentially Suspicious Activity",
        (data.suspicious_activity || []).length
      );
      appendStat(
        security,
        "Unique IP Addresses",
        Object.keys(data.ip_addresses || {}).length
      );
      (data.suspicious_activity || []).forEach(function (item) {
        appendStat(
          security,
          item.ip,
          item.failed_attempts + " failed attempts"
        );
      });
    }
    if (ips) {
      ips.textContent = "";
      var activity = data.ip_addresses || {};
      var keys = Object.keys(activity);
      if (!keys.length) {
        appendStat(ips, "IPv4 addresses", "None found");
      } else {
        keys
          .sort(function (a, b) {
            return activity[b] - activity[a];
          })
          .forEach(function (ip) {
            appendStat(ips, ip, activity[ip] + " events");
          });
      }
    }
    if (matches) {
      matches.textContent = "";
    }
    setText($("log-note"), data.note || "");
  }

  function displayLogSearch(data) {
    setHidden($("log-error"), true);
    setHidden($("log-result"), false);
    var matches = $("log-matches");
    if (!matches) {
      return;
    }
    matches.textContent = "";
    appendStat(matches, "Matches", data.match_count);
    (data.matches || []).forEach(function (line) {
      var li = document.createElement("li");
      li.textContent = line;
      matches.appendChild(li);
    });
    if (data.truncated) {
      var more = document.createElement("li");
      more.textContent = "Additional matches were not shown.";
      matches.appendChild(more);
    }
  }

  function analyzeLog() {
    var source = logSource();
    setHidden($("log-result"), true);
    setHidden($("log-error"), true);
    if (!source) {
      setText($("log-error"), "No file selected.");
      setHidden($("log-error"), false);
      return;
    }
    var options = { method: "POST" };
    if (source.body) {
      options.body = source.body;
    } else {
      options.headers = { "Content-Type": "application/json" };
      options.body = JSON.stringify(source.json);
    }
    fetch("/api/log/analyze", options)
      .then(function (response) {
        return parseJsonSafe(response).then(function (data) {
          return { response: response, data: data };
        });
      })
      .then(function (result) {
        if (!result.response.ok) {
          setText($("log-error"), handleApiError(result.response, result.data));
          setHidden($("log-error"), false);
          return;
        }
        displayLogAnalysis(result.data);
      })
      .catch(function () {
        setText($("log-error"), GENERIC_ERROR);
        setHidden($("log-error"), false);
      });
  }

  function searchLog() {
    var source = logSource();
    var keywordEl = $("log-keyword");
    var keyword = keywordEl ? keywordEl.value : "";
    setHidden($("log-error"), true);
    if (!source) {
      setText($("log-error"), "No file selected.");
      setHidden($("log-error"), false);
      return;
    }
    var options = { method: "POST" };
    if (source.body) {
      source.body.append("keyword", keyword);
      options.body = source.body;
    } else {
      options.headers = { "Content-Type": "application/json" };
      options.body = JSON.stringify({
        filename: source.json.filename,
        keyword: keyword,
      });
    }
    fetch("/api/log/search", options)
      .then(function (response) {
        return parseJsonSafe(response).then(function (data) {
          return { response: response, data: data };
        });
      })
      .then(function (result) {
        if (!result.response.ok) {
          setText($("log-error"), handleApiError(result.response, result.data));
          setHidden($("log-error"), false);
          return;
        }
        displayLogSearch(result.data);
      })
      .catch(function () {
        setText($("log-error"), GENERIC_ERROR);
        setHidden($("log-error"), false);
      });
  }

  function setBackendStatus(text, state) {
    var el = $("backend-status");
    if (!el) {
      return;
    }
    el.textContent = text;
    el.classList.remove("is-online", "is-offline");
    if (state) {
      el.classList.add(state);
    }
  }

  function loadBackendStatus() {
    setBackendStatus("Checking backend…", "");
    fetch("/api/status")
      .then(function (response) {
        if (!response.ok) {
          throw new Error("bad status");
        }
        return response.json();
      })
      .then(function (data) {
        var name = data.application || "CyberToolkit";
        var status = data.status || "unknown";
        setBackendStatus(name + " backend is " + status + ".", "is-online");
      })
      .catch(function () {
        setBackendStatus("Backend is not reachable.", "is-offline");
      });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var explore = $("explore-tools");
    if (explore) {
      explore.addEventListener("click", function () {
        scrollToId("tools");
      });
    }

    document.querySelectorAll("[data-tool]").forEach(function (button) {
      button.addEventListener("click", function () {
        openTool(button.getAttribute("data-tool"));
      });
    });

    var closeButton = $("close-tool");
    if (closeButton) {
      closeButton.addEventListener("click", closeTool);
    }

    var checkBackend = $("check-backend");
    if (checkBackend) {
      checkBackend.addEventListener("click", loadBackendStatus);
    }

    var passwordForm = $("password-form");
    if (passwordForm) {
      passwordForm.addEventListener("submit", analyzePassword);
    }

    var hashForm = $("hash-form");
    if (hashForm) {
      hashForm.addEventListener("submit", calculateHash);
    }

    var algo = $("hash-algorithm");
    if (algo) {
      algo.addEventListener("change", updateMd5Warning);
    }

    var copyButton = $("copy-hash");
    if (copyButton) {
      copyButton.addEventListener("click", copyHash);
    }

    var registerButton = $("integrity-register");
    if (registerButton) {
      registerButton.addEventListener("click", registerIntegrityFile);
    }
    var checkButton = $("integrity-check");
    if (checkButton) {
      checkButton.addEventListener("click", checkIntegrityFile);
    }
    var checkAllButton = $("integrity-check-all");
    if (checkAllButton) {
      checkAllButton.addEventListener("click", checkAllIntegrityFiles);
    }

    var ipForm = $("ip-form");
    if (ipForm) {
      ipForm.addEventListener("submit", analyzeIp);
    }

    var analyzeLogButton = $("log-analyze");
    if (analyzeLogButton) {
      analyzeLogButton.addEventListener("click", analyzeLog);
    }
    var searchLogButton = $("log-search");
    if (searchLogButton) {
      searchLogButton.addEventListener("click", searchLog);
    }

    loadBackendStatus();
  });
})();
