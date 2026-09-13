/**
 * CyberToolkit dashboard interactions (Part 3).
 * Talks to Flask with fetch(). No cybersecurity algorithms, API keys,
 * or passwords belong here.
 */
(function () {
  "use strict";

  var TOOLS = {
    password: {
      title: "Password Analyzer",
      body:
        "This workspace will later POST a password to /api/password/analyze. Flask validates the JSON and calls the Python Password Analyzer. Strength is not calculated in JavaScript.",
    },
    hash: {
      title: "Hash Calculator",
      body:
        "This workspace will later ask Flask to call the Python Hash Calculator for SHA-256, SHA-512, or educational MD5. Hashing is not done in the browser.",
    },
    integrity: {
      title: "File Integrity Checker",
      body:
        "This workspace will later compare file SHA-256 hashes through Flask and the Python module. The dashboard does not read your files by itself yet.",
    },
    ip: {
      title: "IP Information",
      body:
        "This workspace will later validate and look up an address in Python. Frontend checks, if added later, are never a substitute for backend validation.",
    },
    log: {
      title: "Log Analyzer",
      body:
        "This workspace will later analyze a log you are allowed to review, using the Python Log Analyzer. The original log will stay read-only.",
    },
  };

  function scrollToId(id) {
    var target = document.getElementById(id);
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function openTool(key) {
    var info = TOOLS[key];
    var panel = document.getElementById("tool-panel");
    var title = document.getElementById("tool-panel-title");
    var body = document.getElementById("tool-panel-body");
    if (!info || !panel || !title || !body) {
      return;
    }
    title.textContent = info.title;
    body.textContent = info.body;
    panel.hidden = false;
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function closeTool() {
    var panel = document.getElementById("tool-panel");
    if (panel) {
      panel.hidden = true;
    }
  }

  function setBackendStatus(text, state) {
    var el = document.getElementById("backend-status");
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
    var explore = document.getElementById("explore-tools");
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

    var closeButton = document.getElementById("close-tool");
    if (closeButton) {
      closeButton.addEventListener("click", closeTool);
    }

    var checkBackend = document.getElementById("check-backend");
    if (checkBackend) {
      checkBackend.addEventListener("click", loadBackendStatus);
    }

    loadBackendStatus();
  });
})();
