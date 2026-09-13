/**
 * CyberToolkit dashboard interactions (Part 2).
 * No cybersecurity algorithms, API keys, or passwords belong here.
 */
(function () {
  "use strict";

  var TOOLS = {
    password: {
      title: "Password Analyzer",
      body:
        "This workspace will later send a password to Flask, which will call the Python Password Analyzer. Strength is not calculated in JavaScript.",
    },
    hash: {
      title: "Hash Calculator",
      body:
        "This workspace will later ask the Python Hash Calculator for SHA-256, SHA-512, or educational MD5. Hashing is not done in the browser.",
    },
    integrity: {
      title: "File Integrity Checker",
      body:
        "This workspace will later compare file SHA-256 hashes through the Python module. The dashboard does not read your files by itself yet.",
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
  });
})();
