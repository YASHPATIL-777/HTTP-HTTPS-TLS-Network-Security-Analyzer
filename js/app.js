/**
 * HTTP/HTTPS/TLS Network Security Analyzer - Main Application Controller
 * Single Page Application (SPA) Tab Router & Event Bus
 */

(function () {
  'use strict';

  const VIEW_TITLES = {
    overview: {
      title: 'Security Overview Dashboard',
      subtitle: 'Comparative Analysis of Plaintext HTTP vs Cryptographically Secured HTTPS/TLS'
    },
    architecture: {
      title: 'Interactive Network Topology',
      subtitle: 'Cisco Packet Tracer-Inspired Conceptual Architecture (Client, Switch, Router, Firewall, Server)'
    },
    'http-vs-https': {
      title: 'HTTP vs HTTPS Protocol Deep Dive',
      subtitle: 'Technical Matrix of Transport Security, Confidentiality, Port Bindings & Vulnerabilities'
    },
    'tls-security': {
      title: 'TLS Cryptographic Handshake',
      subtitle: 'Step-by-Step Educational Flow: Key Exchange, Authentication, and Record Encryption'
    },
    evidence: {
      title: 'Wireshark Evidence Repository',
      subtitle: 'Verified Laboratory Captures and Interactive Screenshot Gallery'
    },
    'packet-analysis': {
      title: 'Packet Analysis & Dissection Engine',
      subtitle: 'Wireshark Schema Dissection with Frame Tree, Protocol Fields, and Hex Dumps'
    },
    about: {
      title: 'About Network Security Analyzer',
      subtitle: 'Academic Project Specifications, Technologies, Objectives & Future Roadmap'
    }
  };

  function initApp() {
    initNavigation();
    initMobileSidebar();

    // Initialize all modules
    if (window.TopologyModule) window.TopologyModule.init();
    if (window.HandshakeModule) window.HandshakeModule.init();
    if (window.EvidenceModule) window.EvidenceModule.init();
    if (window.PacketModule) window.PacketModule.init();

    // Check initial URL hash or default to overview
    const initialHash = window.location.hash.replace('#', '') || 'overview';
    switchView(initialHash);
  }

  function initNavigation() {
    const navItems = document.querySelectorAll('.sidebar-nav .nav-item');
    navItems.forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const targetView = item.getAttribute('data-view');
        if (targetView) {
          switchView(targetView);
          window.location.hash = targetView;

          // Close mobile sidebar if open
          const sidebar = document.querySelector('.sidebar');
          if (sidebar) sidebar.classList.remove('mobile-open');
        }
      });
    });

    // Handle browser back/forward buttons
    window.addEventListener('hashchange', () => {
      const hash = window.location.hash.replace('#', '') || 'overview';
      switchView(hash);
    });

    // Support in-page links (e.g., summary card click-throughs)
    const inPageLinks = document.querySelectorAll('[data-switch-view]');
    inPageLinks.forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const target = link.getAttribute('data-switch-view');
        if (target) {
          switchView(target);
          window.location.hash = target;
        }
      });
    });
  }

  function switchView(viewId) {
    const validViews = Object.keys(VIEW_TITLES);
    if (!validViews.includes(viewId)) {
      viewId = 'overview';
    }

    // Update active nav item
    const navItems = document.querySelectorAll('.sidebar-nav .nav-item');
    navItems.forEach(item => {
      if (item.getAttribute('data-view') === viewId) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Update active section
    const sections = document.querySelectorAll('.view-section');
    sections.forEach(sec => {
      if (sec.id === `view-${viewId}`) {
        sec.classList.add('active');
      } else {
        sec.classList.remove('active');
      }
    });

    // Update top header titles
    const meta = VIEW_TITLES[viewId];
    if (meta) {
      const titleElem = document.getElementById('currentViewTitle');
      const subElem = document.getElementById('currentViewSubtitle');
      if (titleElem) titleElem.textContent = meta.title;
      if (subElem) subElem.textContent = meta.subtitle;
    }

    // Scroll main viewport to top
    const viewport = document.querySelector('.view-container');
    if (viewport) viewport.scrollTop = 0;
  }

  function initMobileSidebar() {
    const toggleBtn = document.getElementById('btnSidebarToggle');
    const sidebar = document.querySelector('.sidebar');
    if (toggleBtn && sidebar) {
      toggleBtn.addEventListener('click', () => {
        sidebar.classList.toggle('mobile-open');
      });
    }
  }

  // Run on DOM loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
  } else {
    initApp();
  }

})();
