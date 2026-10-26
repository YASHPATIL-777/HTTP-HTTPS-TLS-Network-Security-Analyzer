/**
 * HTTP/HTTPS/TLS Network Security Analyzer - Interactive Topology Module
 * Cisco Packet Tracer-Style Conceptual Network Architecture Canvas
 */

(function () {
  'use strict';

  // Node & Link Conceptual Database
  const TOPOLOGY_DATA = {
    nodes: {
      client: {
        id: 'client',
        name: 'Client / Web Browser',
        type: 'Endpoint Host',
        ip: '192.168.1.50',
        mac: '00:1A:2B:3C:4D:5E',
        gateway: '192.168.1.1',
        os: 'Workstation OS (Browser)',
        layer: 'Layer 7 (Application) & Layer 3/4',
        ports: 'Dynamic/Ephemeral (54321)',
        desc: 'The student or user workstation initiating HTTP and HTTPS requests via a web browser (e.g., Chrome/Firefox). Generates initial TCP 3-way handshakes and TLS Client Hello messages.',
        security: {
          status: 'secure',
          text: 'If connecting via plaintext HTTP, browser credentials, cookies, and tokens are transmitted in cleartext right from this network interface card.'
        }
      },
      switch: {
        id: 'switch',
        name: 'Access Switch (L2)',
        type: 'Local Switching Node',
        ip: '192.168.1.2 (Management)',
        mac: '00:22:33:44:55:66',
        gateway: 'N/A (L2 Device)',
        os: 'Cisco IOS-style Switch',
        layer: 'Layer 2 (Data Link)',
        ports: 'FastEthernet 0/1 - 0/24',
        desc: 'Local network switch forwarding frames within the internal broadcast domain based on MAC addresses. In unmanaged or compromised switches, port mirroring or ARP poisoning can mirror all local traffic.',
        security: {
          status: 'neutral',
          text: 'Vulnerable to ARP spoofing and MAC flooding attacks. If HTTP is in use on the local LAN, an attacker in the same switch domain can capture full session credentials with Wireshark.'
        }
      },
      router: {
        id: 'router',
        name: 'Edge Gateway Router',
        type: 'Layer 3 Gateway',
        ip: '192.168.1.1 (LAN) / 203.0.113.1 (WAN)',
        mac: '00:AA:BB:CC:DD:EE',
        gateway: 'ISP Next-Hop 203.0.113.254',
        os: 'Border Gateway Router',
        layer: 'Layer 3 (Network)',
        ports: 'GigabitEthernet 0/0, 0/1 (NAT Active)',
        desc: 'Routes packets between the private LAN (192.168.1.0/24) and the public Internet. Performs Network Address Translation (NAT) and packet forwarding.',
        security: {
          status: 'neutral',
          text: 'Routers along the transit path can inspect all unencrypted IP packet payloads. When using TLS, the router can only observe IP headers, TCP ports (443), and the unencrypted SNI (Server Name Indication) hostname.'
        }
      },
      firewall: {
        id: 'firewall',
        name: 'Enterprise Perimeter Firewall',
        type: 'Stateful Security Appliance',
        ip: '203.0.113.2',
        mac: '00:50:56:A1:B2:C3',
        gateway: '203.0.113.1',
        os: 'Stateful Packet Filter / NGFW',
        layer: 'Layer 3 through Layer 7',
        ports: 'Inbound/Outbound Rules (80, 443 permitted)',
        desc: 'Enforces network security policies, inspecting incoming and outgoing traffic. Allows TCP port 80 and TCP port 443 while dropping unauthorized protocol requests.',
        security: {
          status: 'secure',
          text: 'For unencrypted HTTP, stateful firewalls can perform deep packet inspection (DPI) to block malicious URLs. For HTTPS, modern firewalls inspect TLS certificate SNI or require TLS decryption proxies.'
        }
      },
      server: {
        id: 'server',
        name: 'Web Server (Destination)',
        type: 'Application & Web Server',
        ip: '93.184.216.34',
        mac: '52:54:00:12:34:56',
        gateway: '93.184.216.1',
        os: 'Linux Server (Nginx / Apache)',
        layer: 'Layer 7 (Application)',
        ports: 'TCP 80 (HTTP) & TCP 443 (HTTPS/TLS)',
        desc: 'The destination web server hosting web applications and services. Possesses a public X.509 digital certificate and private key for TLS cryptographic termination.',
        security: {
          status: 'secure',
          text: 'Must maintain strict private key secrecy. If the server supports both port 80 and 443, it should enforce HTTP Strict Transport Security (HSTS) to prevent SSL stripping attacks.'
        }
      }
    },
    links: {
      http: {
        id: 'http',
        name: 'Unencrypted HTTP Connection (Port 80)',
        type: 'Application Transport Path',
        port: 'TCP 80',
        protocol: 'HTTP/1.1 (Hypertext Transfer Protocol)',
        encryption: 'None (Plaintext ASCII)',
        confidentiality: 'ZERO - Interceptable by any transit node',
        integrity: 'Vulnerable to MITM packet alteration',
        authentication: 'None (No server identity validation)',
        desc: 'Direct communication over TCP port 80 without any cryptographic wrapper. Transmits HTTP requests (GET, POST), response bodies, cookies, authentication tokens, and passwords as raw ASCII text.',
        security: {
          status: 'insecure',
          text: 'CRITICAL SECURITY DEFICIT: In Wireshark, filtering for "http" reveals plaintext passwords, sensitive URLs, and session cookies. Subject to man-in-the-middle tampering and passive packet sniffing.'
        }
      },
      https: {
        id: 'https',
        name: 'Encrypted HTTPS / TLS Connection (Port 443)',
        type: 'Cryptographic Secure Tunnel',
        port: 'TCP 443',
        protocol: 'HTTPS (HTTP over TLS 1.2 / TLS 1.3)',
        encryption: 'Symmetric AEAD (AES-256-GCM / ChaCha20-Poly1305)',
        confidentiality: 'High (Eavesdropper observes only ciphertext)',
        integrity: 'Cryptographic Authentication (HMAC / GHASH)',
        authentication: 'X.509 Digital Certificates via trusted PKI',
        desc: 'HTTP encapsulated inside a Transport Layer Security (TLS) tunnel on TCP port 443. The client and server perform a cryptographic handshake to authenticate the server and derive symmetric session keys.',
        security: {
          status: 'secure',
          text: 'HIGH SECURITY: In Wireshark, application payloads appear as opaque "Application Data" records. Network eavesdroppers and intermediate routers cannot view cookies, passwords, or request URLs.'
        }
      }
    }
  };

  let isAnimating = false;
  let activeSimulation = null;

  // Initialize Topology Diagram
  function initTopology() {
    const svgArea = document.getElementById('topologySvg');
    if (!svgArea) return;

    // Attach click handlers to nodes
    const nodeElements = svgArea.querySelectorAll('.topology-node');
    nodeElements.forEach(node => {
      node.addEventListener('click', (e) => {
        e.stopPropagation();
        const nodeId = node.getAttribute('data-node-id');
        selectNode(nodeId, node);
      });
    });

    // Attach click handlers to connection links
    const linkElements = svgArea.querySelectorAll('.topology-link');
    linkElements.forEach(link => {
      link.addEventListener('click', (e) => {
        e.stopPropagation();
        const linkType = link.getAttribute('data-link-type');
        selectLink(linkType, link);
      });
    });

    // Toolbar buttons
    const btnSimHttp = document.getElementById('btnSimHttp');
    const btnSimHttps = document.getElementById('btnSimHttps');
    const btnResetView = document.getElementById('btnResetTopology');
    const btnCloseInspector = document.getElementById('btnCloseInspector');

    if (btnSimHttp) {
      btnSimHttp.addEventListener('click', () => simulatePacket('http'));
    }
    if (btnSimHttps) {
      btnSimHttps.addEventListener('click', () => simulatePacket('https'));
    }
    if (btnResetView) {
      btnResetView.addEventListener('click', resetView);
    }
    if (btnCloseInspector) {
      btnCloseInspector.addEventListener('click', closeInspector);
    }

    // Default select client on first load for immediate context
    selectNode('client', document.getElementById('node-client'));
  }

  // Display details for selected node
  function selectNode(nodeId, element) {
    clearSelection();
    if (element) element.classList.add('selected');

    const nodeData = TOPOLOGY_DATA.nodes[nodeId];
    if (!nodeData) return;

    const inspector = document.getElementById('topologyInspector');
    if (!inspector) return;

    inspector.classList.remove('collapsed');

    // Populate inspector
    document.getElementById('inspectorTitle').textContent = nodeData.name;
    document.getElementById('inspectorType').textContent = nodeData.type;

    const specsHtml = `
      <div class="spec-key">IP Address:</div><div class="spec-val">${nodeData.ip}</div>
      <div class="spec-key">MAC Address:</div><div class="spec-val">${nodeData.mac}</div>
      <div class="spec-key">Gateway:</div><div class="spec-val">${nodeData.gateway}</div>
      <div class="spec-key">OS / Role:</div><div class="spec-val">${nodeData.os}</div>
      <div class="spec-key">OSI Layer:</div><div class="spec-val">${nodeData.layer}</div>
      <div class="spec-key">Open Ports:</div><div class="spec-val">${nodeData.ports}</div>
    `;
    document.getElementById('inspectorSpecs').innerHTML = specsHtml;
    document.getElementById('inspectorDesc').textContent = nodeData.desc;

    const secImpact = document.getElementById('inspectorSecImpact');
    secImpact.className = `inspector-sec-impact ${nodeData.security.status}`;
    secImpact.innerHTML = `<strong>Cybersecurity Context:</strong> ${nodeData.security.text}`;
  }

  // Display details for selected link
  function selectLink(linkType, element) {
    clearSelection();
    if (element) element.style.strokeWidth = '6';

    const linkData = TOPOLOGY_DATA.links[linkType];
    if (!linkData) return;

    const inspector = document.getElementById('topologyInspector');
    if (!inspector) return;

    inspector.classList.remove('collapsed');

    document.getElementById('inspectorTitle').textContent = linkData.name;
    document.getElementById('inspectorType').textContent = linkData.type;

    const specsHtml = `
      <div class="spec-key">Protocol:</div><div class="spec-val">${linkData.protocol}</div>
      <div class="spec-key">Default Port:</div><div class="spec-val">${linkData.port}</div>
      <div class="spec-key">Encryption:</div><div class="spec-val">${linkData.encryption}</div>
      <div class="spec-key">Confidentiality:</div><div class="spec-val">${linkData.confidentiality}</div>
      <div class="spec-key">Integrity:</div><div class="spec-val">${linkData.integrity}</div>
      <div class="spec-key">Authentication:</div><div class="spec-val">${linkData.authentication}</div>
    `;
    document.getElementById('inspectorSpecs').innerHTML = specsHtml;
    document.getElementById('inspectorDesc').textContent = linkData.desc;

    const secImpact = document.getElementById('inspectorSecImpact');
    secImpact.className = `inspector-sec-impact ${linkData.security.status}`;
    secImpact.innerHTML = `<strong>Wireshark / Educational Note:</strong> ${linkData.security.text}`;
  }

  function clearSelection() {
    const nodes = document.querySelectorAll('.topology-node');
    nodes.forEach(n => n.classList.remove('selected'));

    const links = document.querySelectorAll('.topology-link');
    links.forEach(l => {
      l.style.strokeWidth = '';
    });
  }

  function closeInspector() {
    const inspector = document.getElementById('topologyInspector');
    if (inspector) inspector.classList.add('collapsed');
    clearSelection();
  }

  function resetView() {
    closeInspector();
    clearPacketSimulations();
    // Re-select client
    selectNode('client', document.getElementById('node-client'));
  }

  // Packet Flow Animation Simulation
  function simulatePacket(type) {
    clearPacketSimulations();
    const animLayer = document.getElementById('topologyAnimLayer');
    if (!animLayer) return;

    const isHttp = type === 'http';
    const packetCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    packetCircle.setAttribute('r', isHttp ? '7' : '8');
    packetCircle.setAttribute('class', isHttp ? 'sim-packet-http' : 'sim-packet-https');

    // Route coordinates: Client (120, 240) -> Switch (320, 240) -> Router (520, 240) -> Firewall (720, 240) -> Server (920, 240)
    const waypoints = [
      { x: 120, y: isHttp ? 220 : 260 },
      { x: 320, y: isHttp ? 220 : 260 },
      { x: 520, y: isHttp ? 220 : 260 },
      { x: 720, y: isHttp ? 220 : 260 },
      { x: 920, y: isHttp ? 220 : 260 }
    ];

    animLayer.appendChild(packetCircle);

    let currentWaypoint = 0;
    const speed = 0.02; // Progress per frame
    let progress = 0;

    function animate() {
      if (currentWaypoint >= waypoints.length - 1) {
        // Reached destination, show brief flash then remove
        setTimeout(() => {
          if (packetCircle.parentNode) {
            packetCircle.parentNode.removeChild(packetCircle);
          }
        }, 300);
        return;
      }

      const p1 = waypoints[currentWaypoint];
      const p2 = waypoints[currentWaypoint + 1];

      const curX = p1.x + (p2.x - p1.x) * progress;
      const curY = p1.y + (p2.y - p1.y) * progress;

      packetCircle.setAttribute('cx', curX);
      packetCircle.setAttribute('cy', curY);

      progress += speed;
      if (progress >= 1) {
        progress = 0;
        currentWaypoint++;
      }

      activeSimulation = requestAnimationFrame(animate);
    }

    animate();

    // Also select corresponding link for educational clarity
    const linkElem = document.querySelector(`[data-link-type="${type}"]`);
    if (linkElem) {
      selectLink(type, linkElem);
    }
  }

  function clearPacketSimulations() {
    if (activeSimulation) {
      cancelAnimationFrame(activeSimulation);
      activeSimulation = null;
    }
    const animLayer = document.getElementById('topologyAnimLayer');
    if (animLayer) {
      animLayer.innerHTML = '';
    }
  }

  // Export to window
  window.TopologyModule = {
    init: initTopology,
    simulatePacket: simulatePacket,
    resetView: resetView,
    selectNode: selectNode,
    selectLink: selectLink
  };

})();
