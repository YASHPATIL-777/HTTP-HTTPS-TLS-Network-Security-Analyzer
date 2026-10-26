/**
 * HTTP/HTTPS/TLS Network Security Analyzer - Packet Analysis Module
 * Wireshark-style Packet Dissection, Protocol Filtering, and Hex Dump Inspector
 */

(function () {
  'use strict';

  // Educational Sample Wireshark Packet Captures
  const SAMPLE_PACKETS = [
    {
      no: 1,
      time: '0.000000',
      source: '192.168.1.50',
      destination: '8.8.8.8',
      protocol: 'DNS',
      length: 74,
      info: 'Standard query 0x1a2b A insecure-college.edu',
      summary: 'DNS address resolution for target web domain.',
      security: 'DNS queries over port 53 are unencrypted by default, allowing local eavesdroppers and ISPs to log requested domains.',
      tree: [
        { header: 'Frame 1: 74 bytes on wire (592 bits), 74 bytes captured', fields: ['Interface: eth0', 'Arrival Time: Oct 22, 2026 21:00:00.000'] },
        { header: 'Ethernet II, Src: 00:1a:2b:3c:4d:5e, Dst: 00:aa:bb:cc:dd:ee', fields: ['Destination: Gateway (00:aa:bb:cc:dd:ee)', 'Type: IPv4 (0x0800)'] },
        { header: 'Internet Protocol Version 4, Src: 192.168.1.50, Dst: 8.8.8.8', fields: ['Header Length: 20 bytes', 'Time to Live: 64', 'Protocol: UDP (17)'] },
        { header: 'User Datagram Protocol, Src Port: 53210, Dst Port: 53', fields: ['Source Port: 53210', 'Destination Port: 53', 'Length: 40'] },
        { header: 'Domain Name System (query)', fields: ['Transaction ID: 0x1a2b', 'Queries: insecure-college.edu: type A, class IN'] }
      ],
      hex: [
        { offset: '0000', hex: '00 aa bb cc dd ee 00 1a 2b 3c 4d 5e 08 00 45 00', ascii: '....+<M^..E.' },
        { offset: '0010', hex: '00 3c 1a 2b 40 00 40 11 b8 12 c0 a8 01 32 08 08', ascii: '.<.+@.@......2..' },
        { offset: '0020', hex: '08 08 cf da 00 35 00 28 e1 4a 1a 2b 01 00 00 01', ascii: '.....5.(.J.+....' },
        { offset: '0030', hex: '00 00 00 00 00 00 10 69 6e 73 65 63 75 72 65 2d', ascii: '.......insecure-' },
        { offset: '0040', hex: '63 6f 6c 6c 65 67 65 03 65 64 75 00 00 01 00 01', ascii: 'college.edu.....' }
      ]
    },
    {
      no: 2,
      time: '0.015240',
      source: '8.8.8.8',
      destination: '192.168.1.50',
      protocol: 'DNS',
      length: 90,
      info: 'Standard query response 0x1a2b A insecure-college.edu A 93.184.216.34',
      summary: 'DNS response resolving domain to IP address 93.184.216.34.',
      security: 'DNS response received. Target IP confirmed.',
      tree: [
        { header: 'Frame 2: 90 bytes on wire', fields: ['Interface: eth0'] },
        { header: 'Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.50', fields: ['Protocol: UDP (17)', 'Flags: Don\'t fragment'] },
        { header: 'Domain Name System (response)', fields: ['Answers: insecure-college.edu: type A, class IN, addr 93.184.216.34'] }
      ],
      hex: [
        { offset: '0000', hex: '00 1a 2b 3c 4d 5e 00 aa bb cc dd ee 08 00 45 00', ascii: '..+<M^........E.' },
        { offset: '0010', hex: '00 4c 3f 10 00 00 38 11 b3 c2 08 08 08 08 c0 a8', ascii: '.L?...8.........' },
        { offset: '0020', hex: '01 32 00 35 cf da 00 38 52 1a 1a 2b 81 80 00 01', ascii: '.2.5...8R..+....' },
        { offset: '0030', hex: '00 01 00 00 00 00 c0 0c 00 01 00 01 00 00 01 2c', ascii: '...............,' },
        { offset: '0040', hex: '00 04 5d b8 d8 22', ascii: '..].."..........' }
      ]
    },
    {
      no: 3,
      time: '0.021100',
      source: '192.168.1.50',
      destination: '93.184.216.34',
      protocol: 'TCP',
      length: 66,
      info: '54321 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1',
      summary: 'TCP 3-way handshake initiation for HTTP connection on port 80.',
      security: 'Connection initiated to unencrypted port 80.',
      tree: [
        { header: 'Transmission Control Protocol, Src Port: 54321, Dst Port: 80', fields: ['Sequence Number: 0 (relative)', 'Flags: 0x002 (SYN)', 'Window: 64240', 'Checksum: 0x7a31'] }
      ],
      hex: [
        { offset: '0000', hex: '00 aa bb cc dd ee 00 1a 2b 3c 4d 5e 08 00 45 00', ascii: '....+<M^..E.' },
        { offset: '0010', hex: '00 34 b1 a2 40 00 40 06 20 f1 c0 a8 01 32 5d b8', ascii: '.4..@.@. ...2].' },
        { offset: '0020', hex: 'd8 22 d4 31 00 50 a1 9b 02 14 00 00 00 00 80 02', ascii: '.".1.P..........' },
        { offset: '0030', hex: 'fa f0 7a 31 00 00 02 04 05 b4 01 03 03 08 01 01', ascii: '..z1............' }
      ]
    },
    {
      no: 4,
      time: '0.045300',
      source: '93.184.216.34',
      destination: '192.168.1.50',
      protocol: 'TCP',
      length: 66,
      info: '80 → 54321 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0',
      summary: 'Web server accepts TCP connection on HTTP port 80.',
      security: 'TCP Handshake second phase.',
      tree: [
        { header: 'Transmission Control Protocol, Src Port: 80, Dst Port: 54321', fields: ['Sequence Number: 0', 'Acknowledgment Number: 1', 'Flags: 0x012 (SYN, ACK)'] }
      ],
      hex: [
        { offset: '0000', hex: '00 1a 2b 3c 4d 5e 00 aa bb cc dd ee 08 00 45 00', ascii: '..+<M^........E.' },
        { offset: '0010', hex: '00 34 00 00 40 00 34 06 a2 93 5d b8 d8 22 c0 a8', ascii: '.4..@.4...]"..2' },
        { offset: '0020', hex: '01 32 00 50 d4 31 3c 41 82 90 a1 9b 02 15 80 12', ascii: '.2.P.1<A........' }
      ]
    },
    {
      no: 5,
      time: '0.045420',
      source: '192.168.1.50',
      destination: '93.184.216.34',
      protocol: 'TCP',
      length: 54,
      info: '54321 → 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0',
      summary: 'TCP 3-way handshake established on port 80.',
      security: 'Socket ready for HTTP application data.',
      tree: [
        { header: 'Transmission Control Protocol, Src Port: 54321, Dst Port: 80', fields: ['Flags: 0x010 (ACK)', 'Connection State: ESTABLISHED'] }
      ],
      hex: [
        { offset: '0000', hex: '00 aa bb cc dd ee 00 1a 2b 3c 4d 5e 08 00 45 00', ascii: '....+<M^..E.' },
        { offset: '0010', hex: '00 28 b1 a3 40 00 40 06 20 fc c0 a8 01 32 5d b8', ascii: '.(..@.@. ...2].' }
      ]
    },
    {
      no: 6,
      time: '0.052100',
      source: '192.168.1.50',
      destination: '93.184.216.34',
      protocol: 'HTTP',
      length: 298,
      info: 'GET /login?user=student&password=secretPassword2026 HTTP/1.1',
      summary: 'UNENCRYPTED HTTP GET Request exposing plaintext credentials in URI parameters!',
      security: 'CRITICAL SECURITY DEFECT: Authentication credentials and query parameters are fully readable in cleartext. Any packet sniffer on the LAN or transit ISP can capture this password instantly.',
      tree: [
        { header: 'Frame 6: 298 bytes on wire', fields: ['Protocols in frame: eth:ethertype:ip:tcp:http'] },
        { header: 'Transmission Control Protocol, Src Port: 54321, Dst Port: 80', fields: ['Payload Length: 244 bytes'] },
        { 
          header: 'Hypertext Transfer Protocol (PLAINTEXT)', 
          fields: [
            'Request Method: GET',
            'Request URI: /login?user=student&password=secretPassword2026',
            'Request Version: HTTP/1.1',
            'Host: insecure-college.edu',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64)',
            'Accept: text/html,application/xhtml+xml',
            'Cookie: session_auth=student_unencrypted_token_9981'
          ] 
        }
      ],
      hex: [
        { offset: '0000', hex: '47 45 54 20 2f 6c 6f 67 69 6e 3f 75 73 65 72 3d', ascii: 'GET /login?user=' },
        { offset: '0010', hex: '73 74 75 64 65 6e 74 26 70 61 73 73 77 6f 72 64', ascii: 'student&password' },
        { offset: '0020', hex: '3d 73 65 63 72 65 74 50 61 73 73 77 6f 72 64 32', ascii: '=secretPassword2' },
        { offset: '0030', hex: '30 32 36 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f', ascii: '026 HTTP/1.1..Ho' },
        { offset: '0040', hex: '73 74 3a 20 69 6e 73 65 63 75 72 65 2d 63 6f 6c', ascii: 'st: insecure-col' },
        { offset: '0050', hex: '6c 65 67 65 2e 65 64 75 0d 0a 43 6f 6f 6b 69 65', ascii: 'lege.edu..Cookie' },
        { offset: '0060', hex: '3a 20 73 65 73 73 69 6f 6e 5f 61 75 74 68 3d 73', ascii: ': session_auth=s' }
      ]
    },
    {
      no: 7,
      time: '0.089400',
      source: '93.184.216.34',
      destination: '192.168.1.50',
      protocol: 'HTTP',
      length: 420,
      info: 'HTTP/1.1 200 OK (text/html) Set-Cookie: admin_session=unprotected_cookie_xyz',
      summary: 'HTTP Server Response with cleartext session cookie.',
      security: 'Session hijacking risk: An attacker reading this frame can hijack the authenticated user session without needing their password.',
      tree: [
        { 
          header: 'Hypertext Transfer Protocol (Response)', 
          fields: [
            'Status Code: 200 OK',
            'Content-Type: text/html; charset=UTF-8',
            'Set-Cookie: admin_session=unprotected_cookie_xyz; Path=/',
            'Server: Apache/2.4.52 (Ubuntu)',
            'Body: <h1>Welcome Student Dashboard</h1><p>Grades: A+</p>'
          ] 
        }
      ],
      hex: [
        { offset: '0000', hex: '48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d', ascii: 'HTTP/1.1 200 OK.' },
        { offset: '0010', hex: '0a 53 65 72 76 65 72 3a 20 41 70 61 63 68 65 2f', ascii: '.Server: Apache/' },
        { offset: '0020', hex: '32 2e 34 2e 35 32 0d 0a 53 65 74 2d 43 6f 6f 6b', ascii: '2.4.52..Set-Cook' },
        { offset: '0030', hex: '69 65 3a 20 61 64 6d 69 6e 5f 73 65 73 73 69 6f', ascii: 'ie: admin_sessio' },
        { offset: '0040', hex: '6e 3d 75 6e 70 72 6f 74 65 63 74 65 64 5f 63 6f', ascii: 'n=unprotected_co' }
      ]
    },
    {
      no: 8,
      time: '1.200100',
      source: '192.168.1.50',
      destination: '93.184.216.34',
      protocol: 'TCP',
      length: 66,
      info: '54322 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1',
      summary: 'TCP connection initiation for secure HTTPS on port 443.',
      security: 'Beginning TLS session establishment.',
      tree: [
        { header: 'Transmission Control Protocol, Src Port: 54322, Dst Port: 443', fields: ['Destination Port: 443 (HTTPS)', 'Flags: 0x002 (SYN)'] }
      ],
      hex: [
        { offset: '0000', hex: '00 aa bb cc dd ee 00 1a 2b 3c 4d 5e 08 00 45 00', ascii: '....+<M^..E.' },
        { offset: '0010', hex: '00 34 c2 10 40 00 40 06 1f 83 c0 a8 01 32 5d b8', ascii: '.4..@.@. ...2].' },
        { offset: '0020', hex: 'd8 22 d4 32 01 bb a4 22 10 01 00 00 00 00 80 02', ascii: '.".2..."........' }
      ]
    },
    {
      no: 9,
      time: '1.235400',
      source: '192.168.1.50',
      destination: '93.184.216.34',
      protocol: 'TLS',
      length: 517,
      info: 'Client Hello (SNI=secure.college-demo.edu, Version=TLS 1.3)',
      summary: 'Client initiates TLS 1.3 handshake with cryptographic capabilities.',
      security: 'Cryptographic parameters negotiated. Cipher suites offered include AES-256-GCM and ChaCha20-Poly1305.',
      tree: [
        { 
          header: 'Transport Layer Security (TLS 1.3 Client Hello)', 
          fields: [
            'Content Type: Handshake (22)',
            'Version: TLS 1.2 (0x0303) [Compatibility mode]',
            'Handshake Type: Client Hello (1)',
            'Length: 512 bytes',
            'Random: a3b4c5d6e7f8... (32 bytes)',
            'Session ID: 32 bytes',
            'Cipher Suites (15 suites offered)',
            'Extension: server_name (secure.college-demo.edu)',
            'Extension: supported_versions (TLS 1.3, TLS 1.2)',
            'Extension: key_share (ECDHE group x25519)'
          ] 
        }
      ],
      hex: [
        { offset: '0000', hex: '16 03 01 02 00 01 00 01 fc 03 03 a3 b4 c5 d6 e7', ascii: '................' },
        { offset: '0010', hex: 'f8 01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd', ascii: '..#Eg.....#Eg...' },
        { offset: '0020', hex: 'ef 20 12 34 56 78 90 ab cd ef 12 34 56 78 90 ab', ascii: '. .4Vx.....4Vx..' },
        { offset: '0030', hex: 'cd ef 00 1e 13 02 13 03 13 01 c0 2c c0 2b c0 30', ascii: '...........,.+.0' }
      ]
    },
    {
      no: 10,
      time: '1.272100',
      source: '93.184.216.34',
      destination: '192.168.1.50',
      protocol: 'TLS',
      length: 1240,
      info: 'Server Hello, Change Cipher Spec, Application Data (Encrypted Handshake)',
      summary: 'Server selects TLS 1.3 cipher suite and supplies key share and certificate.',
      security: 'Server authenticated. Ephemeral keys derived. From this point forward, all data is authenticated and encrypted.',
      tree: [
        { 
          header: 'Transport Layer Security (TLS 1.3 Server Hello)', 
          fields: [
            'Selected Version: TLS 1.3 (0x0304)',
            'Selected Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)',
            'Extension: key_share (Server ECDHE share)',
            'Certificate Chain: X.509 CN=secure.college-demo.edu',
            'Status: Cryptographic Tunnel Established'
          ] 
        }
      ],
      hex: [
        { offset: '0000', hex: '16 03 03 00 7a 02 00 00 76 03 03 d1 84 92 f0 e1', ascii: '....z...v.......' },
        { offset: '0010', hex: '32 a0 b1 c2 d3 e4 f5 01 23 45 67 89 ab cd ef 01', ascii: '2.......#Eg.....' },
        { offset: '0020', hex: '23 45 67 89 ab cd ef 20 e0 f1 a2 b3 c4 d5 e6 f7', ascii: '#Eg.... ........' },
        { offset: '0030', hex: '08 19 2a 3b 4c 5d 6e 7f 13 02 00 00 2e 00 33 00', ascii: '..*;L]n.......3.' }
      ]
    },
    {
      no: 11,
      time: '1.295600',
      source: '192.168.1.50',
      destination: '93.184.216.34',
      protocol: 'TLS',
      length: 342,
      info: 'Application Data (Encrypted Request over TLS 1.3)',
      summary: 'Secure HTTP Request (GET /secure-portal) encapsulated in encrypted TLS Record.',
      security: 'HIGH SECURITY: Payload is 100% encrypted ciphertext. Wireshark sniffer cannot observe URL path, cookies, authorization tokens, or payload bytes.',
      tree: [
        { 
          header: 'Transport Layer Security (TLS Record Layer)', 
          fields: [
            'Content Type: Application Data (23 / 0x17)',
            'Version: TLS 1.2 (0x0303) [Encapsulated]',
            'Length: 288 bytes',
            'Encrypted Application Data: 9f 4a 1b 88 c2 e0 14 77 93 ...',
            'Authentication Tag (AEAD GCM): 16 bytes valid'
          ] 
        }
      ],
      hex: [
        { offset: '0000', hex: '17 03 03 01 20 9f 4a 1b 88 c2 e0 14 77 93 e1 a4', ascii: '.... .J.....w...' },
        { offset: '0010', hex: 'f8 29 4c d0 bb 12 76 8a 3e f5 99 01 ca b7 41 e2', ascii: '.)L...v.>.....A.' },
        { offset: '0020', hex: '55 19 8f de 34 2b c1 aa 90 71 83 ff 12 bc d4 98', ascii: 'U...4+...q......' },
        { offset: '0030', hex: 'ef 04 77 19 28 a3 bf c5 94 3e 88 12 e9 4b cc 12', ascii: '..w.(....>...K..' }
      ]
    },
    {
      no: 12,
      time: '1.341200',
      source: '93.184.216.34',
      destination: '192.168.1.50',
      protocol: 'TLS',
      length: 1480,
      info: 'Application Data (Encrypted Web Response over TLS 1.3)',
      summary: 'Secure HTTP Response payload protected by AES-GCM symmetric cipher.',
      security: 'HIGH SECURITY: Encrypted web page content, database records, and secure cookies cannot be viewed by intermediate routers or eavesdroppers.',
      tree: [
        { 
          header: 'Transport Layer Security (TLS Record Layer)', 
          fields: [
            'Content Type: Application Data (23 / 0x17)',
            'Length: 1426 bytes',
            'Encrypted Application Data: 3d b4 a9 7c 10 8f ...',
            'Data Integrity: Cryptographically verified'
          ] 
        }
      ],
      hex: [
        { offset: '0000', hex: '17 03 03 05 92 3d b4 a9 7c 10 8f ee 92 34 1a 80', ascii: '.....=..|....4..' },
        { offset: '0010', hex: 'aa 71 9b 4d 12 e5 8c fa 09 33 11 bb 84 ee c1 7a', ascii: '.q.M.....3.....z' },
        { offset: '0020', hex: 'e2 81 7a 40 99 a3 c8 22 b1 04 6f 19 82 dc ef 14', ascii: '..z@..."..o.....' },
        { offset: '0030', hex: '01 99 2e 45 b8 1a cc d3 77 12 90 e4 a1 b8 cf 30', ascii: '...E....w......0' }
      ]
    }
  ];

  let currentFilterProtocol = 'ALL';
  let currentSearchQuery = '';
  let selectedPacketNo = 6; // Default to HTTP GET to highlight security contrast immediately

  function initPacketAnalyzer() {
    renderPacketTable();
    initFilters();
    selectPacket(6);
  }

  function renderPacketTable() {
    const tableBody = document.getElementById('packetTableBody');
    if (!tableBody) return;

    const filtered = SAMPLE_PACKETS.filter(pkt => {
      // Protocol filter
      if (currentFilterProtocol !== 'ALL' && pkt.protocol !== currentFilterProtocol) {
        return false;
      }
      // Search query filter
      if (currentSearchQuery) {
        const query = currentSearchQuery.toLowerCase();
        const matches = 
          pkt.source.toLowerCase().includes(query) ||
          pkt.destination.toLowerCase().includes(query) ||
          pkt.protocol.toLowerCase().includes(query) ||
          pkt.info.toLowerCase().includes(query);
        if (!matches) return false;
      }
      return true;
    });

    tableBody.innerHTML = '';

    filtered.forEach(pkt => {
      const row = document.createElement('tr');
      row.className = `packet-row proto-${pkt.protocol.toLowerCase()} ${pkt.no === selectedPacketNo ? 'selected' : ''}`;
      row.setAttribute('data-pkt-no', pkt.no);

      row.innerHTML = `
        <td>${pkt.no}</td>
        <td>${pkt.time}</td>
        <td>${pkt.source}</td>
        <td>${pkt.destination}</td>
        <td><strong>${pkt.protocol}</strong></td>
        <td>${pkt.length}</td>
        <td>${escapeHtml(pkt.info)}</td>
      `;

      row.addEventListener('click', () => {
        selectPacket(pkt.no);
      });

      tableBody.appendChild(row);
    });

    // Update count stat
    const countElem = document.getElementById('packetCountStat');
    if (countElem) {
      countElem.textContent = `Showing ${filtered.length} of ${SAMPLE_PACKETS.length} sample packets`;
    }
  }

  function selectPacket(packetNo) {
    selectedPacketNo = packetNo;
    const pkt = SAMPLE_PACKETS.find(p => p.no === packetNo);
    if (!pkt) return;

    // Highlight row
    const rows = document.querySelectorAll('.packet-row');
    rows.forEach(r => {
      if (parseInt(r.getAttribute('data-pkt-no'), 10) === packetNo) {
        r.classList.add('selected');
      } else {
        r.classList.remove('selected');
      }
    });

    // Render Dissection Tree
    const treeContainer = document.getElementById('dissectTree');
    if (treeContainer) {
      let treeHtml = '';
      pkt.tree.forEach((layer, idx) => {
        treeHtml += `
          <div class="tree-layer">
            <div class="tree-layer-header">
              <span>▶</span>
              <strong>${layer.header}</strong>
            </div>
            <div class="tree-layer-body">
              ${layer.fields.map(f => `<div>• ${f}</div>`).join('')}
            </div>
          </div>
        `;
      });
      treeContainer.innerHTML = treeHtml;
    }

    // Render Hex Dump
    const hexContainer = document.getElementById('hexDumpContent');
    if (hexContainer) {
      let hexHtml = '';
      pkt.hex.forEach(line => {
        hexHtml += `
          <div class="hex-line">
            <span class="hex-offset">${line.offset}</span>
            <span class="hex-bytes">${line.hex}</span>
            <span class="hex-ascii">${escapeHtml(line.ascii)}</span>
          </div>
        `;
      });
      hexContainer.innerHTML = hexHtml;
    }

    // Render Security Insight Banner
    const secSummary = document.getElementById('packetSecSummary');
    if (secSummary) {
      secSummary.innerHTML = `
        <span class="sec-summary-highlight">[Packet #${pkt.no} - ${pkt.protocol}]</span>
        ${pkt.security}
      `;
    }
  }

  function initFilters() {
    const chipBtns = document.querySelectorAll('.chip-btn');
    chipBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        chipBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilterProtocol = btn.getAttribute('data-proto');
        renderPacketTable();
      });
    });

    const searchInput = document.getElementById('packetSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        currentSearchQuery = e.target.value.trim();
        renderPacketTable();
      });
    }

    const clearBtn = document.getElementById('btnFilterClear');
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        if (searchInput) searchInput.value = '';
        currentSearchQuery = '';
        currentFilterProtocol = 'ALL';
        chipBtns.forEach(b => {
          if (b.getAttribute('data-proto') === 'ALL') b.classList.add('active');
          else b.classList.remove('active');
        });
        renderPacketTable();
      });
    }
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  window.PacketModule = {
    init: initPacketAnalyzer,
    selectPacket: selectPacket
  };

})();
