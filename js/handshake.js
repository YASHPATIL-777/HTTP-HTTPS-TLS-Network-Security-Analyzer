/**
 * HTTP/HTTPS/TLS Network Security Analyzer - TLS Handshake Interactive Flow Module
 * Educational Step-by-Step Visualization of TLS Handshake
 */

(function () {
  'use strict';

  const HANDSHAKE_STEPS = [
    {
      step: 1,
      title: 'Client Hello',
      direction: 'Client → Server',
      protocol: 'TLS Handshake Protocol (Type 1)',
      wiresharkFilter: 'tls.handshake.type == 1',
      summary: 'The client initiates the TLS session by sending cryptographic capabilities, supported protocols, and a random challenge.',
      fields: [
        { name: 'Protocol Version', value: 'TLS 1.3 (record version TLS 1.2 for backward compatibility)' },
        { name: 'Client Random', value: '32-byte cryptographically secure pseudorandom number' },
        { name: 'Cipher Suites', value: 'TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256' },
        { name: 'Extension: SNI', value: 'server_name = secure.college-demo.edu' },
        { name: 'Extension: Key Share', value: 'ECDHE public key (e.g., x25519 curve parameter)' },
        { name: 'Supported Groups', value: 'x25519, secp256r1' }
      ],
      explanation: 'In this packet, the browser declares which encryption algorithms it supports and immediately sends an ephemeral public key share (in TLS 1.3) to enable 1-RTT key derivation.',
      securityTip: 'Plaintext Exposure: In TLS 1.2 and standard TLS 1.3 without ECH (Encrypted Client Hello), the SNI extension leaks the destination domain name to eavesdroppers.'
    },
    {
      step: 2,
      title: 'Server Hello & Key Share',
      direction: 'Server → Client',
      protocol: 'TLS Handshake Protocol (Type 2)',
      wiresharkFilter: 'tls.handshake.type == 2',
      summary: 'The server agrees on the cryptographic parameters and sends its own ephemeral key share.',
      fields: [
        { name: 'Selected Version', value: 'TLS 1.3 (0x0304)' },
        { name: 'Server Random', value: '32-byte server random number' },
        { name: 'Selected Cipher Suite', value: 'TLS_AES_256_GCM_SHA384' },
        { name: 'Extension: Key Share', value: 'Server ECDHE public key share' }
      ],
      explanation: 'The server selects the strongest mutually supported cipher suite and returns its ECDHE public key. At this point, both parties have enough information to derive the shared secret!',
      securityTip: 'Cipher Downgrade Protection: TLS 1.3 embeds specific signature bytes in the Server Random if downgrading to prevent MITM rollback attacks.'
    },
    {
      step: 3,
      title: 'Certificate & Authentication',
      direction: 'Server → Client',
      protocol: 'TLS Handshake Protocol (Type 11 / 15)',
      wiresharkFilter: 'tls.handshake.type == 11 || tls.handshake.certificate',
      summary: 'The server proves its identity by presenting an X.509 digital certificate signed by a trusted Certificate Authority (CA).',
      fields: [
        { name: 'Certificate Subject', value: 'CN=secure.college-demo.edu, O=Cybersecurity Lab' },
        { name: 'Issuer CA', value: 'CN=DigiCert Global Root G2, O=DigiCert Inc' },
        { name: 'Validity Period', value: 'Valid from Oct 2026 to Oct 2027' },
        { name: 'Public Key Info', value: 'RSA 4096 bits or ECC NIST P-256' },
        { name: 'Certificate Verify', value: 'Digital signature made with the server private key' }
      ],
      explanation: 'The client verifies the certificate chain up to its local root trust store. It checks certificate expiration, domain matching, and revocation status (OCSP/CRL).',
      securityTip: 'MITM Defense: This prevents an attacker from masquerading as the bank or college server. Without the corresponding private key, an attacker cannot forge the Certificate Verify signature.'
    },
    {
      step: 4,
      title: 'Key Derivation (Diffie-Hellman)',
      direction: 'Internal Computation (Both Parties)',
      protocol: 'Cryptographic HKDF Derivation',
      wiresharkFilter: 'Not visible in Wireshark (Calculated in RAM)',
      summary: 'Both the client and server use the exchanged public key shares to compute the identical master secret independently.',
      fields: [
        { name: 'Shared Secret (Z)', value: 'ECDH_compute(Client_Priv, Server_Pub) == ECDH_compute(Server_Priv, Client_Pub)' },
        { name: 'Key Derivation Function', value: 'HKDF-Extract & HKDF-Expand (HMAC-SHA384)' },
        { name: 'Derived Keys', value: 'Client Write Key, Server Write Key, Client IV, Server IV' }
      ],
      explanation: 'Because of the mathematical properties of Elliptic-Curve Diffie-Hellman (ECDHE), an eavesdropper recording all network packets cannot calculate the shared secret without solving the discrete logarithm problem.',
      securityTip: 'Forward Secrecy: Because ephemeral keys are discarded immediately after session termination, even if the server private key is stolen in the future, past recorded sessions cannot be decrypted.'
    },
    {
      step: 5,
      title: 'Finished / Handshake Complete',
      direction: 'Bidirectional (Encrypted)',
      protocol: 'TLS Handshake Protocol (Type 20)',
      wiresharkFilter: 'tls.handshake.type == 20',
      summary: 'Each party sends an encrypted Finished message containing a cryptographic MAC of the entire handshake transcript.',
      fields: [
        { name: 'Verify Data', value: 'HMAC(handshake_secret, transcript_hash)' },
        { name: 'Status', value: 'Symmetric encryption now active' }
      ],
      explanation: 'This final handshake message confirms that no packet was tampered with or modified by a middleman during negotiation.',
      securityTip: 'Transcript Integrity: If a hacker altered the cipher suite list in Step 1 to force weak ciphers, the transcript hash will fail to match and the connection aborts.'
    },
    {
      step: 6,
      title: 'Encrypted Application Data',
      direction: 'Client ↔ Server (Full Duplex)',
      protocol: 'TLS Record Layer (Content Type 23)',
      wiresharkFilter: 'tls.record.content_type == 23',
      summary: 'HTTP requests (GET, POST, headers, cookies, credentials) and responses are transmitted as authenticated ciphertext.',
      fields: [
        { name: 'Record Header', value: '0x17 0x03 0x03 (Opaque Content Type: Application Data)' },
        { name: 'Cipher Algorithm', value: 'AEAD AES-256-GCM' },
        { name: 'Payload Visibility', value: 'Indistinguishable from random noise (100% Ciphertext)' },
        { name: 'Authentication Tag', value: '16-byte Poly1305 / GCM Tag verifying integrity' }
      ],
      explanation: 'All subsequent web communications travel safely inside this encrypted tunnel. Wireshark shows only packet lengths and encrypted hex blobs.',
      securityTip: 'Complete Privacy: Eavesdroppers on Wi-Fi or routers cannot read user passwords, cookies, or sensitive academic records.'
    }
  ];

  let currentStepIndex = 0;

  function initHandshakeViewer() {
    renderStepsList();
    displayStep(0);

    const prevBtn = document.getElementById('btnPrevHandshake');
    const nextBtn = document.getElementById('btnNextHandshake');

    if (prevBtn) {
      prevBtn.addEventListener('click', () => {
        if (currentStepIndex > 0) {
          displayStep(currentStepIndex - 1);
        }
      });
    }

    if (nextBtn) {
      nextBtn.addEventListener('click', () => {
        if (currentStepIndex < HANDSHAKE_STEPS.length - 1) {
          displayStep(currentStepIndex + 1);
        }
      });
    }
  }

  function renderStepsList() {
    const listContainer = document.getElementById('handshakeStepsList');
    if (!listContainer) return;

    listContainer.innerHTML = '';
    HANDSHAKE_STEPS.forEach((s, idx) => {
      const stepCard = document.createElement('div');
      stepCard.className = `handshake-step-card ${idx === 0 ? 'active' : ''}`;
      stepCard.setAttribute('data-step-idx', idx);
      stepCard.innerHTML = `
        <div class="step-number">${s.step}</div>
        <div class="step-details">
          <h4>${s.title}</h4>
          <p>${s.summary}</p>
        </div>
        <div class="step-direction">${s.direction}</div>
      `;
      stepCard.addEventListener('click', () => displayStep(idx));
      listContainer.appendChild(stepCard);
    });
  }

  function displayStep(index) {
    currentStepIndex = index;
    const step = HANDSHAKE_STEPS[index];
    if (!step) return;

    // Update active step styling in list
    const stepCards = document.querySelectorAll('.handshake-step-card');
    stepCards.forEach((c, i) => {
      if (i === index) c.classList.add('active');
      else c.classList.remove('active');
    });

    // Update Detail Panel
    const detailTitle = document.getElementById('hsDetailTitle');
    const detailBadge = document.getElementById('hsDetailBadge');
    const detailFilter = document.getElementById('hsDetailFilter');
    const detailDesc = document.getElementById('hsDetailDesc');
    const detailFields = document.getElementById('hsDetailFields');
    const detailTip = document.getElementById('hsDetailTip');

    if (detailTitle) detailTitle.textContent = `Step ${step.step}: ${step.title}`;
    if (detailBadge) detailBadge.textContent = step.direction;
    if (detailFilter) detailFilter.textContent = step.wiresharkFilter;
    if (detailDesc) detailDesc.textContent = step.explanation;

    if (detailFields) {
      let fieldsHtml = '';
      step.fields.forEach(f => {
        fieldsHtml += `
          <div class="spec-key">${f.name}:</div>
          <div class="spec-val">${f.value}</div>
        `;
      });
      detailFields.innerHTML = fieldsHtml;
    }

    if (detailTip) {
      detailTip.innerHTML = `<strong>Security Takeaway:</strong> ${step.securityTip}`;
    }

    // Update Prev/Next buttons
    const prevBtn = document.getElementById('btnPrevHandshake');
    const nextBtn = document.getElementById('btnNextHandshake');
    if (prevBtn) prevBtn.disabled = index === 0;
    if (nextBtn) nextBtn.disabled = index === HANDSHAKE_STEPS.length - 1;
  }

  window.HandshakeModule = {
    init: initHandshakeViewer,
    displayStep: displayStep
  };

})();
