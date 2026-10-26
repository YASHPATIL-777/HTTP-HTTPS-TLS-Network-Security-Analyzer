/**
 * HTTP/HTTPS/TLS Network Security Analyzer - Wireshark Evidence Gallery Module
 * Handles Preloaded Experiment Captures & Interactive Local Screenshot Uploads
 */

(function () {
  'use strict';

  // Initial Preloaded Actual Evidence Captures from user's cryptography project
  const DEFAULT_EVIDENCE = [
    {
      id: 'exp-a',
      title: 'Experiment A: Plaintext HTTP Packet Capture (Port 80)',
      category: 'HTTP',
      isVerified: true,
      badgeText: 'Actual Evidence',
      badgeClass: 'badge-verified',
      imageSrc: 'assets/evidence/Experiment_A_HTTP.png',
      isPdf: false,
      date: 'Captured Lab Session',
      desc: 'Wireshark packet capture displaying plaintext HTTP traffic on TCP port 80. The protocol dissection reveals visible HTTP GET requests, unencrypted headers, and application payload in clear ASCII text.'
    },
    {
      id: 'exp-b',
      title: 'Experiment B: Encrypted HTTPS / TLS Traffic (Port 443)',
      category: 'HTTPS',
      isVerified: true,
      badgeText: 'Actual Evidence',
      badgeClass: 'badge-verified',
      imageSrc: 'assets/evidence/Experiment_B_HTTPS_TLS.png',
      isPdf: false,
      date: 'Captured Lab Session',
      desc: 'Wireshark packet capture displaying encrypted HTTPS traffic on TCP port 443. The application payload is encapsulated in TLS Record layers, preventing passive eavesdroppers from viewing URL paths or credentials.'
    },
    {
      id: 'exp-c',
      title: 'Experiment C: TLS Handshake & Certificate Verification',
      category: 'TLS',
      isVerified: true,
      badgeText: 'Actual Evidence (PDF Report)',
      badgeClass: 'badge-verified',
      imageSrc: 'assets/evidence/Experiment_B_HTTPS_TLS.png', // Preview image
      pdfSrc: 'assets/evidence/Experiment_C_TLS_Handshake.png.pdf',
      isPdf: true,
      date: 'Captured Lab Session',
      desc: 'Captured documentation and packet analysis of the TLS cryptographic handshake, detailing Client Hello, Server Hello, and X.509 certificate validation.'
    }
  ];

  let evidenceList = [];

  function initEvidenceGallery() {
    loadEvidence();
    renderGallery();
    initUploader();
    initLightbox();
  }

  function loadEvidence() {
    // Check localStorage for any user uploaded items
    const saved = localStorage.getItem('user_wireshark_evidence');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        evidenceList = [...DEFAULT_EVIDENCE, ...parsed];
      } catch (e) {
        evidenceList = [...DEFAULT_EVIDENCE];
      }
    } else {
      evidenceList = [...DEFAULT_EVIDENCE];
    }
  }

  function renderGallery() {
    const grid = document.getElementById('evidenceGrid');
    if (!grid) return;

    grid.innerHTML = '';
    evidenceList.forEach(item => {
      const card = document.createElement('div');
      card.className = 'evidence-card';
      card.setAttribute('data-id', item.id);

      const thumbHtml = item.isPdf
        ? `<div class="evidence-thumbnail-wrap" title="Click to view full details">
             <img src="${item.imageSrc}" alt="${item.title}" class="evidence-thumbnail" />
             <div class="evidence-badge-overlay">
               <span class="badge ${item.badgeClass}">${item.badgeText}</span>
             </div>
           </div>`
        : `<div class="evidence-thumbnail-wrap" title="Click to inspect screenshot">
             <img src="${item.imageSrc}" alt="${item.title}" class="evidence-thumbnail" />
             <div class="evidence-badge-overlay">
               <span class="badge ${item.badgeClass}">${item.badgeText}</span>
             </div>
           </div>`;

      card.innerHTML = `
        ${thumbHtml}
        <div class="evidence-info">
          <h3 class="evidence-title">${item.title}</h3>
          <p class="evidence-desc">${item.desc}</p>
          <div class="evidence-footer">
            <span><strong>Category:</strong> ${item.category}</span>
            <span>${item.date}</span>
          </div>
        </div>
      `;

      card.querySelector('.evidence-thumbnail-wrap').addEventListener('click', () => {
        openLightbox(item);
      });

      grid.appendChild(card);
    });
  }

  // Upload Area Handling
  function initUploader() {
    const fileInput = document.getElementById('evidenceFileInput');
    const dropzone = document.getElementById('evidenceDropzone');
    const uploadForm = document.getElementById('evidenceUploadForm');

    if (!dropzone || !fileInput) return;

    dropzone.addEventListener('click', () => fileInput.click());

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-over');
    });

    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('drag-over');
    });

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-over');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        fileInput.files = e.dataTransfer.files;
        handleFileSelection(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleFileSelection(e.target.files[0]);
      }
    });

    if (uploadForm) {
      uploadForm.addEventListener('submit', (e) => {
        e.preventDefault();
        submitUploadedEvidence();
      });
    }
  }

  let pendingImageData = null;

  function handleFileSelection(file) {
    if (!file.type.startsWith('image/')) {
      alert('Please select a valid image file (PNG, JPG, WEBP).');
      return;
    }

    const reader = new FileReader();
    reader.onload = function (e) {
      pendingImageData = e.target.result;
      const previewImg = document.getElementById('uploadPreviewImg');
      const previewContainer = document.getElementById('uploadPreviewContainer');
      const dropPrompt = document.getElementById('dropPrompt');

      if (previewImg && previewContainer && dropPrompt) {
        previewImg.src = pendingImageData;
        previewContainer.style.display = 'block';
        dropPrompt.style.display = 'none';
      }
    };
    reader.readAsDataURL(file);
  }

  function submitUploadedEvidence() {
    if (!pendingImageData) {
      alert('Please select an image file first.');
      return;
    }

    const titleInput = document.getElementById('uploadTitle');
    const descInput = document.getElementById('uploadDesc');
    const catInput = document.getElementById('uploadCategory');

    const title = titleInput ? titleInput.value.trim() : 'User Evidence Screenshot';
    const desc = descInput ? descInput.value.trim() : 'Locally uploaded Wireshark capture screenshot for demonstration.';
    const category = catInput ? catInput.value : 'General';

    if (!title) {
      alert('Please enter an evidence title.');
      return;
    }

    const newItem = {
      id: 'custom-' + Date.now(),
      title: title,
      category: category,
      isVerified: true,
      badgeText: 'User Uploaded',
      badgeClass: 'badge-info',
      imageSrc: pendingImageData,
      isPdf: false,
      date: new Date().toLocaleDateString(),
      desc: desc
    };

    // Save to localStorage
    const saved = localStorage.getItem('user_wireshark_evidence');
    let userItems = [];
    if (saved) {
      try { userItems = JSON.parse(saved); } catch (e) { userItems = []; }
    }
    userItems.push(newItem);
    try {
      localStorage.setItem('user_wireshark_evidence', JSON.stringify(userItems));
    } catch (e) {
      console.warn('Storage quota exceeded, displaying in current session only');
    }

    evidenceList.push(newItem);
    renderGallery();

    // Reset upload form
    if (titleInput) titleInput.value = '';
    if (descInput) descInput.value = '';
    pendingImageData = null;
    const previewContainer = document.getElementById('uploadPreviewContainer');
    const dropPrompt = document.getElementById('dropPrompt');
    if (previewContainer) previewContainer.style.display = 'none';
    if (dropPrompt) dropPrompt.style.display = 'block';

    alert('Evidence screenshot added to gallery successfully!');
  }

  // Lightbox Modal
  function initLightbox() {
    const modal = document.getElementById('evidenceModal');
    const closeBtn = document.getElementById('btnModalClose');

    if (closeBtn && modal) {
      closeBtn.addEventListener('click', () => {
        modal.classList.remove('active');
      });

      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          modal.classList.remove('active');
        }
      });
    }
  }

  function openLightbox(item) {
    const modal = document.getElementById('evidenceModal');
    if (!modal) return;

    document.getElementById('modalTitle').textContent = item.title;
    const imgElem = document.getElementById('modalImg');
    if (imgElem) {
      imgElem.src = item.imageSrc;
      imgElem.alt = item.title;
    }

    const modalDesc = document.getElementById('modalDesc');
    if (modalDesc) {
      let descHtml = `<p>${item.desc}</p>`;
      if (item.pdfSrc) {
        descHtml += `<div style="margin-top: 1rem;">
          <a href="${item.pdfSrc}" target="_blank" class="btn btn-primary btn-sm">
            📄 Open Original PDF Report (${item.pdfSrc})
          </a>
        </div>`;
      }
      modalDesc.innerHTML = descHtml;
    }

    modal.classList.add('active');
  }

  window.EvidenceModule = {
    init: initEvidenceGallery,
    openLightbox: openLightbox
  };

})();
