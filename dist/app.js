// -- Config / limits
  const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50 MB
  const MAX_SHARES = 20;

  // --- shamir over prime 257 (small field optimized for byte-wise shares) ---
  const mod = 257;
  function modNorm(n){ n = n % mod; if (n < 0) n += mod; return n; }
  function modMul(a,b){ return ((a % mod) * (b % mod)) % mod; }
  function modPow(base, exp){ let result=1; base=modNorm(base); while(exp>0){ if (exp&1) result=modMul(result,base); base=modMul(base,base); exp>>=1;} return result; }
  function modInv(a){ let m=mod, x0=1, x1=0; if(m===1) return 0; let aa=modNorm(a); while(aa>1){ let q=Math.floor(aa/m); [aa,m]=[m, aa-q*m]; [x0,x1]=[x1, x0-q*x1]; } return modNorm(x0); }
  function lagrangeAtZero(points){ let s=0; for(let j=0;j<points.length;j++){ let [xj,yj]=points[j]; let num=1, den=1; for(let m=0;m<points.length;m++){ if(m===j) continue; let xm=points[m][0]; num=modMul(num, modNorm(0-xm)); den=modMul(den, modNorm(xj-xm)); } let denomInv=modInv(den); let lj0=modMul(num,denomInv); s=modNorm(s + modMul(yj, lj0)); } return s; }
  function randCoeffs(degree){ if(degree<=0) return []; const arr = new Uint16Array(degree); crypto.getRandomValues(arr); return Array.from(arr).map(v=>v%mod); }

  // helpers: base64 <> ArrayBuffer
  function abToBase64(buf){ let binary=''; const bytes = new Uint8Array(buf); const len = bytes.byteLength; for(let i=0;i<len;i++) binary += String.fromCharCode(bytes[i]); return btoa(binary); }
  function base64ToAb(b64){ const bin = atob(b64); const len = bin.length; const u = new Uint8Array(len); for(let i=0;i<len;i++) u[i]=bin.charCodeAt(i); return u.buffer; }
  function u16ToBase64(u16){ return abToBase64(u16.buffer); }
  function base64ToU16(b64){ const ab = base64ToAb(b64); return new Uint16Array(ab); }

  async function sha256Hex(data){ let buffer; if (typeof data === 'string') buffer = new TextEncoder().encode(data); else if (data instanceof Uint8Array) buffer = data; else buffer = new Uint8Array(data); const hash = await crypto.subtle.digest('SHA-256', buffer); return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join(''); }

  // UI elements
  const secretText = document.getElementById('secretText');
  const secretFile = document.getElementById('secretFile');
  const sharesCountIn = document.getElementById('sharesCount');
  const thresholdIn = document.getElementById('threshold');
  const createBtn = document.getElementById('createBtn');
  const resetCreate = document.getElementById('resetCreate');
  const createResult = document.getElementById('createResult');
  const envelopeOut = document.getElementById('envelopeOut');
  const sharesContainer = document.getElementById('sharesContainer');
  const downloadEnvelopeBtn = document.getElementById('downloadEnvelopeBtn');
  const downloadAllSharesBtn = document.getElementById('downloadAllSharesBtn');
  const copyEnvelopeBtn = document.getElementById('copyEnvelopeBtn');
  const createProgress = document.getElementById('createProgress');
  const createProgressBar = document.getElementById('createProgressBar');

  const envelopeFile = document.getElementById('envelopeFile');
  const shareFiles = document.getElementById('shareFiles');
  const recoverBtn = document.getElementById('recoverBtn');
  const resetRecover = document.getElementById('resetRecover');
  const recoverProgress = document.getElementById('recoverProgress');
  const recoverProgressBar = document.getElementById('recoverProgressBar');
  const recoverResult = document.getElementById('recoverResult');
  const decryptedOut = document.getElementById('decryptedOut');

  const toastEl = document.getElementById('toast');

  let lastShares = null;
  let lastEnvelope = null;

  function showToast(message, type='info', timeout=4500){
    toastEl.textContent = message;
    toastEl.className = 'toast ' + (type==='success'? 'success': type==='error'? 'error': '');
    toastEl.classList.remove('display-none');
    if(timeout>0){
      setTimeout(()=>{
        toastEl.classList.add('display-none');
      }, timeout);
    }
  }

  function setProgress(el, pct){ el.style.width = pct + '%'; }

  function resetCreateUI(){
    createResult.classList.add('display-none');
    sharesContainer.innerHTML='';
    envelopeOut.textContent='';
    downloadEnvelopeBtn.classList.add('display-none');
    downloadAllSharesBtn.classList.add('display-none');
    copyEnvelopeBtn.classList.add('display-none');
  }
  function resetRecoverUI(){
    recoverResult.classList.add('display-none');
    decryptedOut.textContent='';
  }

  resetCreate.addEventListener('click', ()=>{ secretText.value=''; secretFile.value=''; sharesCountIn.value = 3; thresholdIn.value = 2; resetCreateUI(); showToast('Create form reset', 'info', 1500); });
  resetRecover.addEventListener('click', ()=>{ envelopeFile.value=''; shareFiles.value=''; resetRecoverUI(); showToast('Recover form reset', 'info', 1500); });

  // Create handler
  createBtn.addEventListener('click', async ()=>{
    // basic validations
    const sharesCount = Math.min(MAX_SHARES, Math.max(2, parseInt(sharesCountIn.value||3,10)));
    let threshold = Math.min(sharesCount, Math.max(2, parseInt(thresholdIn.value||2,10)));
    if(sharesCount > MAX_SHARES){ showToast('Shares count limited to ' + MAX_SHARES, 'error'); }
    if(!(sharesCount>=2 && threshold>=2 && threshold<=sharesCount)){ showToast('Invalid shares/threshold', 'error'); return; }

    const text = secretText.value.trim();
    const file = secretFile.files[0];
    if(!text && !file){ showToast('Enter a secret or select a file to protect', 'error'); return; }
    if(file && file.size > MAX_FILE_BYTES){ showToast('File too large (max 50 MB)', 'error'); return; }

    createBtn.disabled = true; createBtn.textContent = 'Creating...'; createProgress.style.display='block'; setProgress(createProgressBar, 0);

    try{
      // generate AES-256-GCM key
      const algo = { name: 'AES-GCM', length: 256 };
      const key = await crypto.subtle.generateKey(algo, true, ['encrypt','decrypt']);
      const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key));

      // prepare plaintext bytes
      const iv = crypto.getRandomValues(new Uint8Array(12));
      let plaintextBytes, meta = { type: 'text' };
      if(file){ const buf = await file.arrayBuffer(); plaintextBytes = new Uint8Array(buf); meta = { type:'file', filename: file.name, mime: file.type || 'application/octet-stream' }; }
      else{ plaintextBytes = new TextEncoder().encode(text); }

      setProgress(createProgressBar, 20);

      // encrypt with AES-GCM
      const ctBuf = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, plaintextBytes);
      const ciphertext = new Uint8Array(ctBuf);

      setProgress(createProgressBar, 45);

      // split rawKey into shares (byte-wise Shamir)
      const sharesObj = {};
      for(let i=1;i<=sharesCount;i++) sharesObj[i]=[];
      const degree = threshold - 1;
      for(let b=0;b<rawKey.length;b++){
        const secretByte = rawKey[b];
        const coeffs = randCoeffs(degree);
        for(let i=1;i<=sharesCount;i++){
          let y = secretByte;
          for(let k=0;k<coeffs.length;k++){ const exp = k+1; const term = modMul(coeffs[k], modPow(i, exp)); y = modNorm(y + term); }
          sharesObj[i].push(y);
        }
      }

      setProgress(createProgressBar, 70);

      lastShares = {};
      for(let i=1;i<=sharesCount;i++){
        const u16 = new Uint16Array(sharesObj[i]);
        const base64 = u16ToBase64(u16);
        const hash = await sha256Hex(base64);
        lastShares[i] = { u16, base64, hash };
      }

      setProgress(createProgressBar, 90);

      // envelope
      const envelope = { ciphertext: abToBase64(ciphertext.buffer), iv: abToBase64(iv.buffer), keyLen: rawKey.length, meta };
      lastEnvelope = envelope;

      // UI: show envelope and share download cards
      createResult.classList.remove('display-none');
      envelopeOut.textContent = JSON.stringify(envelope, null, 2);

      sharesContainer.innerHTML = '';
      for(let i=1;i<=sharesCount;i++){
        const shareData = lastShares[i];
        const metaShare = { index: i, share: shareData.base64, keyLen: rawKey.length, threshold, sharesCount, hash: shareData.hash };
        const blob = new Blob([JSON.stringify(metaShare, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const div = document.createElement('div'); div.className='share-card';
        div.innerHTML = `
          <div><strong>Share ${i}</strong></div>
          <div class="small mt-6">Hash: ${shareData.hash}</div>
          <div class="mt-8"><a download="share-${i}.json" href="${url}" class="btn btn-ghost">Download</a></div>
        `;
        sharesContainer.appendChild(div);
      }

      downloadEnvelopeBtn.classList.remove('display-none');
      downloadAllSharesBtn.classList.remove('display-none');
      copyEnvelopeBtn.classList.remove('display-none');

      setProgress(createProgressBar, 100);
      showToast('Shares created — download envelope & share files.', 'success');

    }catch(err){ console.error(err); showToast('Error during creation. See console.', 'error'); }
    finally{
      createBtn.disabled=false; createBtn.textContent='Create shares & encrypt';
      setTimeout(()=>{
        createProgress.classList.add('display-none');
        setProgress(createProgressBar,0);
      }, 700);
    }
  });

  // downloads
  downloadEnvelopeBtn.addEventListener('click', ()=>{ if(!lastEnvelope) return; const blob = new Blob([JSON.stringify(lastEnvelope, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href=url; a.download='envelope.json'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url); showToast('Envelope downloaded', 'success', 1400); });

  copyEnvelopeBtn.addEventListener('click', async ()=>{ if(!lastEnvelope) return; try{ await navigator.clipboard.writeText(JSON.stringify(lastEnvelope, null, 2)); showToast('Envelope copied to clipboard', 'success'); }catch(e){ showToast('Clipboard copy failed', 'error'); } });

  downloadAllSharesBtn.addEventListener('click', async ()=>{
    if(!lastShares) return; const zip = new JSZip();
    for(const idx in lastShares){ const shareData = lastShares[idx]; const meta = { index: parseInt(idx,10), share: shareData.base64, keyLen: lastEnvelope.keyLen, threshold: parseInt(thresholdIn.value,10), sharesCount: parseInt(sharesCountIn.value,10), hash: shareData.hash }; zip.file(`share-${idx}.json`, JSON.stringify(meta, null, 2)); }
    try{ const content = await zip.generateAsync({ type:'blob' }); const url = URL.createObjectURL(content); const a = document.createElement('a'); a.href=url; a.download='shares.zip'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url); showToast('ZIP downloaded', 'success'); }catch(e){ console.error(e); showToast('ZIP creation failed', 'error'); }
  });

  // Recover
  recoverBtn.addEventListener('click', async ()=>{
    resetRecoverUI();
    const envFile = envelopeFile.files[0];
    if(!envFile){ showToast('Select envelope JSON', 'error'); return; }
    let envelope;
    try{ envelope = JSON.parse(await envFile.text()); }catch(e){ showToast('Invalid envelope JSON', 'error'); return; }
    if(!envelope.ciphertext || !envelope.iv || !envelope.keyLen){ showToast('Envelope missing fields', 'error'); return; }

    const files = Array.from(shareFiles.files || []);
    if(files.length < 2){ showToast('Select at least 2 share files', 'error'); return; }

    recoverBtn.disabled=true; recoverBtn.textContent='Reconstructing...'; recoverProgress.classList.remove('display-none'); setProgress(recoverProgressBar,0);

    try{
      const sharesMap = {};
      let invalid = 0;
      for(const f of files){
        try{
          const obj = JSON.parse(await f.text());
          if(!obj.index || !obj.share || !obj.hash){ invalid++; continue; }
          const computed = await sha256Hex(obj.share);
          if(computed !== obj.hash){ invalid++; continue; }
          const u16 = base64ToU16(obj.share);
          sharesMap[obj.index] = u16;
        }catch(e){ invalid++; continue; }
      }
      const indices = Object.keys(sharesMap).map(x=>parseInt(x,10)).sort((a,b)=>a-b);
      if(indices.length < 2){ showToast('Insufficient valid shares', 'error'); return; }
      if(invalid>0) showToast(invalid + ' invalid share(s) ignored', 'error', 3500);

      setProgress(recoverProgressBar, 25);

      const sharesObj = {};
      for(const idx of indices) sharesObj[idx] = Array.from(sharesMap[idx]);

      const keyLen = envelope.keyLen;
      const recovered = new Uint8Array(keyLen);
      for(let b=0;b<keyLen;b++){
        const points = indices.map(i => [i, sharesObj[i][b]]);
        const val = lagrangeAtZero(points);
        recovered[b] = val;
      }

      setProgress(recoverProgressBar, 60);

      try{
        const imported = await crypto.subtle.importKey('raw', recovered.buffer, { name: 'AES-GCM' }, false, ['decrypt']);
        const ctBuf = base64ToAb(envelope.ciphertext);
        const ivBuf = base64ToAb(envelope.iv);
        const decryptedBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv: new Uint8Array(ivBuf) }, imported, ctBuf);
        const dec = new Uint8Array(decryptedBuf);

        recoverResult.classList.remove('display-none');

        if(envelope.meta && envelope.meta.type === 'file'){
          const blob = new Blob([dec.buffer], { type: envelope.meta.mime || 'application/octet-stream' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a'); a.href=url; a.download = envelope.meta.filename || 'recovered.bin'; a.textContent = `Download recovered file (${a.download})`; decryptedOut.innerHTML=''; decryptedOut.appendChild(a);
          showToast('File ready to download', 'success');
        }else{
          const text = new TextDecoder().decode(dec);
          decryptedOut.textContent = text;
          const blob = new Blob([text], { type:'text/plain' }); const url = URL.createObjectURL(blob);
          const a = document.createElement('a'); a.href=url; a.download='recovered.txt'; a.textContent='Download as .txt'; decryptedOut.appendChild(document.createElement('br')); decryptedOut.appendChild(a);
          showToast('Decryption successful', 'success');
        }

        setProgress(recoverProgressBar, 100);
      }catch(e){ console.error(e); showToast('Decrypt failed: invalid key or tampered envelope', 'error'); }

    }catch(err){ console.error(err); showToast('Reconstruction error', 'error'); }
    finally{
      recoverBtn.disabled=false; recoverBtn.textContent='Reconstruct & decrypt';
      setTimeout(()=>{
        recoverProgress.classList.add('display-none');
        setProgress(recoverProgressBar,0);
      },700);
    }
  })