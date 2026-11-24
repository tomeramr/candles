/* קורא נרות פרו: subscription bar + periodic license check (injected by tools/build_pro.py) */
(function(){
  let key='',iid='',api='',portal='';
  try{key=sessionStorage.getItem('pro_key')||'';iid=sessionStorage.getItem('pro_iid')||'';api=sessionStorage.getItem('pro_api')||'';portal=sessionStorage.getItem('pro_portal')||''}catch(e){}
  const wipe=()=>{try{localStorage.removeItem('pro_saved');localStorage.removeItem('pro_html');['pro_key','pro_iid','pro_api','pro_portal','pro_name'].forEach(k=>sessionStorage.removeItem(k))}catch(e){}};
  const lock=reason=>{wipe();try{localStorage.setItem('pro_msg',reason)}catch(e){}location.reload()};
  if(!key){lock('invalid');return}
  if(!/^https:\/\/[^\s"'<>]+$/.test(portal))portal='';
  const bar=document.createElement('div');bar.setAttribute('role','region');bar.setAttribute('aria-label','מנוי');
  bar.style.cssText='background:#e8f1ff;color:#123b7a;text-align:center;padding:6px 8px;font-size:13px;font-weight:600;display:flex;gap:6px 14px;justify-content:center;flex-wrap:wrap';
  const L=window.__LIC||{};
  bar.innerHTML='<span id="proWho"></span>'
    +(portal?'<a href="'+portal.replace(/"/g,'')+'" target="_blank" rel="noopener" style="color:inherit">ניהול מנוי</a>':'')
    +'<a href="terms.html" style="color:inherit">תקנון</a><a href="accessibility.html" style="color:inherit">נגישות</a>'
    +'<a href="#" id="proOut" style="color:inherit">יציאה</a>';
  document.body.prepend(bar);
  document.getElementById('proWho').textContent=L.guest?`🎟️ גישת אורח · ${L.label||''}${L.until?' · עד '+new Date(L.until).toLocaleDateString('he-IL'):''}`:`✅ קורא נרות פרו · מנוי פעיל${L.label?' · '+L.label:''}`;
  document.getElementById('proOut').addEventListener('click',async e=>{e.preventDefault();
    if(!confirm('לצאת מהחשבון במכשיר הזה? המכשיר יפנה מקום לרישיון שלך במכשיר אחר.'))return;
    if(!L.guest)try{await fetch(api.replace(/\/+$/,'')+'/release',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key,iid}),keepalive:true})}catch(e){}
    wipe();try{localStorage.setItem('pro_msg','logout')}catch(e){}location.reload()});
  const ver=(document.querySelector('meta[name="app-version"]')||{}).content||'';
  let last=Date.now();
  async function ping(){if(!api)return;last=Date.now();
    try{const r=await fetch(api.replace(/\/+$/,'')+'/ping',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key,iid,ver})});
      const j=await r.json().catch(()=>({}));
      if(j&&j.ok===false&&['invalid','expired','disabled','wrong_product','bad_key'].includes(j.reason))lock(j.reason);
      else if(j&&j.ok){try{const s=JSON.parse(localStorage.getItem('pro_saved')||'null');if(s){s.ok=Date.now();localStorage.setItem('pro_saved',JSON.stringify(s))}}catch(e){}}
    }catch(e){}}
  setTimeout(ping,4000);
  setInterval(()=>{if(!document.hidden)ping()},180000);
  document.addEventListener('visibilitychange',()=>{if(!document.hidden&&Date.now()-last>180000)ping()});
})();
