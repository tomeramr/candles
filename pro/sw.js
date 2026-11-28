// Network-first: always load the newest version when online, fall back to cache offline.
const CACHE='candles-pro-v34';
const ASSETS=['./','./index.html','./manifest.webmanifest','./icon-192.png','./icon-512.png','./terms.html','./accessibility.html'];
self.addEventListener('install',e=>{self.skipWaiting();e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).catch(()=>{}))});
self.addEventListener('activate',e=>{e.waitUntil((async()=>{for(const k of await caches.keys())if(k!==CACHE&&k.startsWith('candles-pro'))await caches.delete(k);await self.clients.claim()})())});
self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);
  if(e.request.method!=='GET'||u.origin!==location.origin)return; // market data APIs go straight to the network
  e.respondWith((async()=>{
    try{const r=await fetch(e.request,{cache:'no-store'});const c=await caches.open(CACHE);c.put(e.request,r.clone());return r}
    catch(err){const m=await caches.match(e.request)||await caches.match('./index.html');if(m)return m;throw err}
  })());
});
// Tapping an alert notification opens (or focuses) the app.
self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil((async()=>{
  const all=await self.clients.matchAll({type:'window',includeUncontrolled:true});
  for(const c of all){if('focus' in c)return c.focus()}
  if(self.clients.openWindow)return self.clients.openWindow('./');
})())});
