const $=s=>document.querySelector(s);function note(msg,bad=false){const n=$('#notice');n.textContent=msg;n.className='notice'+(bad?' error':'');n.style.display='block'}async function api(path,opts={}){const r=await fetch(path,{credentials:'same-origin',...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.detail||'Request failed ('+r.status+')');return d}let deviceMap=null,deviceMarkers=null;
function initDeviceMap(){
 if(typeof L==='undefined'){$('#deviceMap').textContent='Map library could not be loaded. Device location details remain available in the table.';return}
 if(deviceMap)return;
 deviceMap=L.map('deviceMap').setView([22.5,79],4);
 L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:18,attribution:'© OpenStreetMap'}).addTo(deviceMap);
 deviceMarkers=L.featureGroup().addTo(deviceMap);
}
function renderDeviceMap(devices){
 initDeviceMap();if(!deviceMap||!deviceMarkers)return;
 deviceMarkers.clearLayers();
 (devices||[]).forEach(d=>{
  const lat=Number(d.latitude),lon=Number(d.longitude);
  if(!Number.isFinite(lat)||!Number.isFinite(lon)||lat < -90||lat > 90||lon < -180||lon > 180)return;
  const place=[d.city,d.region,d.country].filter(Boolean).join(', ')||'Location unavailable';
  const popup='<b>'+esc(d.device_id)+'</b><br>'+esc(place)+'<br>'+esc(d.public_ip||'Public IP unavailable')+'<br><small>Approximate IP location — not GPS</small>';
  L.marker([lat,lon]).bindPopup(popup).addTo(deviceMarkers);
 });
 if(deviceMarkers.getLayers().length){deviceMap.fitBounds(deviceMarkers.getBounds().pad(0.18));}
 else {deviceMap.setView([22.5,79],4);}
 setTimeout(()=>deviceMap.invalidateSize(),100);
}
async function load(){
 try{
  const d=await api('/api/admin/devices'),a=d.devices||[];
  $('#total').textContent=d.count??a.length;
  $('#inventory').textContent=a.filter(x=>x.status==='inventory').length;
  $('#claimed').textContent=a.filter(x=>x.status==='claimed').length;
  $('#blocked').textContent=a.filter(x=>x.status==='blocked').length;
  const isOnline=x=>!!x.last_seen&&(Date.now()-Date.parse(x.last_seen)<30*60*1000);
  $('#online').textContent=a.filter(isOnline).length;
  $('#rows').innerHTML=a.length?a.map(x=>{
   const place=[x.city,x.region,x.country].filter(Boolean).join(', ')||'Not reported';
   const seen=x.last_seen?new Date(x.last_seen).toLocaleString():'Never';
   const publicIp=x.public_ip||'Public IP unavailable';
   const lanIp=x.lan_ip||'LAN IP unavailable';
   const coord=Number.isFinite(Number(x.latitude))&&Number.isFinite(Number(x.longitude))?'<br><small>'+Number(x.latitude).toFixed(4)+', '+Number(x.longitude).toFixed(4)+'</small>':'';
   const live=isOnline(x),state=x.status+' · '+(live?'Online':'Offline');
   const ledCfg=x.led_test||{led1:'#ff00ff',led5:'#00ffff'};
   return '<tr><td><b>'+esc(x.device_id)+'</b><br><small>'+esc(x.hardware_model||'ESP32-C3')+'</small></td><td><span class="pill">'+esc(state)+'</span></td><td>'+esc(x.claimed_by||'—')+'</td><td>'+esc(seen)+'</td><td>'+esc(place)+'<br><small>LAN: '+esc(lanIp)+'</small><br><small>Public: '+esc(publicIp)+'</small>'+coord+'</td><td><div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center"><button class="btn secondary restart-device" data-device="'+esc(x.device_id)+'" type="button">↻ Restart</button><button class="btn secondary rotate-device-token" data-device="'+esc(x.device_id)+'" type="button">Rotate token</button></div><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px"><label style="font-size:11px">LED A <input class="led-color" data-device="'+esc(x.device_id)+'" data-led="led1" type="color" value="'+esc(ledCfg.led1)+'" aria-label="LED A color"></label><label style="font-size:11px">LED B <input class="led-color" data-device="'+esc(x.device_id)+'" data-led="led5" type="color" value="'+esc(ledCfg.led5)+'" aria-label="LED B color"></label><button class="btn secondary save-led-colors" data-device="'+esc(x.device_id)+'" type="button">Apply colors</button></div></td></tr>'
  }).join(''):'<tr><td colspan="6" class="empty">No devices have been registered yet.</td></tr>';
  document.querySelectorAll('.rotate-device-token').forEach(button=>button.addEventListener('click',()=>rotateDeviceToken(button.dataset.device)));
  document.querySelectorAll('.restart-device').forEach(button=>button.addEventListener('click',()=>restartDevice(button.dataset.device)));
  document.querySelectorAll('.save-led-colors').forEach(button=>button.addEventListener('click',()=>saveLedColors(button.dataset.device)));

  renderDeviceMap(a);
 }catch(e){note(e.message,true);if(e.message.includes('sign in')||e.message.includes('Session'))showLogin()}
}
async function restartDevice(deviceId){
 if(!confirm('Restart device '+deviceId+'? It will reboot when it receives the next heartbeat.'))return;
 try{const d=await api('/api/admin/devices/'+encodeURIComponent(deviceId)+'/restart',{method:'POST',body:'{}'});note('Restart command queued for '+deviceId+'. '+d.message); }catch(e){note(e.message,true)}
}
async function saveLedColors(deviceId){
 const fields=[...document.querySelectorAll('.led-color[data-device="'+CSS.escape(deviceId)+'"]')];
 const payload={led1:fields.find(x=>x.dataset.led==='led1')?.value||'#ff00ff',led5:fields.find(x=>x.dataset.led==='led5')?.value||'#00ffff'};
 try{await api('/api/admin/devices/'+encodeURIComponent(deviceId)+'/led-test',{method:'PUT',body:JSON.stringify(payload)});note('LED test colors saved for '+deviceId+'. They apply on the device next heartbeat.');}catch(e){note(e.message,true)}
}

async function rotateDeviceToken(deviceId){
 if(!confirm('Rotate the heartbeat token for '+deviceId+'? The old token will stop working.'))return;
 try{
  const d=await api('/api/admin/devices/'+encodeURIComponent(deviceId)+'/token',{method:'POST',body:'{}'});
  $('#devicetoken').textContent=d.device_token;
  $('#tokenbox').style.display='block';
  note('New heartbeat token issued for '+deviceId+'. Copy it now and enter it in the local setup page. The old token is invalid.');
 }catch(e){note(e.message,true)}
}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function showLogin(){$('#loginpanel').hidden=false;$('#apparea').hidden=true}function showApp(){$('#loginpanel').hidden=true;$('#apparea').hidden=false;load();loadBlocklist()}$('#loginform').onsubmit=async e=>{e.preventDefault();try{await api('/api/admin/login',{method:'POST',body:JSON.stringify({username:$('#username').value,password:$('#password').value})});$('#password').value='';note('Login successful');showApp()}catch(x){note(x.message,true)}};$('#logout').onclick=async()=>{await api('/api/logout',{method:'POST',body:'{}'});showLogin();note('You have been logged out.')};$('#register').onclick=async()=>{const id=$('#deviceid').value.trim().toUpperCase();if(!id)return note('Factory MAC Device ID is required.',true);try{const d=await api('/api/admin/devices',{method:'POST',body:JSON.stringify({device_id:id,hardware_model:'ESP32-C3-SuperMini',notes:$('#notes').value.trim()})});$('#claimtoken').textContent=d.claim_token;$('#devicetoken').textContent=d.device_token;$('#tokenbox').style.display='block';$('#deviceid').value='';$('#notes').value='';note('Device registered. Save both one-time tokens; enter the device token in local setup.');load()}catch(e){note(e.message,true)}};$('#copytoken').onclick=()=>navigator.clipboard.writeText($('#claimtoken').textContent).then(()=>note('Claim token copied'));$('#copydevicetoken').onclick=()=>navigator.clipboard.writeText($('#devicetoken').textContent).then(()=>note('Device token copied'));$('#refresh').onclick=load;$('#refreshMap').onclick=load;api('/api/admin/session').then(showApp).catch(showLogin);
// Refresh device presence, IP addresses and map while the dashboard is open.
setInterval(()=>{if(!$('#apparea').hidden)load()},30000);
async function loadBlocklist(){try{const d=await api('/api/admin/blocklist');$('#domainlist').value=(d.domains||[]).join('\\n');note('Loaded '+(d.domains||[]).length+' domains (version '+d.version+').')}catch(e){note(e.message,true)}}
$('#loadblocklist').onclick=loadBlocklist;
$('#saveblocklist').onclick=async()=>{const domains=[...new Set($('#domainlist').value.split(/[\\s,;]+/).map(x=>x.trim().toLowerCase()).filter(Boolean))];if(!domains.length)return note('Add at least one domain.',true);try{const d=await api('/api/admin/blocklist',{method:'PUT',body:JSON.stringify({domains})});note('Blocklist saved. Version '+d.version+' · '+d.domain_count+' domains.');}catch(e){note(e.message,true)}};
$('#geminireview').onclick=async()=>{const domains=$('#reviewdomains').value.split(/[\\s,;]+/).map(x=>x.trim().toLowerCase()).filter(Boolean);if(!domains.length)return note('Enter domains for review.',true);try{const d=await api('/api/admin/domain-review',{method:'POST',body:JSON.stringify({domains})});const out=d.results||[];$('#reviewresults').style.display='block';$('#reviewresults').innerHTML='<b>Gemini suggestions (not saved)</b>'+out.map(x=>'<p>'+esc(x.domain)+' — <b>'+esc(x.decision)+'</b> · '+Math.round(x.confidence*100)+'% · '+esc(x.reason)+'</p>').join('');note('Gemini review complete. Check each suggestion before updating the blocklist.')}catch(e){note(e.message,true)}};
