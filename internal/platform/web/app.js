'use strict';
let credential = '';
const $ = id => document.getElementById(id);
function message(text, error = false) { $('message').textContent = text; $('message').className = error ? 'error' : 'success'; }
async function api(path, body) {
  const response = await fetch(path, {method: body ? 'POST' : 'GET', headers: {'Authorization':'Bearer ' + credential, 'Content-Type':'application/json'}, body: body ? JSON.stringify(body) : undefined, credentials:'omit', redirect:'error'});
  const result = await response.json(); if (!response.ok) throw new Error(result.error || 'Request failed'); return result;
}
async function run(fn) { try { await fn(); } catch (error) { message(error.message, true); } }
async function refresh() {
  const selected = $('key-list').value;
  const keys = await api('/api/command', {operation:'list'});
  $('key-list').replaceChildren(...(keys || []).map(key => { const option = document.createElement('option'); option.value = key; option.textContent = key; return option; }));
  if ((keys || []).includes(selected)) $('key-list').value = selected;
  const events = await api('/api/activity'); $('events').textContent = events.slice().reverse().map(event => new Date(event.time).toLocaleTimeString() + ' · ' + event.operation + ' · ' + (event.success ? 'success' : 'rejected')).join('\n') || 'No management operations yet.';
}
async function execute(command) { const result = await api('/api/command', command); message(command.operation + ' completed.'); await refresh(); return result; }
$('connect').onclick = () => run(async () => { credential = $('token').value; $('token').value = ''; await refresh(); message('Connected to Knox.'); });
$('refresh').onclick = () => run(refresh);
$('lock').onclick = () => location.reload();
$('inspect').onclick = () => run(async () => { const key = $('key-list').value; const data = await execute({operation:'inspect',key_id:key}); $('metadata').textContent = JSON.stringify(data,null,2); $('version-key').value = key; $('acl-key').value = key; });
$('create-key').onclick = () => run(async () => { const value = $('new-value').value; $('new-value').value = ''; await execute({operation:'create',key_id:$('new-id').value,value}); });
$('add-version').onclick = () => run(async () => { const value = $('version-value').value; $('version-value').value = ''; const result = await execute({operation:'add-version',key_id:$('version-key').value,value}); $('version-id').value = String(result.version_id); });
$('set-status').onclick = () => run(async () => { const raw = $('version-id').value; if (!/^[1-9]\d*$/.test(raw)) throw new Error('Enter a positive version ID.'); await execute({operation:'set-status',key_id:$('version-key').value,version_id:raw,status:$('version-status').value}); });
$('set-acl').onclick = () => run(async () => { await execute({operation:'set-acl',key_id:$('acl-key').value,acl:JSON.parse($('acl').value)}); });
