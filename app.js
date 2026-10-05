const $=s=>document.querySelector(s);
const escDate=value=>{if(!value)return null;const d=new Date(value);return Number.isNaN(d.getTime())?null:d};
const dateLabel=value=>{const d=escDate(value);return d?new Intl.DateTimeFormat("it-IT",{day:"2-digit",month:"2-digit",year:"numeric",timeZone:"UTC"}).format(d):""};
const nameOf=(obj,keys)=>{if(!obj||typeof obj!=="object")return"";const key=Object.keys(obj).find(k=>keys.includes(k.toLowerCase()));return key?obj[key]:""};
const cell=(tag,text,cls)=>{const el=document.createElement(tag);if(cls)el.className=cls;el.textContent=text;return el};

async function loadTranscripts(){
  const response=await fetch("/api/refresh",{cache:"no-store"});const payload=await response.json();if(!response.ok)throw Error(payload.error||`HTTP ${response.status}`);
  const files=payload.files||[],candidates=[],errors=[];
  for(const file of files){
    if(file.error){errors.push(file);continue}
    const data=file.data||{},candidate=data.candidate||{};
    const candidateName=candidate.name||file.name||"Candidato";
    const certs=Array.isArray(data.certs)?data.certs:[];
    candidates.push({name:candidateName,source:file.name,certs:certs.map(c=>({id:String(c.ccatId??c.id??""),name:c.name||c.certificationName||"Certificazione senza nome",date:c.activeDate||c.activationDate||c.dateEarned||"",dateObj:escDate(c.activeDate||c.activationDate||c.dateEarned)}))});
  }
  return{candidates,errors,saved:payload.saved||0};
}
function showErrors(errors){const list=$("#errors");if(!list)return;list.replaceChildren();for(const e of errors){const li=cell("li",`${e.name||"Sorgente"} (${e.url}) — ${e.message||"errore di download"}`);list.append(li)}}
function normalizeClassifications(data){const list=Array.isArray(data)?data:(data.certifications||[]);return new Map(list.map(x=>[String(x.ccatId??x.id??""),x]))}

function renderDashboard(candidates,classifications){
  const holder=$("#dashboard");const classList=Array.isArray(classifications)?classifications:(classifications.certifications||[]);const byId=normalizeClassifications(classifications);
  const products=[...new Set(classList.map(x=>x.focusProduct).filter(Boolean))].sort((a,b)=>a.localeCompare(b,"it"));
  const dimensions=[...new Map(classList.filter(x=>x.type&&x.specification).map(x=>[`${x.type}|||${x.specification}`,{type:x.type,specification:x.specification}])).values()].sort((a,b)=>a.type.localeCompare(b.type,"it")||a.specification.localeCompare(b.specification,"it"));
  const totals=new Map();let unmatched=0;
  for(const person of candidates)for(const cert of person.certs){const category=byId.get(cert.id);if(!category){unmatched++;continue}const key=`${category.focusProduct}|||${category.type}|||${category.specification}`;if(!totals.has(key))totals.set(key,[]);totals.get(key).push({person:person.name,cert:cert.name,date:dateLabel(cert.date)})}
  if(!products.length||!dimensions.length){holder.innerHTML='<div class="empty-state">Il file classifications.json non contiene classificazioni.</div>';return}
  const wrap=document.createElement("div");wrap.className="table-wrap";const table=document.createElement("table");table.className="matrix";const thead=document.createElement("thead"),top=document.createElement("tr");top.append(cell("th","Focus Product"));for(const d of dimensions){const th=cell("th",`${d.type} · ${d.specification}`);th.title=`${d.type}: ${d.specification}`;top.append(th)}thead.append(top);table.append(thead);const tbody=document.createElement("tbody");
  for(const product of products){const tr=document.createElement("tr");tr.append(cell("th",product));for(const d of dimensions){const entries=totals.get(`${product}|||${d.type}|||${d.specification}`)||[],td=document.createElement("td");if(entries.length){td.append(cell("span",String(entries.length),"metric"));td.append(cell("span",`${new Set(entries.map(x=>x.person)).size} candidati`,"metric-detail"));td.title=entries.map(x=>`${x.person}: ${x.cert}${x.date?` (${x.date})`:""}`).join("\n")}else td.append(cell("span","—","empty"));tr.append(td)}tbody.append(tr)}table.append(tbody);wrap.append(table);holder.replaceChildren(wrap);
  const note=$("#classification-note");note.textContent=unmatched?`${unmatched} certificazioni nei transcript non hanno ancora una voce in classifications.json.`:`Classificazioni caricate da classifications.json · ${classList.length} esami mappati.`;
}

function renderCertTable(candidates,showOld,query){
  const holder=$("#cert-table"),candidateNames=[...new Set(candidates.map(c=>c.name))];const map=new Map();const cutoff=new Date();cutoff.setFullYear(cutoff.getFullYear()-2);
  for(const person of candidates)for(const cert of person.certs){if(!map.has(cert.id||cert.name))map.set(cert.id||cert.name,{name:cert.name,dates:new Map(),latest:null});const entry=map.get(cert.id||cert.name);entry.dates.set(person.name,cert);if(cert.dateObj&&(!entry.latest||cert.dateObj>entry.latest))entry.latest=cert.dateObj}
  let records=[...map.values()].filter(cert=>cert.name.toLocaleLowerCase("it").includes(query.toLocaleLowerCase("it"))&&(showOld||[...cert.dates.values()].some(x=>!x.dateObj||x.dateObj>=cutoff))).sort((a,b)=>a.name.localeCompare(b.name,"it"));
  if(!records.length){holder.innerHTML='<div class="empty-state">Nessuna certificazione corrisponde ai filtri.</div>';return}
  const wrap=document.createElement("div");wrap.className="table-wrap";const table=document.createElement("table");table.className="matrix";const thead=document.createElement("thead"),hr=document.createElement("tr");hr.append(cell("th","Certificazione"));for(const name of candidateNames)hr.append(cell("th",name));thead.append(hr);table.append(thead);const tbody=document.createElement("tbody");
  for(const cert of records){const tr=document.createElement("tr");tr.append(cell("th",cert.name));for(const name of candidateNames){const td=document.createElement("td"),award=cert.dates.get(name),isOld=award?.dateObj&&award.dateObj<cutoff;if(award&&(!isOld||showOld))td.append(cell("span",dateLabel(award.date)||"Data non disponibile","date"));else td.append(cell("span","—","empty"));tr.append(td)}tbody.append(tr)}table.append(tbody);wrap.append(table);holder.replaceChildren(wrap);
}

function addSourceRow(url="",name=""){
  const tr=document.createElement("tr");for(const [value,placeholder]of[[url,"https://host/percorso/file.json"],[name,"Nome candidato"]]){const td=document.createElement("td"),input=document.createElement("input");input.value=value;input.placeholder=placeholder;input.type="text";td.append(input);tr.append(td)}const action=document.createElement("td"),remove=document.createElement("button");remove.className="danger";remove.type="button";remove.textContent="Rimuovi";remove.addEventListener("click",()=>tr.remove());action.append(remove);tr.append(action);$("#source-rows").append(tr)
}
function sourceDraft(){return[...$("#source-rows").rows].map(r=>({url:r.cells[0].querySelector("input").value.trim(),name:r.cells[1].querySelector("input").value.trim()})).filter(x=>x.url||x.name)}
async function initSettings(){const response=await fetch("/api/config",{cache:"no-store"}),data=await response.json();if(!response.ok)throw Error(data.error||`HTTP ${response.status}`);for(const x of data.sources||[])addSourceRow(x.url,x.name);$("#config-status").textContent=`${(data.sources||[]).length} URL caricate da config.json`}
async function saveSettings(){const button=$("#save-config");button.disabled=true;$("#config-status").textContent="Salvataggio…";try{const response=await fetch("/api/config",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sources:sourceDraft()})}),data=await response.json();if(!response.ok)throw Error(data.error||`HTTP ${response.status}`);$("#source-rows").replaceChildren();for(const x of data.sources)addSourceRow(x.url,x.name);$("#config-status").textContent=`Configurazione salvata · ${data.sources.length} URL`}catch(e){$("#config-status").textContent=`Errore: ${e.message}`}finally{button.disabled=false}}

async function init(){
  const page=document.body.dataset.page;
  if(page==="settings"){
    $("#add-source").addEventListener("click",()=>addSourceRow());$("#save-config").addEventListener("click",saveSettings);
    try{await initSettings()}catch(e){$("#config-status").textContent=`Errore configurazione: ${e.message}`}return;
  }
  let data;
  const redraw=()=>{if(!data)return;if(page==="dashboard")renderDashboard(data.candidates,data.classifications);else renderCertTable(data.candidates,$("#show-old").checked,$("#cert-search").value)};
  if(page==="table"){$("#show-old").addEventListener("change",redraw);$("#cert-search").addEventListener("input",redraw)}
  const refresh=async()=>{const button=$("#reload");button.disabled=true;$("#status").textContent="Download dei transcript…";try{const [transcripts,classResponse]=await Promise.all([loadTranscripts(),page==="dashboard"?fetch("/api/classifications",{cache:"no-store"}):Promise.resolve(null)]);let classifications={certifications:[]};if(classResponse){classifications=await classResponse.json();if(!classResponse.ok)throw Error(classifications.error||`HTTP ${classResponse.status}`)}data={...transcripts,classifications};showErrors(transcripts.errors);redraw();$("#status").textContent=`${transcripts.saved} file JSON scaricati · ${transcripts.candidates.length} candidati`}catch(e){$("#status").textContent=`Errore: ${e.message}`}finally{button.disabled=false}};
  $("#reload").addEventListener("click",refresh);await refresh();
}
document.addEventListener("DOMContentLoaded",init);
