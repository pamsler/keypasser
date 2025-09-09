export const el=(t,cls="",html="")=>{const n=document.createElement(t); if(cls) n.className=cls; if(html) n.innerHTML=html; return n;};
export async function api(path,opts={}) {
  const res=await fetch(path,{credentials:"include",...opts});
  const txt=await res.text(); const ct=res.headers.get("content-type")||"";
  const data=ct.includes("application/json")?(txt?JSON.parse(txt):{}):txt;
  if(!res.ok) throw new Error(data?.error||res.statusText||txt||"Fehler"); return data;
}
export async function isAuthed(){ try{ const r=await api("/api/me"); return !!r.authed; }catch{ return false; }}


export const iconBtn=(svg,label)=>{const b=el("button","p-2 rounded-full border border-gray-300/60 dark:border-gray-600/60 hover:bg-gray-100 dark:hover:bg-gray-800 transition"); b.innerHTML=svg; b.setAttribute("aria-label",label||""); return b;};
export const linkTab=(t,h)=>{const a=el("a","px-3 py-2 rounded-xl hover:bg-gray-100 dark:hover:bg-gray-800",t); a.href=h; return a;};
export const deckTab=(iconSvg,text,href)=>{
  const a = el("a",
    "tab inline-flex items-center gap-2 px-5 h-10 text-sm text-gray-300 " +
    "hover:text-white rounded-md relative transition whitespace-nowrap select-none");
  a.href = href;
  a.innerHTML = `<span class="ico shrink-0 opacity-80" style="display:inline-flex;align-items:center;">
    ${iconSvg}
  </span><span class="label">${text}</span>`;
  a.onmouseenter = ()=> a.style.backgroundColor = "rgba(255,255,255,.06)";
  a.onmouseleave = ()=> a.style.backgroundColor = (a.classList.contains("is-active") ? "rgba(16,185,129,.10)" : "transparent");
  function update(){
    const active = location.hash.startsWith(href);
    a.classList.toggle("is-active", active);
    a.classList.toggle("text-emerald-400", active);
    a.style.backgroundColor = active ? "rgba(16,185,129,.10)" : "transparent";
    a.style.setProperty("--deck-underline", active ? "2px" : "0");
  }
  update();
  window.addEventListener("hashchange", update);
  a.style.setProperty("paddingBottom",".5rem"); 
  a.style.setProperty("transition","color .15s ease");
  a.addEventListener("mouseenter",()=>a.style.setProperty("--deck-underline","2px"));
  a.addEventListener("mouseleave",update);
  const after = document.createElement("span");
  after.style.cssText="position:absolute;left:50%;bottom:0;transform:translateX(-50%);height:var(--deck-underline,0);width:32px;background:rgb(16,185,129);border-radius:1px;";
  a.appendChild(after);
  return a;
};

export const userPill=(email)=>{
  const pill = el("div","hidden sm:flex items-center gap-2 px-3 py-1 rounded-xl border border-white/10 bg-white/5 text-sm");
  const init = (email||"?").split("@")[0].slice(0,2).toUpperCase();
  pill.innerHTML = `
    <span class="w-7 h-7 rounded-full bg-emerald-600 text-white grid place-items-center text-xs font-bold">${init}</span>
    <span class="whitespace-nowrap">${email||""}</span>`;
  return pill;
};
export const card=(title,body)=>{const c=el("div","backdrop-blur bg-white/70 dark:bg-gray-800/70 border border-gray-200/60 dark:border-gray-700/60 rounded-2xl shadow p-6"); if(title) c.append(el("h2","text-lg font-semibold mb-4",title)); c.append(body); return c;};
export const field=i=>{i.className="w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900"; return i;};
export const primary=t=>{const b=el("button","px-4 py-2 rounded-xl bg-indigo-600 text-white hover:bg-indigo-500"); b.textContent=t; return b;};
export const secondary=t=>{const b=el("button","px-4 py-2 rounded-xl border border-gray-300 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-800"); b.textContent=t; return b;};
export const actions=(...xs)=>{const d=el("div","flex gap-3"); xs.forEach(x=>d.append(x)); return d;};
export const row3=(a,b,c)=>{const d=el("div","grid grid-cols-1 md:grid-cols-3 gap-3"); d.append(a,b,c); return d;};
export const toast=(m)=>{const t=el("div","fixed bottom-5 left-1/2 -translate-x-1/2 px-4 py-2 rounded-xl bg-gray-900 text-white text-sm shadow"); t.textContent=m; document.body.append(t); setTimeout(()=>t.remove(),2600);};

export const svgMoon=()=>`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 1 0 9.79 9.79z"/></svg>`;
export const svgSun =()=>`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M6.76 4.84l-1.8-1.79-1.41 1.41 1.79 1.8 1.42-1.42zM18.24 4.84l1.79-1.79 1.41 1.41-1.79 1.8-1.41-1.42zM12 4V1h2v3h-2zm0 19v-3h2v3h-2zm7-9h3v2h-3v-2zM4 12H1v2h3v-2zm2.76 7.16l-1.79 1.79 1.41 1.41 1.8-1.79-1.42-1.41zm10.48 0l1.41 1.41 1.79-1.79-1.41-1.41-1.79 1.79zM17 12a5 5 0 1 1-10 0 5 5 0 0 1 10 0z"/></svg>`;
export const svgPower=()=>`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M13 3h-2v10h2V3zm-1 19a9 9 0 1 1 6.36-2.64l-1.41-1.41A7 7 0 1 0 12 19z"/></svg>`;

export async function fetchBranding(){
  try{
    const b = await api("/api/branding");
    return b?.logo_url || null;
  }catch{ return null; }
}
export function setFavicon(href){
  try{
    const link = document.querySelector('link#favicon') || (()=>{const l=document.createElement('link');l.id='favicon';l.rel='icon';document.head.appendChild(l);return l;})();
    link.href = href;
  }catch{}
}