// public/views/dashboard.js
import { el, api, card } from "../ui.js";
import { shell } from "../spa.js";

export function viewDashboard(){
  const wrap = el("div","space-y-8");

  const toolbar = el("div","flex items-center justify-between gap-3");
  const left = el("div","text-sm text-gray-500 dark:text-gray-400","Letzte Vorgänge");
  const right = el("div","flex items-center gap-2");
  const sizeSel = el("select","px-2 py-1 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-sm");
  sizeSel.innerHTML = `<option>8</option><option selected>10</option><option>20</option><option>30</option>`;
  right.append(el("span","text-xs text-gray-500","Pro Seite:"), sizeSel);
  toolbar.append(left,right);

  const tblWrap = el("div","overflow-x-auto rounded-xl border border-gray-200/60 dark:border-gray-700/60");
  const tbl = el("table","w-full text-sm");
  tbl.innerHTML = `
    <thead class="bg-gray-50/70 dark:bg-gray-900/40">
      <tr class="text-left text-gray-500 dark:text-gray-400">
        <th class="py-2.5 pl-4 pr-3">Zeit</th>
        <th class="py-2.5 px-3">Von</th>
        <th class="py-2.5 px-3">An</th>
        <th class="py-2.5 px-3">Status</th>
      </tr>
    </thead>
    <tbody class="divide-y divide-gray-200/60 dark:divide-gray-700/60"></tbody>
  `;
  const tbody = tbl.querySelector("tbody");
  tblWrap.append(tbl);

  const pager = el("div","flex items-center justify-between px-2 pt-3");
  const pInfo = el("span","text-xs text-gray-500");
  const pCtrls = el("div","flex gap-1");
  const mkBtn = (t)=>{ const b=el("button","h-8 w-8 rounded-lg border border-gray-300 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-800 disabled:opacity-50 disabled:cursor-not-allowed",t); b.type="button"; return b; };
  const prev = mkBtn("‹"), next = mkBtn("›");
  pCtrls.append(prev,next); pager.append(pInfo,pCtrls);

  let page = 1, size = 10, total = 0;

  const fmtCH = (d)=> new Date(d).toLocaleString("de-CH",{ timeZone:"Europe/Zurich" });

  function badgeStatus(s){
    const map = {
      active:  "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200",
      used:    "bg-amber-100   text-amber-800   dark:bg-amber-900/40   dark:text-amber-200",
      expired: "bg-red-100     text-red-800     dark:bg-red-900/40     dark:text-red-200"
    };
    const b = el("span",`px-2 py-0.5 text-xs rounded-full ${map[s]||"bg-gray-200 text-gray-800 dark:bg-gray-700 dark:text-gray-200"}`);
    b.textContent = s==="active"?"Aktiv": s==="used"?"Verwendet":"Abgelaufen";
    return b;
  }

  async function loadPage(){
    let r;
    try { r = await api(`/api/audit?page=${page}&size=${size}`); }
    catch(e){
      if (e?.status===403) {
        tbody.innerHTML = `<tr><td class="py-7 text-center text-gray-500 dark:text-gray-400" colspan="4">
          Kein Zugriff
        </td></tr>`;
        pInfo.textContent = "—"; prev.disabled = next.disabled = true; return;
      }
      throw e;
    }
    total = r.total;
    tbody.innerHTML = "";

    if (!r.items.length){
      const tr = el("tr");
      tr.innerHTML = `<td class="py-7 text-center text-gray-500 dark:text-gray-400" colspan="4">Keine Einträge</td>`;
      tbody.append(tr);
    } else {
      r.items.forEach(it=>{
        const tr = el("tr","hover:bg-gray-50/60 dark:hover:bg-gray-900/40 transition");
        tr.innerHTML = `
          <td class="py-2.5 pl-4 pr-3 font-mono">${fmtCH(it.created_at)}</td>
          <td class="py-2.5 px-3">${it.from_email||"—"}</td>
          <td class="py-2.5 px-3">${it.to_email||"—"}</td>
          <td class="py-2.5 px-3"></td>
        `;
        tr.children[3].append(badgeStatus(it.status));
        tbody.append(tr);
      });
    }

    const first = total ? (page-1)*size + 1 : 0;
    const last  = Math.min(page*size, total);
    pInfo.textContent = total ? `${first}–${last} von ${total}` : "—";
    prev.disabled = page<=1;
    next.disabled = page*size>=total;
  }

  prev.onclick = ()=>{ if(page>1){ page--; loadPage(); } };
  next.onclick = ()=>{ if(page*size<total){ page++; loadPage(); } };
  sizeSel.onchange = ()=>{ size = Number(sizeSel.value||10); page = 1; loadPage(); };

  const timer = setInterval(()=>loadPage().catch(()=>{}), 30_000);

  const activityCard = card("Aktivität",
    el("div","space-y-3")
      .appendChild(toolbar).parentNode
      .appendChild(tblWrap).parentNode
      .appendChild(pager).parentNode
  );

  const chartBox = el("div","w-full relative");
  const SVGNS="http://www.w3.org/2000/svg";
  const W=640, H=220, M={l:36,r:10,t:10,b:26};
  const svg=document.createElementNS(SVGNS,"svg");
  svg.setAttribute("class","w-full h-[220px]");
  svg.setAttribute("viewBox",`0 0 ${W} ${H}`);
  chartBox.append(svg);
  const tip=el("div","absolute px-2 py-1 text-xs rounded bg-gray-900 text-white hidden");
  chartBox.append(tip);

  (async ()=>{
    await loadPage();

    const series = await api("/api/stats/day");
    const max = Math.max(1, ...series.map(d=>d.sent));
    const innerW = W - M.l - M.r, innerH = H - M.t - M.b;
    const bw = innerW / (series.length||1);

    [0,0.5,1].forEach(fr=>{
      const y = M.t + innerH*(1-fr);
      const gl = document.createElementNS(SVGNS,"line");
      gl.setAttribute("x1", M.l); gl.setAttribute("x2", W-M.r);
      gl.setAttribute("y1", y); gl.setAttribute("y2", y);
      gl.setAttribute("class","stroke-gray-300/30");
      svg.append(gl);
      const lab=document.createElementNS(SVGNS,"text");
      lab.setAttribute("x", 4); lab.setAttribute("y", y+3);
      lab.setAttribute("font-size","10"); lab.setAttribute("class","fill-gray-500");
      lab.textContent = Math.round(max*fr);
      svg.append(lab);
    });

    series.forEach((d,i)=>{
      const h = (d.sent/max)*innerH;
      const x = M.l + i*bw + 4;
      const y = M.t + innerH - h;
      const r = document.createElementNS(SVGNS,"rect");
      r.setAttribute("x",x); r.setAttribute("y",y);
      r.setAttribute("width",Math.max(2,bw-8)); r.setAttribute("height",Math.max(2,h));
      r.setAttribute("rx","4");
      r.setAttribute("class","fill-indigo-500/90 hover:fill-indigo-400 transition-colors");
      r.addEventListener("mouseenter", (ev)=>{
        tip.textContent = `${new Date(d.day).toLocaleDateString("de-CH")} • ${d.sent}`;
        tip.style.left = `${ev.offsetX+12}px`; tip.style.top = `${ev.offsetY-18}px`;
        tip.classList.remove("hidden");
      });
      r.addEventListener("mouseleave", ()=> tip.classList.add("hidden"));
      svg.append(r);

      if(i%2===0){
        const tx=document.createElementNS(SVGNS,"text");
        tx.setAttribute("x", M.l + i*bw + 2);
        tx.setAttribute("y", H-6);
        tx.setAttribute("font-size","10"); tx.setAttribute("class","fill-gray-500");
        tx.textContent=new Date(d.day).toLocaleDateString("de-CH",{day:"2-digit",month:"2-digit"});
        svg.append(tx);
      }
    });
  })().catch(()=>{ clearInterval(timer); });

  wrap.append(activityCard, card("Gesendete E-Mails pro Tag (14T)", chartBox));
  return shell(wrap,true);
}
