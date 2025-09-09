import { el, api, isAuthed, iconBtn, deckTab, svgMoon, svgSun, svgPower, fetchBranding, setFavicon } from "./ui.js";
import { viewLogin }     from "./views/login.js";
import { viewDashboard } from "./views/dashboard.js";
import { viewSettings }  from "./views/settings.js";
import { viewProfile }   from "./views/profile.js";
import { viewUsers }     from "./views/users.js";
import { viewSend }      from "./views/send.js";


(function(){
  const t = localStorage.getItem("theme");
  const wantsDark = t==="dark" || (!t && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", wantsDark);
  document.body?.classList.toggle("dark", wantsDark);
})();
function themeToggleBtn(){
  const isDark = document.documentElement.classList.contains("dark");
  const b = iconBtn(isDark ? svgSun() : svgMoon(), "Theme");
  b.onclick = () => {
    const next = !document.documentElement.classList.contains("dark");
    document.documentElement.classList.toggle("dark", next);
    document.body?.classList.toggle("dark", next);
    localStorage.setItem("theme", next ? "dark" : "light");
    b.innerHTML = next ? svgSun() : svgMoon();
  };
  return b;
}


function initialsFromEmail(email){
  const local = String(email||"").split("@")[0];
  const parts = local.split(/[._-]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return local.slice(0,2).toUpperCase();
}

function makeUserPill(email){
  const pill = el("button","flex items-center gap-2 rounded-xl border border-white/10 bg-white/10 px-2 py-1 hover:bg-white/20 transition");
  const avatar = el("div","w-8 h-8 rounded-full grid place-items-center text-xs font-semibold text-white bg-indigo-600",
    initialsFromEmail(email)
  );
  const label  = el("span","hidden sm:inline max-w-[12rem] truncate", email||"");
  pill.append(avatar, label);
  pill.style.cursor = "pointer";
  pill.onclick = ()=>{ location.hash="#/profile"; };
  return pill;
}


export async function shell(children, showNav){
  const wrap=el("div","min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 dark:from-gray-950 dark:to-gray-900 text-gray-900 dark:text-gray-100");
  if(showNav) wrap.append(await topbar());                 
  const main=el("main","max-w-[1200px] mx-auto px-4 py-10");   
  main.append(children); 
  wrap.append(main);
  return wrap;
}
async function topbar(){
  const wrapper = el("div","sticky top-0 z-30");
  const top = el("div","backdrop-blur border-b border-white/10 bg-white/90 dark:bg-slate-900/95");
  const bar = el("div","max-w-[1200px] mx-auto px-4 h-16 grid grid-cols-3 items-center");


  const brandWrap = el("a","justify-self-center flex items-center gap-2 rounded-xl px-2 py-1 hover:bg-white/5","");
  brandWrap.href = "#/dashboard";
  const brandImg  = el("img","h-[1.875rem] w-[1.875rem] rounded-full hidden");
  const brandText = el("span","font-medium","KeyPasser");
  brandWrap.append(brandImg,brandText);
  const left = el("div","");

  const me = await api("/api/me").catch(()=>({}));
  const right = el("div","justify-self-end flex items-center gap-2 min-w-0");
  if (me?.user?.email) {
    right.append(makeUserPill(me.user.email));
  }

  const theme = themeToggleBtn();
  const logout = iconBtn(svgPower(),"Logout");
  logout.onclick = ()=> api("/api/logout",{method:"POST"}).then(()=>{ location.hash="#/login"; render(); });

  right.append(theme, logout);
  bar.append(left, brandWrap, right);
  top.append(bar);
  wrapper.append(top);

  const logoUrl = await fetchBranding();
  if (logoUrl){ brandImg.src = logoUrl; brandImg.classList.remove("hidden"); setFavicon(logoUrl); }
  window.addEventListener("branding-refresh", async ()=>{
    const u = await fetchBranding();
    if (u){ brandImg.src=u; brandImg.classList.remove("hidden"); setFavicon(u); }
  });

  const sub  = el("div","backdrop-blur border-b border-white/10 bg-white/90 dark:bg-slate-900/95");
  const grid = el("div","max-w-[1200px] mx-auto px-4 h-12 grid grid-cols-3 items-center");
  const leftSpacer  = el("div","");
  const rightSpacer = el("div","");
  const tabs = el("nav","justify-self-center flex items-center gap-4");
  const send  = deckTab('<svg width="16" height="16" viewBox="0 0 24 24"><path fill="currentColor" d="M2 3l20 9-20 9 5-9-5-9zm7.5 9L4 18l10-6L4 6l5.5 6z"/></svg>',"Send Secret","#/new");
  const set   = deckTab('<svg width="16" height="16" viewBox="0 0 24 24"><path fill="currentColor" d="M12 8a4 4 0 1 1-4 4a4 4 0 0 1 4-4m8.14 2.5l1.72 1l-1.63 2.83c.04.23.07.46.07.7s-.03.47-.07.7L21.86 19.5l-1.72 1l-1.63-2.82a7.29 7.29 0 0 1-1.21.7l-.25.1l-.38 1.95h-3.44l-.38-1.95l-.25-.1a7.29 7.29 0 0 1-1.22-.7L3.86 20.5l-1.72-1l1.63-2.83A6.8 6.8 0 0 1 3.34 12c0-.24.03-.47.07-.7L1.78 8.47l1.72-1l1.63 2.83c.39-.28.8-.52 1.22-.7l.25-.1L7 6.55h3.44l.38 1.95l.25.1c.42.18.83.42 1.21.7L13.91 7.5z"/></svg>',"Einstellungen","#/settings");
  const users = deckTab('<svg width="16" height="16" viewBox="0 0 24 24"><path fill="currentColor" d="M16 11a3 3 0 1 0-3-3a3 3 0 0 0 3 3m-8 0a3 3 0 1 0-3-3a3 3 0 0 0 3 3m0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4m8 0a7.22 7.22 0 0 0-2.1.3A5.42 5.42 0 0 1 18 17v2h6v-2c0-2.23-3.58-4-8-4"/></svg>',"Users","#/users");
  tabs.append(send,set,users);
  grid.append(leftSpacer, tabs, rightSpacer);
  sub.append(grid);
  wrapper.append(sub);

  return wrapper;
}

async function render(){
  const root=document.getElementById("app"); root.innerHTML="";
  const h=location.hash||"#/login"; const ok=await isAuthed();
  if(!ok && h!=="#/login"){ location.hash="#/login"; return render(); }
  if(!ok) return root.append(await viewLogin());
  if(h.startsWith("#/new"))      return root.append(await viewSend());
  if(h.startsWith("#/settings")) return root.append(await viewSettings());
  if(h.startsWith("#/users"))    return root.append(await viewUsers());
  if(h.startsWith("#/profile"))  return root.append(await viewProfile());
  return root.append(await viewDashboard());
}
window.addEventListener("hashchange", render); render();