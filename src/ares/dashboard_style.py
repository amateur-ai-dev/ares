"""The dashboard stylesheet, kept out of the template strings.

Inlined rather than served as a file because the Content-Security-Policy
allows no external origin at all, and because a single-file dashboard is one
less thing to get wrong when someone runs this on a machine that has never
seen the repository.
"""

STYLE = """:root{--void:#24262b;--panel:#2c2f35;--panel2:#33373e;--line:#3b4047;--line2:#4b515a;
--fg:#eae7e1;--fg2:#aca79e;--fg3:#827d75;
--ok:#84b394;--ap:#d3a463;--no:#d08a80;--acc:#93b2ca;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--void);color:var(--fg);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
background-image:radial-gradient(circle at 12% -12%,rgba(147,178,202,.06),transparent 48%),
radial-gradient(circle at 94% 2%,rgba(211,164,99,.05),transparent 42%)}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.bar{border-bottom:1px solid var(--line);background:rgba(36,38,43,.92);padding:.85rem 0}
.in{max-width:1080px;margin:0 auto;padding:0 1.5rem}
.bar .in{display:flex;align-items:center;gap:.9rem;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:.6rem;color:var(--fg);text-decoration:none}
.brand:hover{text-decoration:none}
.brand span{font:700 1.05rem/1 var(--mono);letter-spacing:.22em}
.brand em{color:var(--acc);font-style:normal}
.logo{width:26px;height:30px;display:block;flex:none}
.tagline{color:var(--fg3);font-size:.8rem;border-left:1px solid var(--line2);padding-left:.9rem}
.dot{margin-left:auto;display:flex;align-items:center;gap:.45rem;font:600 .68rem/1 var(--mono);
letter-spacing:.14em;color:var(--ok)}
.dot i{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px rgba(132,179,148,.16)}
main{max-width:1080px;margin:0 auto;padding:2rem 1.5rem 5rem}
.lab{font:700 .68rem/1 var(--mono);letter-spacing:.18em;color:var(--fg3);margin:0 0 .7rem}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:1.6rem;overflow:hidden;box-shadow:0 1px 2px rgba(0,0,0,.18)}
.ph{display:flex;align-items:center;gap:.7rem;padding:.75rem 1.1rem;border-bottom:1px solid var(--line);
background:var(--panel2)}
.ph h2{margin:0;font:700 .78rem/1 var(--mono);letter-spacing:.14em;text-transform:uppercase}
.ph .note{margin-left:auto;color:var(--fg3);font-size:.75rem}
.pb{padding:1.1rem}
.dl-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:.7rem}
.dl{display:flex;align-items:center;gap:.8rem;padding:.85rem 1rem;border:1px solid var(--line2);
border-radius:8px;background:var(--panel2);color:var(--fg)}
.dl:hover{border-color:var(--acc);text-decoration:none;background:#3a3f47}
.dl .ext{font:700 .68rem/1 var(--mono);letter-spacing:.06em;padding:.42rem .5rem;border-radius:5px;
background:rgba(147,178,202,.14);color:var(--acc);flex:none}
.dl b{display:block;font-size:.9rem;font-weight:600}
.dl span{color:var(--fg3);font-size:.74rem;font-family:var(--mono)}
.thesis{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0}
.th{padding:1.1rem;border-right:1px solid var(--line)}
.th:last-child{border-right:0}
.th .k{display:inline-flex;align-items:center;gap:.45rem;font:700 .7rem/1 var(--mono);letter-spacing:.12em;margin-bottom:.5rem}
.th .k i{width:8px;height:8px;border-radius:2px}
.th p{margin:0;color:var(--fg2);font-size:.85rem;line-height:1.5}
.k.v{color:var(--ok)} .k.v i{background:var(--ok)}
.k.r{color:var(--no)} .k.r i{background:var(--no)}
.k.a{color:var(--ap)} .k.a i{background:var(--ap)}
.runs{list-style:none;margin:0;padding:0}
.runs li{border-bottom:1px solid var(--line)}
.runs li:last-child{border-bottom:0}
.runs a.row{display:flex;align-items:center;gap:1rem;padding:.95rem 1.1rem;color:var(--fg)}
.runs a.row:hover{background:var(--panel2);text-decoration:none}
.chip{font:700 .64rem/1 var(--mono);letter-spacing:.12em;padding:.38rem .55rem;border-radius:5px;flex:none;border:1px solid}
.chip.demo{color:var(--ap);border-color:rgba(211,164,99,.38);background:rgba(211,164,99,.12)}
.chip.eval{color:var(--acc);border-color:rgba(147,178,202,.38);background:rgba(147,178,202,.12)}
.runs b{font-size:.94rem;font-weight:600}
.runs .id{color:var(--fg3);font:.72rem var(--mono);margin-top:.15rem}
.arrow{margin-left:auto;color:var(--fg3);font-family:var(--mono)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:0}
.stat{padding:1.1rem;border-right:1px solid var(--line)}
.stat:last-child{border-right:0}
.stat .v{display:block;font:700 2rem/1 var(--mono);font-variant-numeric:tabular-nums}
.stat .k{font:700 .66rem/1 var(--mono);letter-spacing:.14em;color:var(--fg3);margin-top:.45rem;display:block}
.stat.v1 .v{color:var(--ok)} .stat.v2 .v{color:var(--ap)} .stat.v3 .v{color:var(--no)}
.mode{display:flex;gap:.9rem;padding:1rem 1.1rem;border-radius:10px;margin-bottom:1.6rem;border:1px solid;font-size:.88rem}
.mode.demo{border-color:rgba(211,164,99,.42);background:rgba(211,164,99,.09);color:#e2bc86}
.mode.eval{border-color:rgba(147,178,202,.4);background:rgba(147,178,202,.08);color:#b7cede}
.mode b{display:block;font:700 .68rem/1 var(--mono);letter-spacing:.16em;margin-bottom:.35rem}
h1{font-size:1.7rem;margin:.2rem 0 .25rem;letter-spacing:-.01em}
.sub{color:var(--fg3);font:.78rem var(--mono);margin:0 0 1.6rem}
.rows{list-style:none;margin:0;padding:0}
.rows li{padding:.8rem 1.1rem;border-bottom:1px solid var(--line);font-size:.9rem;display:flex;gap:.8rem;align-items:flex-start}
.rows li:last-child{border-bottom:0}
.tag{font:700 .62rem/1 var(--mono);letter-spacing:.1em;padding:.35rem .5rem;border-radius:4px;flex:none;margin-top:.1rem}
.tag.v{background:rgba(132,179,148,.15);color:var(--ok)}
.tag.s{background:rgba(211,164,99,.15);color:var(--ap)}
.meta{color:var(--fg3);font:.72rem var(--mono);margin-top:.25rem}
.panel.aporia{border-color:rgba(208,138,128,.45)}
.panel.aporia .ph{background:rgba(208,138,128,.1);border-bottom-color:rgba(208,138,128,.28)}
.panel.aporia .ph h2{color:var(--no)}
.lead{color:var(--fg2);font-size:.88rem;margin:0 0 .9rem;padding:0 1.1rem}
.empty{color:var(--fg3);font-style:italic}
.prec{padding:1.1rem}
.prec .p1{margin:0 0 .4rem;font:700 1rem/1.4 var(--mono);color:var(--ok)}
.prec .p2{margin:0;color:var(--fg2);font-size:.84rem}
.foot{color:var(--fg3);font-size:.78rem;border-top:1px solid var(--line);padding-top:1.2rem;margin-top:2.5rem}
.act{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1.1rem;margin-bottom:1.6rem}
form.card{display:flex;flex-direction:column;gap:.75rem}
label{display:block;font:700 .66rem/1 var(--mono);letter-spacing:.14em;color:var(--fg3);margin-bottom:.35rem}
input[type=file],select,input[type=number]{width:100%;background:var(--void);color:var(--fg);
border:1px solid var(--line2);border-radius:6px;padding:.55rem .6rem;font:.82rem var(--mono)}
input[type=file]::file-selector-button{background:var(--panel2);color:var(--fg2);border:1px solid var(--line2);
border-radius:5px;padding:.35rem .6rem;margin-right:.7rem;font:.74rem var(--mono);cursor:pointer}
input[type=file]::file-selector-button:hover{border-color:var(--acc);color:var(--acc)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:.7rem}
button{background:var(--acc);color:#1a1d22;border:0;border-radius:6px;padding:.7rem 1rem;
font:700 .74rem/1 var(--mono);letter-spacing:.12em;cursor:pointer}
button:hover{filter:brightness(1.09)}
button.ghost{background:transparent;color:var(--ap);border:1px solid rgba(211,164,99,.45)}
button.ghost:hover{background:rgba(211,164,99,.1);filter:none}
.hint{color:var(--fg3);font-size:.75rem;margin:0}
.err{border-color:rgba(208,138,128,.5);background:rgba(208,138,128,.1);color:#e8b0a7;
padding:.85rem 1rem;border-radius:8px;border:1px solid;margin-bottom:1.4rem;font-size:.86rem}
.st{font:700 .62rem/1 var(--mono);letter-spacing:.12em;padding:.36rem .5rem;border-radius:5px;flex:none;border:1px solid}
.st.complete{color:var(--ok);border-color:rgba(132,179,148,.4);background:rgba(132,179,148,.12)}
.st.running{color:var(--ap);border-color:rgba(211,164,99,.4);background:rgba(211,164,99,.12)}
.st.queued{color:var(--fg3);border-color:var(--line2)}
.st.failed{color:var(--no);border-color:rgba(208,138,128,.4);background:rgba(208,138,128,.12)}
.mgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:0}
.m{padding:.9rem 1rem;border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
.m .v{display:block;font:700 1.35rem/1 var(--mono);font-variant-numeric:tabular-nums}
.m .k{font:700 .6rem/1.3 var(--mono);letter-spacing:.1em;color:var(--fg3);margin-top:.4rem;display:block}
.fnd{list-style:none;margin:0;padding:0}
.fnd li{padding:.85rem 1.1rem;border-bottom:1px solid var(--line);display:flex;gap:.85rem;align-items:flex-start}
.fnd li:last-child{border-bottom:0}
.sev{font:700 .6rem/1 var(--mono);letter-spacing:.1em;padding:.34rem .48rem;border-radius:4px;flex:none;margin-top:.15rem}
.sev.ERROR{background:rgba(208,138,128,.16);color:var(--no)}
.sev.WARNING{background:rgba(211,164,99,.16);color:var(--ap)}
.sev.INFO{background:rgba(147,178,202,.14);color:var(--acc)}
.cwe{display:inline-block;font:700 .64rem/1 var(--mono);color:var(--acc);
background:rgba(147,178,202,.12);border-radius:4px;padding:.28rem .42rem;margin-right:.45rem}
@media(max-width:640px){.two{grid-template-columns:1fr}}

/* ---- executive strip ---- */
.exec{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:0;
border:1px solid var(--line);border-radius:10px;overflow:hidden;background:var(--panel);margin-bottom:1.1rem}
.exec .c{padding:1.15rem 1.2rem;border-right:1px solid var(--line)}
.exec .c:last-child{border-right:0}
.exec .k{display:block;font:700 .6rem/1.2 var(--mono);letter-spacing:.16em;color:var(--fg3)}
.exec .v{display:block;font:700 2.15rem/1 var(--mono);font-variant-numeric:tabular-nums;margin:.55rem 0 .4rem}
.exec .n{display:block;color:var(--fg3);font-size:.71rem;line-height:1.45}
.exec .c.ok .v{color:var(--ok)} .exec .c.acc .v{color:var(--acc)} .exec .c.ap .v{color:var(--ap)}
.exec .c.none .v{color:var(--fg3)}
.withheld{border:1px dashed var(--line2);border-radius:8px;padding:.7rem .95rem;margin-bottom:1.6rem;
color:var(--fg2);font-size:.79rem;background:rgba(211,164,99,.05)}
.withheld b{color:var(--ap);font:700 .62rem/1 var(--mono);letter-spacing:.14em;margin-right:.5rem}

/* ---- funnel ---- */
.funnel{padding:1.2rem 1.1rem .6rem}
.fr{display:grid;grid-template-columns:150px 1fr 92px;gap:1rem;align-items:center;margin-bottom:.95rem}
.fr .fl{font:700 .66rem/1.3 var(--mono);letter-spacing:.1em;color:var(--fg2);text-align:right}
.fr .fb{position:relative;height:34px;background:rgba(255,255,255,.028);border-radius:5px;overflow:hidden}
.fr .fb i{position:absolute;inset:0 auto 0 0;border-radius:5px;display:block;
background:linear-gradient(90deg,var(--acc),rgba(147,178,202,.5))}
.fr.s-verified .fb i{background:linear-gradient(90deg,var(--ok),rgba(132,179,148,.45))}
.fr.s-attack .fb i{background:linear-gradient(90deg,var(--ap),rgba(211,164,99,.45))}
.fr .fv{font:700 1.05rem/1 var(--mono);font-variant-numeric:tabular-nums;text-align:right}
.fr .fn{grid-column:2/4;color:var(--fg3);font-size:.71rem;margin:-.55rem 0 0}
.drop{grid-column:2/4;color:var(--fg3);font:.66rem var(--mono);margin:-.5rem 0 0;letter-spacing:.04em}
.beside{display:flex;gap:.8rem;align-items:center;margin:.2rem 1.1rem 1.2rem;padding:.75rem .95rem;
border-left:3px solid var(--no);background:rgba(208,138,128,.07);border-radius:0 6px 6px 0}
.beside .bv{font:700 1.35rem/1 var(--mono);color:var(--no);font-variant-numeric:tabular-nums}
.beside .bt{color:var(--fg2);font-size:.78rem;line-height:1.45}

/* ---- timeline ---- */
.tl{padding:1.4rem 1.1rem 1.1rem;overflow-x:auto}
.tlrail{position:relative;height:76px;min-width:640px;margin-bottom:.4rem}
.tlrail:before{content:"";position:absolute;left:0;right:0;top:37px;height:2px;background:var(--line2)}
.tlrail .pt{position:absolute;top:30px;width:11px;height:11px;border-radius:50%;
background:var(--panel);border:2px solid var(--ok);transform:translateX(-50%)}
.tlrail .pt.hit{width:17px;height:17px;top:27px;border-color:var(--ap);background:var(--ap);
box-shadow:0 0 0 5px rgba(211,164,99,.16)}
.tlrail .pt.conn{border-color:var(--acc)}
.tlends{display:flex;justify-content:space-between;color:var(--fg3);font:.68rem var(--mono);
border-top:1px solid var(--line);padding-top:.6rem}
.tllegend{display:flex;gap:1.3rem;flex-wrap:wrap;padding:.85rem 1.1rem;border-top:1px solid var(--line);
color:var(--fg3);font-size:.73rem}
.tllegend span{display:flex;align-items:center;gap:.45rem}
.tllegend i{width:10px;height:10px;border-radius:50%;border:2px solid var(--ok);display:block}
.tllegend i.hit{background:var(--ap);border-color:var(--ap)}
.tllegend i.conn{border-color:var(--acc)}
.tlist{list-style:none;margin:0;padding:0;max-height:420px;overflow-y:auto}
.tlist li{display:grid;grid-template-columns:150px 14px 1fr;gap:.85rem;align-items:baseline;
padding:.62rem 1.1rem;border-bottom:1px solid var(--line);font-size:.83rem}
.tlist li:last-child{border-bottom:0}
.tlist li.hit{background:rgba(211,164,99,.06)}
.tlist .ts{color:var(--fg3);font:.71rem var(--mono);font-variant-numeric:tabular-nums}
.tlist .mk{width:9px;height:9px;border-radius:50%;border:2px solid var(--ok);align-self:center}
.tlist li.hit .mk{background:var(--ap);border-color:var(--ap)}
.tlist .fl2{color:var(--fg2)}
.tlist .arrow2{color:var(--fg3);margin:0 .4rem}
.tlist b.pick{color:var(--ap);font:700 .6rem/1 var(--mono);letter-spacing:.1em;margin-left:.5rem}
@media(max-width:640px){.fr{grid-template-columns:104px 1fr 62px}.tlist li{grid-template-columns:110px 14px 1fr}}
"""
