import os
import datetime
from pathlib import Path

from fastapi import FastAPI, Depends, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from models import Asset, Threat, init_db, get_db
from calculator import StrideCategory, calculate_risk, format_risk_matrix, score_to_display
from data import ASSET_TYPES, PROTOCOLS, THREAT_TEMPLATES

app = FastAPI(title="Калькулятор угроз умного дома")

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
static_dir = BASE_DIR / "static"
if not static_dir.exists():
    static_dir.mkdir()
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

init_db()


def get_type_name(type_id: str) -> str:
    for t in ASSET_TYPES:
        if t["id"] == type_id:
            return t["name"]
    return type_id


def get_stride_info(stride: str) -> dict:
    for s in StrideCategory:
        if s.value == stride:
            return {"value": s.value, "name": s.full_name, "desc": s.description}
    return {"value": stride, "name": stride, "desc": ""}


STRIDE_COLORS = {
    "S": "#6366f1",
    "T": "#f59e0b",
    "R": "#8b5cf6",
    "I": "#06b6d4",
    "D": "#ef4444",
    "E": "#ec4899",
}


# ─── Страницы ─────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    threats = db.query(Threat).all()

    total_assets = len(assets)
    total_threats = len(threats)
    mitigated = sum(1 for t in threats if t.mitigated)

    by_level = {"низкий": 0, "средний": 0, "высокий": 0, "критический": 0}
    by_stride = {s.value: 0 for s in StrideCategory}
    for t in threats:
        by_level[t.risk_level] = by_level.get(t.risk_level, 0) + 1
        by_stride[t.stride] = by_stride.get(t.stride, 0) + 1

    risk_matrix = format_risk_matrix()
    stride_labels = [
        {"value": s.value, "name": s.full_name.split("(")[0].strip()}
        for s in StrideCategory
    ]

    return templates.TemplateResponse("index.html", {
        "request": request,
        "assets": assets,
        "threats": threats,
        "total_assets": total_assets,
        "total_threats": total_threats,
        "mitigated": mitigated,
        "by_level": by_level,
        "by_stride": by_stride,
        "risk_matrix": risk_matrix,
        "stride_labels": stride_labels,
        "score_to_display": score_to_display,
        "STRIDE_COLORS": STRIDE_COLORS,
        "get_type_name": get_type_name,
    })


@app.get("/assets", response_class=HTMLResponse)
def asset_list(request: Request, db: Session = Depends(get_db)):
    assets = db.query(Asset).order_by(Asset.created_at.desc()).all()
    return templates.TemplateResponse("assets.html", {
        "request": request,
        "assets": assets,
        "asset_types": ASSET_TYPES,
        "get_type_name": get_type_name,
    })


@app.get("/assets/new", response_class=HTMLResponse)
def asset_new_form(request: Request):
    return templates.TemplateResponse("asset_form.html", {
        "request": request,
        "asset": None,
        "asset_types": ASSET_TYPES,
        "protocols": PROTOCOLS,
    })


@app.post("/assets/new")
def asset_new(
    name: str = Form(...),
    type: str = Form(...),
    protocols: str = Form(""),
    description: str = Form(""),
    db: Session = Depends(get_db),
):
    asset = Asset(name=name, type=type, protocols=protocols, description=description)
    db.add(asset)
    db.commit()
    return RedirectResponse("/assets", status_code=303)


@app.get("/assets/{asset_id}/edit", response_class=HTMLResponse)
def asset_edit_form(asset_id: int, request: Request, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return RedirectResponse("/assets", status_code=303)
    return templates.TemplateResponse("asset_form.html", {
        "request": request,
        "asset": asset,
        "asset_types": ASSET_TYPES,
        "protocols": PROTOCOLS,
    })


@app.post("/assets/{asset_id}/edit")
def asset_edit(
    asset_id: int,
    name: str = Form(...),
    type: str = Form(...),
    protocols: str = Form(""),
    description: str = Form(""),
    db: Session = Depends(get_db),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset:
        asset.name = name
        asset.type = type
        asset.protocols = protocols
        asset.description = description
        db.commit()
    return RedirectResponse("/assets", status_code=303)


@app.post("/assets/{asset_id}/delete")
def asset_delete(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset:
        # Unlink threats
        db.query(Threat).filter(Threat.asset_id == asset_id).update(
            {Threat.asset_id: None, Threat.asset_name: ""}
        )
        db.delete(asset)
        db.commit()
    return RedirectResponse("/assets", status_code=303)


@app.get("/threats", response_class=HTMLResponse)
def threat_list(
    request: Request,
    stride: str = Query(None),
    level: str = Query(None),
    mitigated: str = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(Threat)
    if stride:
        q = q.filter(Threat.stride == stride)
    if level:
        q = q.filter(Threat.risk_level == level)
    if mitigated == "yes":
        q = q.filter(Threat.mitigated == True)
    elif mitigated == "no":
        q = q.filter(Threat.mitigated == False)
    threats = q.order_by(Threat.risk_score.desc(), Threat.created_at.desc()).all()

    assets = db.query(Asset).all()

    return templates.TemplateResponse("threats.html", {
        "request": request,
        "threats": threats,
        "assets": assets,
        "stride_list": [s for s in StrideCategory],
        "STRIDE_COLORS": STRIDE_COLORS,
        "get_stride_info": get_stride_info,
    })


@app.get("/threats/new", response_class=HTMLResponse)
def threat_new_form(request: Request, db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    return templates.TemplateResponse("threat_form.html", {
        "request": request,
        "threat": None,
        "assets": assets,
        "stride_list": [s for s in StrideCategory],
        "threat_templates": THREAT_TEMPLATES,
    })


@app.post("/threats/new")
def threat_new(
    name: str = Form(...),
    stride: str = Form(...),
    description: str = Form(""),
    asset_id: int = Form(0),
    probability: int = Form(1),
    impact: int = Form(1),
    db: Session = Depends(get_db),
):
    risk = calculate_risk(probability, impact)
    asset_name = ""
    if asset_id:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset:
            asset_name = asset.name
    threat = Threat(
        name=name,
        stride=stride,
        description=description,
        asset_id=asset_id if asset_id else None,
        asset_name=asset_name,
        probability=probability,
        impact=impact,
        risk_score=risk.score,
        risk_level=risk.level.value,
        is_custom=True,
    )
    db.add(threat)
    db.commit()
    return RedirectResponse("/threats", status_code=303)


@app.get("/threats/{threat_id}/edit", response_class=HTMLResponse)
def threat_edit_form(threat_id: int, request: Request, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        return RedirectResponse("/threats", status_code=303)
    assets = db.query(Asset).all()
    return templates.TemplateResponse("threat_form.html", {
        "request": request,
        "threat": threat,
        "assets": assets,
        "stride_list": [s for s in StrideCategory],
    })


@app.post("/threats/{threat_id}/edit")
def threat_edit(
    threat_id: int,
    name: str = Form(...),
    stride: str = Form(...),
    description: str = Form(""),
    asset_id: int = Form(0),
    probability: int = Form(1),
    impact: int = Form(1),
    db: Session = Depends(get_db),
):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if threat:
        risk = calculate_risk(probability, impact)
        asset_name = ""
        if asset_id:
            asset = db.query(Asset).filter(Asset.id == asset_id).first()
            if asset:
                asset_name = asset.name
        threat.name = name
        threat.stride = stride
        threat.description = description
        threat.asset_id = asset_id if asset_id else None
        threat.asset_name = asset_name
        threat.probability = probability
        threat.impact = impact
        threat.risk_score = risk.score
        threat.risk_level = risk.level.value
        db.commit()
    return RedirectResponse("/threats", status_code=303)


@app.post("/threats/{threat_id}/toggle")
def threat_toggle(threat_id: int, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if threat:
        threat.mitigated = not threat.mitigated
        db.commit()
    referer = "/threats"
    return RedirectResponse(referer, status_code=303)


@app.post("/threats/{threat_id}/delete")
def threat_delete(threat_id: int, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if threat:
        db.delete(threat)
        db.commit()
    return RedirectResponse("/threats", status_code=303)


@app.get("/api/threat-templates")
def get_threat_templates():
    from fastapi.responses import JSONResponse
    return JSONResponse(THREAT_TEMPLATES)


@app.get("/report", response_class=HTMLResponse)
def report(request: Request, db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    threats = db.query(Threat).order_by(Threat.risk_score.desc()).all()
    risk_matrix = format_risk_matrix()

    by_level = {
        "низкий": {"count": 0, "color": "#22c55e"},
        "средний": {"count": 0, "color": "#eab308"},
        "высокий": {"count": 0, "color": "#f97316"},
        "критический": {"count": 0, "color": "#ef4444"},
    }
    for t in threats:
        if t.risk_level in by_level:
            by_level[t.risk_level]["count"] += 1

    return templates.TemplateResponse("report.html", {
        "request": request,
        "assets": assets,
        "threats": threats,
        "risk_matrix": risk_matrix,
        "by_level": by_level,
        "generated_at": datetime.datetime.now().strftime("%d.%m.%Y %H:%M"),
        "get_stride_info": get_stride_info,
        "STRIDE_COLORS": STRIDE_COLORS,
        "get_type_name": get_type_name,
        "score_to_display": score_to_display,
    })


@app.get("/report/pdf")
def report_pdf(request: Request, db: Session = Depends(get_db)):
    from io import BytesIO
    from fpdf import FPDF

    FONT_CANDIDATES = [
        ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"),
        ("C:/Windows/Fonts/Calibri.ttf", "C:/Windows/Fonts/Calibrib.ttf"),
    ]
    reg_path = bold_path = None
    for reg_c, bold_c in FONT_CANDIDATES:
        if Path(reg_c).exists():
            reg_path = reg_c
            bold_path = bold_c if Path(bold_c).exists() else reg_c
            break
    if not reg_path:
        return Response("Шрифт не найден", status_code=500)

    assets = db.query(Asset).all()
    threats = db.query(Threat).order_by(Threat.risk_score.desc()).all()
    mitigated_count = sum(1 for t in threats if t.mitigated)
    by_level = {
        "низкий": {"count": 0, "color": "#22c55e"},
        "средний": {"count": 0, "color": "#eab308"},
        "высокий": {"count": 0, "color": "#f97316"},
        "критический": {"count": 0, "color": "#ef4444"},
    }
    for t in threats:
        if t.risk_level in by_level:
            by_level[t.risk_level]["count"] += 1

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.add_font("F", "", str(reg_path))
    pdf.add_font("F", "B", str(bold_path))
    pdf.add_font("F", "I", str(reg_path))

    LM = 18
    RW = 174
    GRAY = (113, 113, 122)
    DARK = (30, 38, 69)
    LIGHT_BG = (248, 250, 252)

    def F(style="", size=10):
        pdf.set_font("F", style, size)

    def C(hex_str):
        h = hex_str.lstrip("#")
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

    def Y():
        return pdf.get_y()

    def section(title, num):
        pdf.ln(3)
        pdf.set_fill_color(*DARK)
        pdf.rect(LM, Y(), 3, 9, style="F")
        pdf.set_x(LM + 9)
        pdf.set_text_color(*DARK)
        F("B", 13)
        pdf.cell(RW - 9, 9, f"{num}. {title}")
        pdf.ln(11)

    # ─── Title page ───
    pdf.set_fill_color(*DARK)
    pdf.rect(0, 0, 210, 6, style="F")
    pdf.ln(20)

    pdf.set_y(55)
    F("B", 22)
    pdf.set_text_color(*DARK)
    pdf.cell(RW, 10, "Модель угроз", align="C")
    pdf.ln(14)
    F("B", 14)
    pdf.set_text_color(*DARK)
    pdf.cell(RW, 8, "инфраструктуры умного дома", align="C")
    pdf.ln(16)

    pdf.set_draw_color(*DARK)
    pdf.set_line_width(0.5)
    pdf.line(LM + 50, Y(), LM + RW - 50, Y())
    pdf.ln(8)

    F("", 9)
    pdf.set_text_color(*GRAY)
    pdf.cell(RW, 5, "Методология STRIDE  |  Оценка рисков R = P x I", align="C")
    pdf.ln(14)

    generated = datetime.datetime.now().strftime("%d.%m.%Y %H:%M")
    meta = [
        ("Дата формирования", generated),
        ("Всего активов", str(len(assets))),
        ("Всего угроз", str(len(threats))),
        ("Устранено", str(mitigated_count)),
    ]
    bw = 110
    bx = LM + (RW - bw) / 2
    pdf.set_draw_color(210, 215, 225)
    pdf.set_fill_color(248, 250, 252)
    pdf.rect(bx, Y(), bw, len(meta) * 8 + 10, style="DF")
    sy = Y() + 5
    for i, (lb, vl) in enumerate(meta):
        y = sy + i * 8
        pdf.set_xy(bx + 12, y)
        F("", 8.5)
        pdf.set_text_color(*GRAY)
        pdf.cell(52, 6, lb)
        F("B", 8.5)
        pdf.set_text_color(*DARK)
        pdf.cell(32, 6, vl, align="R")

    # ─── Assets ───
    pdf.add_page()
    section("Активы", 1)

    if assets:
        cw = [RW * 0.38, RW * 0.27, RW * 0.35]
        hd = ["Название", "Тип", "Протоколы"]

        pdf.set_fill_color(*DARK)
        pdf.set_text_color(255, 255, 255)
        F("B", 7.5)
        cx = LM
        for h, w in zip(hd, cw):
            pdf.set_xy(cx, Y())
            pdf.cell(w, 7, "  " + h, fill=True)
            cx += w
        pdf.ln(7)

        for i, a in enumerate(assets):
            if Y() > 268:
                pdf.add_page()
                section("Активы (продолжение)", 1)
                pdf.set_fill_color(*DARK)
                pdf.set_text_color(255, 255, 255)
                F("B", 7.5)
                cx = LM
                for h, w in zip(hd, cw):
                    pdf.set_xy(cx, Y()); pdf.cell(w, 7, "  " + h, fill=True); cx += w
                pdf.ln(7)

            bg = LIGHT_BG if i % 2 == 0 else (255, 255, 255)
            pdf.set_fill_color(*bg)
            pdf.set_text_color(40, 45, 55)
            F("", 7.5)
            cx = LM
            vs = [a.name, get_type_name(a.type), a.protocols.replace(",", ", ")[:50] if a.protocols else "—"]
            for v, w in zip(vs, cw):
                pdf.set_xy(cx, Y()); pdf.cell(w, 6.5, "  " + v, fill=True); cx += w
            pdf.ln(6.5)
    else:
        F("I", 9)
        pdf.set_text_color(*GRAY)
        pdf.cell(RW, 6, "Нет добавленных активов")

    # ─── Risk Distribution ───
    pdf.ln(5)
    section("Распределение рисков", 2)

    bar_colors = {"низкий": "#22c55e", "средний": "#eab308", "высокий": "#f97316", "критический": "#ef4444"}
    total = len(threats)

    for level, info in by_level.items():
        if Y() > 268:
            pdf.add_page()
            section("Распределение рисков (продолжение)", 2)
        pct = (info["count"] / total * 100) if total > 0 else 0

        F("B", 8.5)
        pdf.set_text_color(40, 45, 55)
        pdf.set_x(LM)
        pdf.cell(40, 5, level.capitalize())
        F("", 8.5)
        pdf.set_text_color(*GRAY)
        pdf.cell(10, 5, str(info["count"]), align="R")
        pdf.ln(6)

        by = Y()
        bh = 5
        fw = max(pct * RW / 100, 0)
        pdf.set_fill_color(*C(bar_colors[level]))
        pdf.rect(LM, by, fw, bh, style="F")
        pdf.set_fill_color(232, 237, 243)
        pdf.rect(LM + fw, by, RW - fw, bh, style="F")

        if pct > 8:
            pdf.set_xy(LM + fw - 14, by + 0.5)
            F("B", 6.5)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(12, 4, f"{pct:.0f}%", align="R")

        pdf.set_y(by + bh + 3.5)

    pdf.ln(2)
    pdf.set_draw_color(210, 215, 225)
    pdf.set_line_width(0.3)
    pdf.line(LM, Y(), LM + RW, Y())
    pdf.ln(4)
    F("B", 9)
    pdf.set_text_color(*DARK)
    pdf.set_x(LM)
    pdf.cell(RW / 2, 5, f"Всего угроз: {total}")
    pdf.cell(RW / 2, 5, f"Устранено: {mitigated_count}")

    # ─── Threats Registry ───
    pdf.add_page()
    section("Реестр угроз", 3)

    if threats:
        tc = [8, 10, 56, 30, 8, 8, 8, 24, 22]
        hd = ["#", "STRIDE", "Угроза", "Актив", "P", "I", "R", "Уровень", "Статус"]
        risk_clrs = {k: C(v) for k, v in bar_colors.items()}

        def th():
            pdf.set_fill_color(*DARK)
            pdf.set_text_color(255, 255, 255)
            F("B", 7)
            cx = LM
            for h, w in zip(hd, tc):
                a = "C" if h in ("P", "I", "R", "#", "STRIDE") else "L"
                pdf.set_xy(cx, Y())
                pdf.cell(w, 7, " " + h if a == "L" else h, align=a, fill=True)
                cx += w
            pdf.ln(7)

        th()
        for i, t in enumerate(threats):
            if Y() > 260:
                pdf.add_page(); th()

            bg = LIGHT_BG if i % 2 == 0 else (255, 255, 255)
            pdf.set_fill_color(*bg)
            cx = LM

            F("", 7)
            pdf.set_text_color(*GRAY)
            pdf.set_xy(cx, Y()); pdf.cell(tc[0], 6, str(t.id), align="C", fill=True); cx += tc[0]

            F("B", 7)
            pdf.set_text_color(*DARK)
            pdf.set_xy(cx, Y()); pdf.cell(tc[1], 6, t.stride, align="C", fill=True); cx += tc[1]

            F("", 7.5)
            pdf.set_text_color(40, 45, 55)
            pdf.set_xy(cx, Y()); pdf.cell(tc[2], 6, (t.name[:48] + "..") if len(t.name) > 48 else t.name, fill=True); cx += tc[2]

            F("", 7.5)
            pdf.set_text_color(*GRAY)
            pdf.set_xy(cx, Y()); pdf.cell(tc[3], 6, (t.asset_name or "—")[:22], fill=True); cx += tc[3]

            for j, v in enumerate([str(t.probability), str(t.impact), str(t.risk_score)]):
                F("B" if j == 2 else "", 7.5)
                pdf.set_text_color(40, 45, 55)
                pdf.set_xy(cx, Y()); pdf.cell(tc[4 + j], 6, v, align="C", fill=True); cx += tc[4 + j]

            lc = risk_clrs.get(t.risk_level, (148, 163, 184))
            F("B", 8)
            pdf.set_text_color(*lc)
            pdf.set_xy(cx, Y()); pdf.cell(tc[7], 6, t.risk_level, align="C", fill=True); cx += tc[7]

            F("B", 8)
            pdf.set_text_color(40, 45, 55)
            pdf.set_xy(cx, Y()); pdf.cell(tc[8], 6, "Устранено" if t.mitigated else "Активно", align="C", fill=True)

            pdf.ln(6)

        # ─── Recommendations ───
        if Y() > 235: pdf.add_page()
        pdf.ln(4)
        pdf.set_draw_color(210, 215, 225)
        pdf.set_line_width(0.3)
        pdf.line(LM, Y(), LM + RW, Y())
        pdf.ln(6)

        section("Рекомендации", 4)
        recs = [
            "Регулярно обновлять прошивки и ПО всех устройств умного дома",
            "Использовать сегментацию сети (гостевая / основная / IoT VLAN)",
            "Отключить UPnP и ненужные сетевые сервисы на роутере",
            "Настроить сложные уникальные пароли для каждого устройства",
            "Включить журналирование событий и регулярно просматривать логи",
            "Использовать WPA3 для Wi-Fi, AES-шифрование для ZigBee",
            "Включить двухфакторную аутентификацию для облачных сервисов",
        ]
        for r in recs:
            if Y() > 275: pdf.add_page(); section("Рекомендации (продолжение)", 4)
            pdf.set_x(LM + 6)
            pdf.set_text_color(34, 180, 80)
            F("B", 9)
            pdf.cell(5, 5, "✓")
            pdf.set_text_color(60, 65, 75)
            F("", 8.5)
            pdf.multi_cell(RW - 11, 5, r)
            pdf.ln(0.5)

    try:
        buf = BytesIO()
        pdf.output(buf)
        buf.seek(0)
    except Exception as e:
        return Response(f"Ошибка генерации PDF: {e}", status_code=500)
    return Response(buf.getvalue(), media_type="application/pdf",
                    headers={"Content-Disposition": "attachment; filename=otchet-ugrozy.pdf"})


if __name__ == "__main__":
    import uvicorn
    import os
    
    port = int(os.environ.get("PORT", 8000))
    
    reload = os.environ.get("ENV", "production") == "development"
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=reload
    )
