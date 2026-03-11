import { useState } from "react";
import { apiFetch } from "../api";
import { S, COLORS } from "../styles";
import { Modal } from "../components/Modal";
import { Empty } from "../components/Empty";

export default function ConsolesPage({ consoles, setConsoles, userId, companies }) {
    const [search, setSearch] = useState("");
    const [showAdd, setShowAdd] = useState(false);
    const [form, setForm] = useState({ name: "", manufacturerId: "", releaseYear: "", region: "" });
    const [err, setErr] = useState("");
    const [hovered, setHovered] = useState(null);

    const filtered = consoles.filter(c =>
        c.name.toLowerCase().includes(search.toLowerCase()) ||
        c.manufacturer?.companyName?.toLowerCase().includes(search.toLowerCase()) ||
        c.region?.toLowerCase().includes(search.toLowerCase())
    );

    const set = k => e => setForm(f => ({ ...f, [k]: e.target.value }));

    async function addConsole() {
        setErr("");
        try {
            const c = await apiFetch("/consoles", {
                method: "POST",
                body: JSON.stringify({
                    name: form.name,
                    manufacturer: { id: parseInt(form.manufacturerId) },
                    releaseYear: parseInt(form.releaseYear),
                    region: form.region
                }),
            });
            setConsoles(cs => [...cs, c]);
            setShowAdd(false);
            setForm({ name: "", manufacturerId: "", releaseYear: "", region: "" });
        } catch (e) { setErr(e.error || "Failed to add console"); }
    }

    const regionColor = { Japan: COLORS.magenta, "North America": COLORS.cyan, Europe: COLORS.green };

    return (
        <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
                <h1 style={S.heading}>▶ CONSOLE CATALOG</h1>
                {userId && <button style={S.btn("primary")} onClick={() => setShowAdd(true)}>[ + ADD CONSOLE ]</button>}
            </div>
            <div style={S.searchBar}>
                <input style={S.input} placeholder="> SEARCH CONSOLES_" value={search} onChange={e => setSearch(e.target.value)} />
            </div>
            {filtered.length === 0 ? <Empty msg="No consoles found" /> : (
                <div style={S.grid}>
                    {filtered.map(c => (
                        <div key={c.id} style={{ ...S.card, ...(hovered === c.id ? S.cardHover : {}) }} onMouseEnter={() => setHovered(c.id)} onMouseLeave={() => setHovered(null)}>
                            <div style={{ position: "absolute", top: 0, right: 0, width: "12px", height: "12px", borderLeft: `1px solid ${hovered === c.id ? COLORS.cyan : COLORS.borderDim}`, borderBottom: `1px solid ${hovered === c.id ? COLORS.cyan : COLORS.borderDim}` }} />
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.75rem" }}>
                                <h3 style={{ margin: 0, fontSize: "1rem", color: COLORS.yellow, textShadow: `0 0 8px ${COLORS.yellow}88`, fontWeight: 900 }}>{c.name}</h3>
                                <span style={S.badge(regionColor[c.region] || COLORS.muted)}>{c.region}</span>
                            </div>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.4rem" }}>
                                <span style={S.tag}>🏢 {c.manufacturer?.companyName}</span>
                                <span style={S.tag}>📅 {c.releaseYear}</span>
                            </div>
                        </div>
                    ))}
                </div>
            )}
            {showAdd && (
                <Modal title="ADD CONSOLE" onClose={() => setShowAdd(false)}>
                    {err && <div style={S.error}>{err}</div>}
                    <div style={S.formGroup}>
                        <label style={S.label}>Name *</label>
                        <input style={S.input} value={form.name} onChange={set("name")} />
                    </div>
                    <div style={S.formGroup}>
                        <label style={S.label}>Manufacturer *</label>
                        <select style={S.input} value={form.manufacturerId} onChange={set("manufacturerId")}>
                            <option value="">-- SELECT --</option>
                            {companies.map(c => (
                                <option key={c.id} value={c.id}>{c.companyName}</option>
                            ))}
                        </select>
                    </div>
                    <div style={S.formGroup}>
                        <label style={S.label}>Release Year *</label>
                        <input style={S.input} type="number" value={form.releaseYear} onChange={set("releaseYear")} />
                    </div>
                    <div style={S.formGroup}>
                        <label style={S.label}>Region *</label>
                        <select style={S.input} value={form.region} onChange={set("region")}>
                            <option value="">-- SELECT --</option>
                            {["Japan", "North America", "Europe", "Australia", "Asia"].map(r => (
                                <option key={r}>{r}</option>
                            ))}
                        </select>
                    </div>
                    <div style={{ display: "flex", gap: "0.75rem", justifyContent: "flex-end" }}>
                        <button style={S.btn("ghost")} onClick={() => setShowAdd(false)}>[ CANCEL ]</button>
                        <button style={S.btn("primary")} onClick={addConsole}>[ CONFIRM ]</button>
                    </div>
                </Modal>
            )}
        </div>
    );
}