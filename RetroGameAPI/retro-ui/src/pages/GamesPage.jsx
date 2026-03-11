import { useState, useEffect } from "react";
import { apiFetch } from "../api";
import { S, COLORS } from "../styles";
import { Modal } from "../components/Modal";
import { GameCard } from "../components/GameCard";
import { Spinner } from "../components/Spinner";
import { Empty } from "../components/Empty";

export default function GamesPage({ userId, consoles, companies, onWantGame }) {
    const [games, setGames] = useState([]);
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState("");
    const [showAdd, setShowAdd] = useState(false);
    const [form, setForm] = useState({ title: "", consoleId: "", year: "", condition: "", madeById: "" });
    const [err, setErr] = useState("");

    useEffect(() => {
        apiFetch("/games").then(setGames).finally(() => setLoading(false));
    }, []);

    const filtered = games.filter(g =>
        g.title.toLowerCase().includes(search.toLowerCase()) ||
        g.console?.name?.toLowerCase().includes(search.toLowerCase())
    );

    const set = k => e => setForm(f => ({ ...f, [k]: e.target.value }));

    async function addGame() {
        setErr("");
        try {
            const g = await apiFetch("/games", {
                method: "POST",
                body: JSON.stringify({
                    title: form.title,
                    console: { id: parseInt(form.consoleId) },
                    year: parseInt(form.year) || 0,
                    condition: form.condition,
                    madeBy: { id: parseInt(form.madeById) }
                }),
            });
            setGames(gs => [...gs, g]);
            setShowAdd(false);
            setForm({ title: "", consoleId: "", year: "", condition: "", madeById: "" });
        } catch (e) { setErr(e.error || "Failed to add game"); }
    }

    async function deleteGame(id) {
        if (!window.confirm("Delete this game?")) return;
        await apiFetch(`/games/${id}`, { method: "DELETE" });
        setGames(gs => gs.filter(g => g.id !== id));
    }

    return (
        <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
                <h1 style={S.heading}>▶ GAME LIBRARY</h1>
                {userId && <button style={S.btn("primary")} onClick={() => setShowAdd(true)}>[ + INSERT GAME ]</button>}
            </div>
            <div style={S.searchBar}>
                <input style={{ ...S.input, borderColor: COLORS.borderDim }} placeholder="> SEARCH GAMES_" value={search} onChange={e => setSearch(e.target.value)} />
            </div>
            {loading ? <Spinner /> : filtered.length === 0 ? <Empty msg="No games found" /> : (
                <div style={S.grid}>
                    {filtered.map(g => (
                        <GameCard key={g.id} g={g} userId={userId} onDelete={deleteGame} onWantGame={onWantGame} />
                    ))}
                </div>
            )}
            {showAdd && (
                <Modal title="INSERT GAME" onClose={() => setShowAdd(false)}>
                    {err && <div style={S.error}>{err}</div>}
                    <div style={S.formGroup}>
                        <label style={S.label}>Title *</label>
                        <input style={S.input} value={form.title} onChange={set("title")} />
                    </div>
                    <div style={S.formGroup}>
                        <label style={S.label}>Console *</label>
                        <select style={S.input} value={form.consoleId} onChange={set("consoleId")}>
                            <option value="">-- SELECT --</option>
                            {consoles.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                        </select>
                    </div>
                    <div style={S.formGroup}>
                        <label style={S.label}>Publisher *</label>
                        <select style={S.input} value={form.madeById} onChange={set("madeById")}>
                            <option value="">-- SELECT --</option>
                            {companies.map(c => <option key={c.id} value={c.id}>{c.companyName}</option>)}
                        </select>
                    </div>
                    <div style={S.formGroup}>
                        <label style={S.label}>Year</label>
                        <input style={S.input} type="number" value={form.year} onChange={set("year")} />
                    </div>
                    <div style={S.formGroup}>
                        <label style={S.label}>Condition</label>
                        <select style={S.input} value={form.condition} onChange={set("condition")}>
                            <option value="">-- SELECT --</option>
                            {["Mint", "Good", "Fair", "Poor"].map(c => <option key={c}>{c}</option>)}
                        </select>
                    </div>
                    <div style={{ display: "flex", gap: "0.75rem", justifyContent: "flex-end" }}>
                        <button style={S.btn("ghost")} onClick={() => setShowAdd(false)}>[ CANCEL ]</button>
                        <button style={S.btn("primary")} onClick={addGame}>[ CONFIRM ]</button>
                    </div>
                </Modal>
            )}
        </div>
    );
}