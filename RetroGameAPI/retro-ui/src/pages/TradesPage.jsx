import { useState, useEffect } from "react";
import { apiFetch } from "../api";
import { S, COLORS } from "../styles";
import { Modal } from "../components/Modal";
import { Spinner } from "../components/Spinner";
import { Empty } from "../components/Empty";

const statusColor = { pending: COLORS.orange, accepted: COLORS.green, rejected: COLORS.red };
const statusGlow  = { pending: "#ff880055", accepted: "#00ff8855", rejected: "#ff335555" };
const conditionColor = { Mint: COLORS.green, Good: COLORS.cyan, Fair: COLORS.orange, Poor: COLORS.red };

function GameSlot({ label, game, accentColor }) {
    return (
        <div style={{
            background: COLORS.bg, border: `1px solid ${accentColor}44`, padding: "0.75rem", flex: 1,
            clipPath: "polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))",
        }}>
            <div style={{ fontSize: "0.6rem", color: accentColor, marginBottom: "0.4rem", letterSpacing: "0.15em", textTransform: "uppercase", textShadow: `0 0 6px ${accentColor}` }}>{label}</div>
            <div style={{ fontWeight: 900, fontSize: "0.9rem", color: COLORS.yellow, textShadow: `0 0 6px ${COLORS.yellow}88`, marginBottom: "0.3rem", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {game?.title || "???"}
            </div>
            <div style={{ fontSize: "0.7rem", color: COLORS.cyan, marginBottom: "0.25rem" }}>🕹 {game?.console?.name || "—"}</div>
            <div style={{ display: "flex", gap: "0.3rem", flexWrap: "wrap", marginTop: "0.4rem" }}>
                {game?.year > 0 && <span style={{ ...S.tag, fontSize: "0.6rem" }}>📅 {game.year}</span>}
                {game?.condition && <span style={{ ...S.badge(conditionColor[game.condition] || COLORS.muted), fontSize: "0.6rem" }}>{game.condition}</span>}
            </div>
        </div>
    );
}

function TradeCard({ offer, showActions, onRespond }) {
    const [hovered, setHovered] = useState(false);
    const sColor = statusColor[offer.status] || COLORS.muted;
    const sGlow  = statusGlow[offer.status]  || "transparent";
    return (
        <div
            style={{ background: COLORS.panel, border: `1px solid ${hovered ? sColor : COLORS.borderDim}`, padding: "1.1rem", position: "relative", transition: "border-color 0.2s, box-shadow 0.2s", boxShadow: hovered ? `0 0 18px ${sGlow}` : "none", clipPath: "polygon(0 0, calc(100% - 14px) 0, 100% 14px, 100% 100%, 14px 100%, 0 calc(100% - 14px))" }}
            onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}
        >
            <div style={{ position: "absolute", top: 0, right: 0, width: "14px", height: "14px", borderLeft: `1px solid ${hovered ? sColor : COLORS.borderDim}`, borderBottom: `1px solid ${hovered ? sColor : COLORS.borderDim}` }} />
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.9rem" }}>
                <span style={{ fontSize: "0.7rem", color: COLORS.muted, letterSpacing: "0.12em" }}>
                    OFFER <span style={{ color: sColor, textShadow: `0 0 6px ${sColor}` }}>#{String(offer.id).padStart(4, "0")}</span>
                </span>
                <span style={{ ...S.badge(sColor), fontSize: "0.6rem", boxShadow: `0 0 8px ${sGlow}` }}>◆ {offer.status.toUpperCase()}</span>
            </div>
            <div style={{ display: "flex", gap: "0.5rem", alignItems: "stretch", marginBottom: "0.85rem" }}>
                <GameSlot label="◀ OFFERING" game={offer.offeredGame} accentColor={COLORS.magenta} />
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", fontSize: "1.2rem", color: COLORS.magenta, flexShrink: 0, textShadow: `0 0 12px ${COLORS.magenta}`, padding: "0 0.2rem" }}>⇄</div>
                <GameSlot label="▶ WANTING"  game={offer.targetGame}  accentColor={COLORS.cyan} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: `1px solid ${COLORS.borderDim}`, paddingTop: "0.6rem", marginBottom: showActions && offer.status === "pending" ? "0.75rem" : 0 }}>
                <span style={{ fontSize: "0.7rem", color: COLORS.muted }}>
                    👤 <span style={{ color: COLORS.cyan }}>{offer.createdByUser?.username || `#${offer.createdByUserID}`}</span>
                </span>
                <span style={{ fontSize: "0.65rem", color: COLORS.muted }}>{offer.createdAt?.slice(0, 10)}</span>
            </div>
            {showActions && offer.status === "pending" && (
                <div style={{ display: "flex", gap: "0.5rem" }}>
                    <button style={{ ...S.btn("success"), flex: 1, fontSize: "0.72rem" }} onClick={() => onRespond(offer.id, "accepted")}>[ ✓ ACCEPT ]</button>
                    <button style={{ ...S.btn("danger"),  flex: 1, fontSize: "0.72rem" }} onClick={() => onRespond(offer.id, "rejected")}>[ ✗ REJECT ]</button>
                </div>
            )}
        </div>
    );
}

export default function TradesPage({ userId, pendingTargetGame, clearPending }) {
    const [tab, setTab] = useState("incoming");
    const [incoming, setIncoming] = useState([]);
    const [outgoing, setOutgoing] = useState([]);
    const [loading, setLoading] = useState(true);
    const [myGames, setMyGames] = useState([]);
    const [showCreate, setShowCreate] = useState(false);
    const [targetGame, setTargetGame] = useState(null);   // full game object
    const [offeredGameId, setOfferedGameId] = useState("");
    const [err, setErr] = useState("");
    const [ok, setOk] = useState("");

    useEffect(() => {
        if (!userId) return;
        Promise.all([
            apiFetch("/trade-offers/incoming"),
            apiFetch("/trade-offers/outgoing"),
            apiFetch(`/users/${userId}/games`),
        ]).then(([inc, out, mine]) => {
            setIncoming(inc);
            setOutgoing(out);
            setMyGames(mine);
        }).finally(() => setLoading(false));
    }, [userId]);

    // Open the modal automatically when navigated here via "WANT THIS"
    useEffect(() => {
        if (pendingTargetGame) {
            setTargetGame(pendingTargetGame);
            setOfferedGameId("");
            setErr("");
            setShowCreate(true);
            clearPending();
        }
    }, [pendingTargetGame]);

    function openCreate() {
        setTargetGame(null);
        setOfferedGameId("");
        setErr("");
        setShowCreate(true);
    }

    async function createOffer() {
        setErr("");
        if (!targetGame) { setErr("No target game selected"); return; }
        if (!offeredGameId) { setErr("Please select a game to offer"); return; }
        try {
            const offer = await apiFetch("/trade-offers", {
                method: "POST",
                body: JSON.stringify({ targetGameId: targetGame.id, offeredGameId: parseInt(offeredGameId) })
            });
            setOutgoing(o => [offer, ...o]);
            setShowCreate(false);
            setOk("TRADE OFFER TRANSMITTED.");
        } catch (e) { setErr(e.error || "Failed to create offer"); }
    }

    async function respond(id, status) {
        await apiFetch(`/trade-offers/${id}/status`, { method: "PATCH", body: JSON.stringify({ status }) });
        setIncoming(offers => offers.map(o => o.id === id ? { ...o, status } : o));
    }

    if (!userId) return (
        <div style={{ textAlign: "center", paddingTop: "4rem", color: COLORS.muted, letterSpacing: "0.1em" }}>
            <div style={{ fontSize: "2rem", marginBottom: "1rem" }}>🔒</div>
            <div style={{ textTransform: "uppercase" }}>&gt; ACCESS DENIED. PLEASE LOGIN._</div>
        </div>
    );

    const activeList = tab === "incoming" ? incoming : outgoing;

    return (
        <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
                <h1 style={S.heading}>▶ TRADE TERMINAL</h1>
                <button style={S.btn("primary")} onClick={openCreate}>[ + NEW TRADE ]</button>
            </div>
            {ok && <div style={S.success}>{ok}</div>}
            <div style={S.tabRow}>
                {["incoming", "outgoing"].map(t => (
                    <button key={t} onClick={() => setTab(t)} style={S.navBtn(tab === t)}>
                        {t === "incoming" ? `[ ▼ INCOMING: ${incoming.length} ]` : `[ ▲ OUTGOING: ${outgoing.length} ]`}
                    </button>
                ))}
            </div>
            {activeList.length > 0 && (
                <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem" }}>
                    {["pending","accepted","rejected"].map(s => {
                        const n = activeList.filter(o => o.status === s).length;
                        return n > 0 ? <span key={s} style={{ ...S.badge(statusColor[s]), cursor: "default" }}>{s}: {n}</span> : null;
                    })}
                </div>
            )}
            {loading ? <Spinner /> : activeList.length === 0
                ? <Empty msg={`No ${tab} offers`} />
                : <div style={S.grid}>{activeList.map(o => <TradeCard key={o.id} offer={o} showActions={tab === "incoming"} onRespond={respond} />)}</div>
            }

            {showCreate && (
                <Modal title="INITIATE TRADE" onClose={() => setShowCreate(false)}>
                    {err && <div style={S.error}>{err}</div>}

                    {/* Target game — locked if pre-filled, manual ID entry otherwise */}
                    <div style={S.formGroup}>
                        <label style={S.label}>You Want</label>
                        {targetGame ? (
                            <div style={{ background: COLORS.bg, border: `1px solid ${COLORS.cyan}44`, padding: "0.6rem 0.9rem", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                <span style={{ color: COLORS.yellow, fontWeight: 900, fontSize: "0.85rem" }}>{targetGame.title}</span>
                                <span style={{ fontSize: "0.7rem", color: COLORS.cyan }}>{targetGame.console?.name}</span>
                                <button onClick={() => setTargetGame(null)} style={{ background: "none", border: "none", color: COLORS.muted, cursor: "pointer", fontFamily: "monospace", fontSize: "0.9rem" }}>×</button>
                            </div>
                        ) : (
                            <input style={S.input} type="number" placeholder="Enter target game ID manually" onChange={e => setTargetGame({ id: parseInt(e.target.value), title: `Game #${e.target.value}` })} />
                        )}
                    </div>

                    {/* Offered game — dropdown of user's own games */}
                    <div style={S.formGroup}>
                        <label style={S.label}>You Offer</label>
                        {myGames.length === 0
                            ? <div style={{ color: COLORS.muted, fontSize: "0.8rem", padding: "0.5rem 0" }}>You have no games listed. Add games first.</div>
                            : (
                                <select style={S.input} value={offeredGameId} onChange={e => setOfferedGameId(e.target.value)}>
                                    <option value="">-- SELECT YOUR GAME --</option>
                                    {myGames.map(g => (
                                        <option key={g.id} value={g.id}>{g.title} ({g.console?.name})</option>
                                    ))}
                                </select>
                            )
                        }
                    </div>

                    <div style={{ display: "flex", gap: "0.75rem", justifyContent: "flex-end" }}>
                        <button style={S.btn("ghost")} onClick={() => setShowCreate(false)}>[ CANCEL ]</button>
                        <button style={S.btn("primary")} onClick={createOffer}>[ TRANSMIT ]</button>
                    </div>
                </Modal>
            )}
        </div>
    );
}