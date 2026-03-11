import { useState } from "react";
import { S, COLORS } from "../styles";

export function GameCard({ g, userId, onDelete, onWantGame }) {
    const [hovered, setHovered] = useState(false);
    const conditionColor = { Mint: COLORS.green, Good: COLORS.cyan, Fair: COLORS.orange, Poor: COLORS.red };
    const isOwn = userId && g.ownerId === userId;

    return (
        <div
            style={{ ...S.card, ...(hovered ? S.cardHover : {}) }}
            onMouseEnter={() => setHovered(true)}
            onMouseLeave={() => setHovered(false)}
        >
            <div style={{ position: "absolute", top: 0, right: 0, width: "12px", height: "12px", borderLeft: `1px solid ${hovered ? COLORS.cyan : COLORS.borderDim}`, borderBottom: `1px solid ${hovered ? COLORS.cyan : COLORS.borderDim}` }} />
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.75rem" }}>
                <h3 style={{ margin: 0, fontSize: "0.95rem", color: COLORS.yellow, textShadow: `0 0 8px ${COLORS.yellow}88`, fontWeight: 900, letterSpacing: "0.05em" }}>{g.title}</h3>
                {g.condition && <span style={S.badge(conditionColor[g.condition] || COLORS.muted)}>{g.condition}</span>}
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.4rem", marginBottom: "0.75rem" }}>
                <span style={S.tag}>🕹 {g.console?.name || "Unknown"}</span>
                {g.year > 0 && <span style={S.tag}>📅 {g.year}</span>}
                <span style={S.tag}>🏢 {g.madeBy?.companyName}</span>
            </div>
            <div style={{ fontSize: "0.75rem", color: COLORS.muted, letterSpacing: "0.05em", marginBottom: "0.75rem" }}>
                OWNER_ID: {g.ownerId}
            </div>
            <div style={{ display: "flex", gap: "0.5rem" }}>
                {/* Only show WANT THIS on other people's games when logged in */}
                {userId && !isOwn && onWantGame && (
                    <button
                        style={{ ...S.btn("primary"), fontSize: "0.7rem", flex: 1 }}
                        onClick={() => onWantGame(g)}
                    >[ ★ WANT THIS ]</button>
                )}
                {isOwn && (
                    <button
                        style={{ ...S.btn("danger"), fontSize: "0.7rem" }}
                        onClick={() => onDelete(g.id)}
                    >[ DELETE ]</button>
                )}
            </div>
        </div>
    );
}