import { S, COLORS } from "../styles";

export function Modal({ title, onClose, children }) {
    return (
        <div style={S.modal} onClick={onClose}>
            <div style={S.modalBox} onClick={e => e.stopPropagation()}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
                    <h2 style={{ color: COLORS.magenta, margin: 0, fontSize: "1rem", letterSpacing: "0.15em", textTransform: "uppercase", textShadow: `0 0 10px ${COLORS.magenta}` }}>&gt; {title}</h2>
                    <button onClick={onClose} style={{ background: "none", border: `1px solid ${COLORS.borderDim}`, color: COLORS.muted, width: "28px", height: "28px", cursor: "pointer", fontFamily: "monospace", fontSize: "1rem" }}>×</button>
                </div>
                {children}
            </div>
        </div>
    );
}
