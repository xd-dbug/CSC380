import { COLORS } from "../styles";

export function Empty({ msg }) {
    return (
        <div style={{ textAlign: "center", padding: "3rem", color: COLORS.muted, letterSpacing: "0.1em", textTransform: "uppercase", fontSize: "0.8rem", border: `1px dashed ${COLORS.borderDim}` }}>
            &gt; {msg} _
        </div>
    );
}
