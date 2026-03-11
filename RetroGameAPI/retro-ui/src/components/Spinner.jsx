import { COLORS } from "../styles";

export function Spinner() {
    return (
        <div style={{ textAlign: "center", padding: "3rem", color: COLORS.cyan, letterSpacing: "0.2em", textTransform: "uppercase", fontSize: "0.85rem" }}>
            <span style={{ textShadow: `0 0 10px ${COLORS.cyan}` }}>[ LOADING... ]</span>
        </div>
    );
}
