export default function Scanlines() {
    return (
        <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 999, backgroundImage: "repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(0,0,0,0.08) 3px, rgba(0,0,0,0.08) 4px)" }} />
    );
}
