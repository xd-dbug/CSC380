import { useState } from "react";
import { apiFetch } from "../api";
import { S, COLORS } from "../styles";

export default function AuthPage({ onLogin }) {
    const [mode, setMode] = useState("login");
    const [form, setForm] = useState({ username: "", password: "", email: "", fullName: "", address: "" });
    const [err, setErr] = useState("");
    const [ok, setOk] = useState("");

    const set = k => e => setForm(f => ({ ...f, [k]: e.target.value }));

    async function submit() {
        setErr(""); setOk("");
        try {
            if (mode === "login") {
                const data = await apiFetch("/login", {
                    method: "POST",
                    body: JSON.stringify({ username: form.username, password: form.password })
                });
                localStorage.setItem("token", data.token);
                localStorage.setItem("userId", data.userId);
                onLogin(data);
            } else {
                await apiFetch("/register", { method: "POST", body: JSON.stringify(form) });
                setOk("REGISTRATION COMPLETE. PLEASE LOGIN.");
                setMode("login");
            }
        } catch (e) { setErr(e.error || "AUTH FAILED"); }
    }

    return (
        <div style={{ ...S.main, maxWidth: "420px" }}>
            <div style={{ textAlign: "center", padding: "2rem 0 1rem", color: COLORS.yellow, fontSize: "2rem", textShadow: `0 0 20px ${COLORS.yellow}` }}>🎮</div>
            <div style={{ textAlign: "center", marginBottom: "2rem", color: COLORS.cyan, letterSpacing: "0.2em", textTransform: "uppercase", textShadow: `0 0 10px ${COLORS.cyan}`, fontSize: "0.85rem" }}>RETRO GAME EXCHANGE v1.0</div>
            <div style={S.card}>
                <div style={S.tabRow}>
                    {["login", "register"].map(m => (
                        <button key={m} onClick={() => setMode(m)} style={S.navBtn(mode === m)}>[ {m.toUpperCase()} ]</button>
                    ))}
                </div>
                <div style={S.pixelDivider} />
                {err && <div style={S.error}>&gt; ERROR: {err}</div>}
                {ok && <div style={S.success}>&gt; {ok}</div>}
                <div style={S.formGroup}>
                    <label style={S.label}>Username</label>
                    <input style={S.input} value={form.username} onChange={set("username")} onKeyDown={e => e.key === "Enter" && submit()} />
                </div>
                {mode === "register" && <>
                    <div style={S.formGroup}>
                        <label style={S.label}>Email</label>
                        <input style={S.input} value={form.email} onChange={set("email")} />
                    </div>
                    <div style={S.formGroup}>
                        <label style={S.label}>Full Name</label>
                        <input style={S.input} value={form.fullName} onChange={set("fullName")} />
                    </div>
                    <div style={S.formGroup}>
                        <label style={S.label}>Address</label>
                        <input style={S.input} placeholder="123 Main St, City, State" value={form.address} onChange={set("address")} />
                    </div>
                </>}
                <div style={S.formGroup}>
                    <label style={S.label}>Password</label>
                    <input style={S.input} type="password" value={form.password} onChange={set("password")} onKeyDown={e => e.key === "Enter" && submit()} />
                </div>
                <button style={{ ...S.btn("primary"), width: "100%", padding: "0.75rem" }} onClick={submit}>
                    [ {mode === "login" ? "PRESS START" : "CREATE PLAYER"} ]
                </button>
            </div>
        </div>
    );
}