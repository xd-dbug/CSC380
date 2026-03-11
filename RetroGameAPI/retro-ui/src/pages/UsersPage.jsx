import { useState, useEffect } from "react";
import { apiFetch } from "../api";
import { S, COLORS } from "../styles";
import { Spinner } from "../components/Spinner";
import { Empty } from "../components/Empty";
import { Modal } from "../components/Modal";

function UserCard({ u, isMe, onWantGame, onEditMe }) {
    const [expanded, setExpanded] = useState(false);
    const [games, setGames] = useState(null);
    const [loadingGames, setLoadingGames] = useState(false);
    const [hovered, setHovered] = useState(false);

    async function toggleGames() {
        if (!expanded && games === null) {
            setLoadingGames(true);
            try {
                const g = await apiFetch(`/users/${u.id}/games`);
                setGames(g);
            } catch { setGames([]); }
            finally { setLoadingGames(false); }
        }
        setExpanded(e => !e);
    }

    return (
        <div style={{ ...S.card, ...(hovered ? S.cardHover : {}), marginBottom: "0.75rem" }}
             onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
            <div style={{ position: "absolute", top: 0, right: 0, width: "12px", height: "12px", borderLeft: `1px solid ${hovered ? COLORS.cyan : COLORS.borderDim}`, borderBottom: `1px solid ${hovered ? COLORS.cyan : COLORS.borderDim}` }} />

            {/* Header row */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.5rem" }}>
                <div>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.2rem" }}>
                        <span style={{ fontWeight: 900, fontSize: "1rem", color: COLORS.yellow, textShadow: `0 0 8px ${COLORS.yellow}88` }}>
                            {u.username}
                        </span>
                        {isMe && <span style={S.badge(COLORS.green)}>YOU</span>}
                    </div>
                    {u.fullName && <div style={{ fontSize: "0.75rem", color: COLORS.muted }}>{u.fullName}</div>}
                </div>
                <span style={{ fontSize: "0.65rem", color: COLORS.muted, fontFamily: "monospace" }}>#{u.id}</span>
            </div>

            {/* Info tags */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.4rem", marginBottom: "0.75rem" }}>
                <span style={S.tag}>✉ {u.email}</span>
                {u.address && <span style={S.tag}>📍 {u.address}</span>}
            </div>

            {/* Action buttons */}
            <div style={{ display: "flex", gap: "0.5rem" }}>
                <button style={{ ...S.btn("ghost"), fontSize: "0.7rem" }} onClick={toggleGames}>
                    {expanded ? "[ ▲ HIDE GAMES ]" : "[ ▼ VIEW GAMES ]"}
                </button>
                {isMe && (
                    <button style={{ ...S.btn("primary"), fontSize: "0.7rem" }} onClick={onEditMe}>
                        [ ✎ EDIT PROFILE ]
                    </button>
                )}
            </div>

            {/* Expandable games list */}
            {expanded && (
                <div style={{ marginTop: "0.9rem", borderTop: `1px solid ${COLORS.borderDim}`, paddingTop: "0.75rem" }}>
                    {loadingGames
                        ? <div style={{ color: COLORS.cyan, fontSize: "0.75rem", letterSpacing: "0.1em" }}>[ LOADING... ]</div>
                        : games?.length === 0
                            ? <div style={{ color: COLORS.muted, fontSize: "0.75rem" }}>&gt; No games listed</div>
                            : (
                                <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                                    {games?.map(g => (
                                        <div key={g.id} style={{ background: COLORS.bg, border: `1px solid ${COLORS.borderDim}`, padding: "0.5rem 0.75rem", display: "flex", justifyContent: "space-between", alignItems: "center", gap: "0.5rem" }}>
                                            <div>
                                                <span style={{ color: COLORS.yellow, fontWeight: 700, fontSize: "0.85rem" }}>{g.title}</span>
                                                <span style={{ color: COLORS.cyan, fontSize: "0.7rem", marginLeft: "0.5rem" }}>{g.console?.name}</span>
                                            </div>
                                            {!isMe && onWantGame && (
                                                <button style={{ ...S.btn("primary"), fontSize: "0.65rem", padding: "0.25rem 0.6rem", whiteSpace: "nowrap" }} onClick={() => onWantGame(g)}>
                                                    [ ★ WANT ]
                                                </button>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            )
                    }
                </div>
            )}
        </div>
    );
}

function EditProfileModal({ userId, onClose, onSaved }) {
    const [form, setForm] = useState({ username: "", email: "", fullName: "", address: "" });
    const [pwForm, setPwForm] = useState({ currentPassword: "", newPassword: "" });
    const [tab, setTab] = useState("profile");
    const [err, setErr] = useState("");
    const [ok, setOk] = useState("");
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        apiFetch("/users").then(users => {
            const me = users.find(u => u.id === userId);
            if (me) setForm({ username: me.username, email: me.email, fullName: me.fullName || "", address: me.address || "" });
        }).finally(() => setLoading(false));
    }, [userId]);

    const set  = k => e => setForm(f => ({ ...f, [k]: e.target.value }));
    const setPw = k => e => setPwForm(f => ({ ...f, [k]: e.target.value }));

    async function saveProfile() {
        setErr(""); setOk("");
        try {
            const updated = await apiFetch(`/users/${userId}`, {
                method: "PATCH",
                body: JSON.stringify(form),
            });
            setOk("PROFILE UPDATED.");
            onSaved(updated);
        } catch (e) { setErr(e.error || "Update failed"); }
    }

    async function savePassword() {
        setErr(""); setOk("");
        try {
            await apiFetch(`/users/${userId}/password`, {
                method: "PATCH",
                body: JSON.stringify(pwForm),
            });
            setOk("PASSWORD UPDATED.");
            setPwForm({ currentPassword: "", newPassword: "" });
        } catch (e) { setErr(e.error || "Password update failed"); }
    }

    return (
        <Modal title="EDIT PROFILE" onClose={onClose}>
            {loading ? <Spinner /> : <>
                <div style={S.tabRow}>
                    {["profile", "password"].map(t => (
                        <button key={t} style={S.navBtn(tab === t)} onClick={() => { setTab(t); setErr(""); setOk(""); }}>
                            [ {t.toUpperCase()} ]
                        </button>
                    ))}
                </div>
                <div style={S.pixelDivider} />
                {err && <div style={S.error}>{err}</div>}
                {ok  && <div style={S.success}>{ok}</div>}

                {tab === "profile" && <>
                    <div style={S.formGroup}><label style={S.label}>Username</label><input style={S.input} value={form.username} onChange={set("username")} /></div>
                    <div style={S.formGroup}><label style={S.label}>Email</label><input style={S.input} value={form.email} onChange={set("email")} /></div>
                    <div style={S.formGroup}><label style={S.label}>Full Name</label><input style={S.input} value={form.fullName} onChange={set("fullName")} /></div>
                    <div style={S.formGroup}><label style={S.label}>Address</label><input style={S.input} value={form.address} onChange={set("address")} /></div>
                    <div style={{ display: "flex", justifyContent: "flex-end" }}>
                        <button style={S.btn("primary")} onClick={saveProfile}>[ SAVE CHANGES ]</button>
                    </div>
                </>}

                {tab === "password" && <>
                    <div style={S.formGroup}><label style={S.label}>Current Password</label><input style={S.input} type="password" value={pwForm.currentPassword} onChange={setPw("currentPassword")} /></div>
                    <div style={S.formGroup}><label style={S.label}>New Password</label><input style={S.input} type="password" value={pwForm.newPassword} onChange={setPw("newPassword")} /></div>
                    <div style={{ display: "flex", justifyContent: "flex-end" }}>
                        <button style={S.btn("primary")} onClick={savePassword}>[ UPDATE PASSWORD ]</button>
                    </div>
                </>}
            </>}
        </Modal>
    );
}

export default function UsersPage({ userId, onWantGame }) {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState("");
    const [showEdit, setShowEdit] = useState(false);

    useEffect(() => {
        apiFetch("/users").then(setUsers).finally(() => setLoading(false));
    }, []);

    const filtered = users.filter(u =>
        u.username.toLowerCase().includes(search.toLowerCase()) ||
        u.fullName?.toLowerCase().includes(search.toLowerCase()) ||
        u.address?.toLowerCase().includes(search.toLowerCase())
    );

    // Move logged-in user to the top
    const sorted = userId
        ? [...filtered].sort((a, b) => (b.id === userId) - (a.id === userId))
        : filtered;

    return (
        <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
                <h1 style={S.heading}>▶ PLAYER REGISTRY</h1>
            </div>
            <div style={S.searchBar}>
                <input style={S.input} placeholder="> SEARCH PLAYERS_" value={search} onChange={e => setSearch(e.target.value)} />
            </div>
            {loading ? <Spinner /> : sorted.length === 0 ? <Empty msg="No users found" /> : (
                <div>
                    {sorted.map(u => (
                        <UserCard
                            key={u.id}
                            u={u}
                            isMe={u.id === userId}
                            onWantGame={userId ? onWantGame : null}
                            onEditMe={() => setShowEdit(true)}
                        />
                    ))}
                </div>
            )}
            {showEdit && userId && (
                <EditProfileModal
                    userId={userId}
                    onClose={() => setShowEdit(false)}
                    onSaved={updated => setUsers(us => us.map(u => u.id === updated.id ? updated : u))}
                />
            )}
        </div>
    );
}