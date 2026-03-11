import { useState, useEffect } from "react";
import { apiFetch } from "./api";
import { S, COLORS } from "./styles";
import Scanlines from "./components/Scanlines";
import AuthPage from "./pages/AuthPage";
import GamesPage from "./pages/GamesPage";
import ConsolesPage from "./pages/ConsolesPage";
import TradesPage from "./pages/TradesPage";
import UsersPage from "./pages/UsersPage";

export default function App() {
    const [page, setPage] = useState("games");
    const [userId, setUserId] = useState(() => parseInt(localStorage.getItem("userId")) || null);
    const [consoles, setConsoles] = useState([]);
    const [companies, setCompanies] = useState([]);
    // targetGameId set when user clicks "WANT THIS" on a game card
    const [pendingTargetGame, setPendingTargetGame] = useState(null);

    useEffect(() => {
        apiFetch("/consoles").then(setConsoles).catch(() => setConsoles([]));
        apiFetch("/companies").then(setCompanies).catch(() => setCompanies([]));
    }, []);

    function handleLogin(data) {
        setUserId(data.userId);
        setPage("games");
    }

    function logout() {
        localStorage.removeItem("token");
        localStorage.removeItem("userId");
        setUserId(null);
        setPage("games");
    }

    function wantGame(game) {
        setPendingTargetGame(game);
        setPage("trades");
    }

    return (
        <div style={S.app}>
            <Scanlines />
            <nav style={S.nav}>
                <span style={S.logo} onClick={() => setPage("games")}>🎮 RGX</span>
                {["games", "consoles", "trades", "users"].map(p => (
                    <button key={p} style={S.navBtn(page === p)} onClick={() => setPage(p)}>
                        [ {p.toUpperCase()} ]
                    </button>
                ))}
                <div style={S.navRight}>
                    {userId ? (
                        <>
                            <span style={{ color: COLORS.green, fontSize: "0.8rem", letterSpacing: "0.05em", textShadow: `0 0 8px ${COLORS.green}` }}>● P{userId}</span>
                            <button style={S.btn("ghost")} onClick={logout}>[ LOGOUT ]</button>
                        </>
                    ) : (
                        <button style={S.btn("primary")} onClick={() => setPage("auth")}>[ LOGIN ]</button>
                    )}
                </div>
            </nav>
            <div style={S.main}>
                {page === "auth"     && <AuthPage onLogin={handleLogin} />}
                {page === "games"    && <GamesPage userId={userId} consoles={consoles} companies={companies} onWantGame={wantGame} />}
                {page === "consoles" && <ConsolesPage consoles={consoles} setConsoles={setConsoles} userId={userId} companies={companies} />}
                {page === "trades"   && <TradesPage userId={userId} pendingTargetGame={pendingTargetGame} clearPending={() => setPendingTargetGame(null)} />}
                {page === "users"    && <UsersPage userId={userId} onWantGame={wantGame} />}
            </div>
        </div>
    );
}