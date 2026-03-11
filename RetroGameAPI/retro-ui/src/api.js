
export const API = "http://localhost:30080";
export const token = () => localStorage.getItem("token");

export async function apiFetch(path, opts = {}) {
    const res = await fetch(`${API}${path}`, {
        ...opts,
        headers: {
            "Content-Type": "application/json",
            ...(token() ? { Authorization: `Bearer ${token()}` } : {}),
            ...(opts.headers || {}),
        },
    });
    if (!res.ok) throw await res.json();
    if (res.status === 204) return null;
    return res.json();
}