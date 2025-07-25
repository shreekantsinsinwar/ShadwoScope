# ShadowScope - Shodan Recon Toolkit
import tkinter as tk
from tkinter import ttk, messagebox
import shodan

THEME_BG = "#1e1e2f"
THEME_FG = "#f5f5f5"
ACCENT_COLOR = "#38bdf8"

class ShadowScopeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ShadowScope - Shodan Recon Toolkit")
        self.root.geometry("750x500")
        self.root.configure(bg=THEME_BG)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=THEME_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=THEME_BG, foreground=THEME_FG, padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", ACCENT_COLOR)], foreground=[("selected", THEME_BG)])

        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill="both", expand=True)

        self.create_lookup_tab()
        self.create_help_tab()

    def create_lookup_tab(self):
        tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(tab, text="🔍 Recon")

        tk.Label(tab, text="🔐 Shodan API Key", bg=THEME_BG, fg=ACCENT_COLOR).pack(pady=5)
        self.api_key_entry = tk.Entry(tab, width=60)
        self.api_key_entry.pack(pady=5)

        tk.Label(tab, text="🌐 Enter IP or Domain", bg=THEME_BG, fg=ACCENT_COLOR).pack(pady=5)
        self.target_entry = tk.Entry(tab, width=60)
        self.target_entry.pack(pady=5)

        tk.Button(tab, text="Scan Target", bg=ACCENT_COLOR, fg=THEME_BG, command=self.perform_scan).pack(pady=10)

        self.output_text = tk.Text(tab, height=20, bg="#121212", fg=THEME_FG, insertbackground=THEME_FG)
        self.output_text.pack(fill="both", expand=True, padx=10, pady=5)

    def create_help_tab(self):
        tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(tab, text="📖 How to Use")

        help_text = """
👁️‍🗨️ Welcome to ShadowScope — your Shodan-powered intelligence lens

This tool lets you perform real-time reconnaissance on any public IP or domain using Shodan's powerful API.

🛠 Steps to Use:
1. Get your FREE Shodan API key from: https://account.shodan.io/register
2. Enter the key in the first box.
3. Type an IP address or domain you want to investigate.
4. Click "Scan Target" and wait for the magic.

📌 What You Get:
- Open ports
- Detected services
- Hostnames
- City, Country, ISP info
- OS fingerprint (if available)
- Banner grabs (great for spotting weak spots)

⚠️ Notes:
- Don’t use your API limit carelessly.
- This tool does NOT perform any active scanning — all data is from Shodan’s database.
- Educational & ethical use only!

🔍 Example Targets:
- `8.8.8.8`
- `scanme.shodan.io`
"""
        tk.Label(tab, text=help_text, justify="left", wraplength=700, font=("Consolas", 10), bg=THEME_BG, fg=THEME_FG).pack(padx=10, pady=10)

    def perform_scan(self):
        api_key = self.api_key_entry.get().strip()
        target = self.target_entry.get().strip()

        if not api_key or not target:
            messagebox.showwarning("Input Required", "Please enter both API key and a target.")
            return

        try:
            api = shodan.Shodan(api_key)
            host = api.host(target)

            output = f"🔎 Info for {target}:\n\n"
            output += f"IP: {host.get('ip_str', 'N/A')}\n"
            output += f"City: {host.get('city', 'N/A')}\n"
            output += f"Country: {host.get('country_name', 'N/A')}\n"
            output += f"ISP: {host.get('isp', 'N/A')}\n"
            output += f"Org: {host.get('org', 'N/A')}\n"
            output += f"OS: {host.get('os', 'N/A')}\n\n"

            for service in host['data']:
                output += f"🟢 Port {service['port']}\n"
                output += f"   Banner:\n{service.get('data', '').strip()[:300]}...\n\n"

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, output)

        except shodan.APIError as e:
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, f"❌ Shodan API Error: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ShadowScopeApp(root)
    root.mainloop()
