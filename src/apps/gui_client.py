"""Modern graphical client for SecureChannel."""

import socket
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import scrolledtext

from src.protocol.message import MESSAGE_TYPE_CHAT, MESSAGE_TYPE_CLOSE
from src.protocol.socket_handshake import client_handshake
from src.protocol.transport import receive_protected_message, send_protected_message


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
CLIENT_ID = "client"
EXPECTED_SERVER_ID = "server"
PROJECT_ROOT = Path(__file__).resolve().parents[2]

BG = "#0b1220"
PANEL = "#111b2e"
ENTRY = "#08101d"
BORDER = "#263750"
TEXT = "#f8fafc"
MUTED = "#94a3b8"
CYAN = "#22d3ee"
GREEN = "#22c55e"
GREEN_DARK = "#16a34a"
RED = "#ef4444"
RED_DARK = "#dc2626"
ORANGE = "#f59e0b"
PURPLE = "#a78bfa"
BLUE = "#38bdf8"


def _collect_binary(value, seen=None) -> bytes:
    """Collect byte fields from a protected-message object for display only."""
    if seen is None:
        seen = set()

    if value is None:
        return b""

    value_id = id(value)
    if value_id in seen:
        return b""
    seen.add(value_id)

    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, (str, int, bool)):
        return b""

    for method_name in ("to_bytes", "serialize", "pack"):
        method = getattr(value, method_name, None)
        if callable(method):
            try:
                result = method()
            except (TypeError, ValueError, AttributeError):
                continue
            if isinstance(result, memoryview):
                return result.tobytes()
            if isinstance(result, (bytes, bytearray)):
                return bytes(result)

    collected = bytearray()
    for field_name in (
        "header_bytes",
        "header",
        "ciphertext",
        "tag",
        "auth_tag",
        "authentication_tag",
        "payload",
        "data",
    ):
        if hasattr(value, field_name):
            collected.extend(_collect_binary(getattr(value, field_name), seen))

    return bytes(collected)


def protected_preview(value) -> tuple[str, int | None]:
    """Return a safe hexadecimal preview without changing the message object."""
    raw = _collect_binary(value)
    if not raw:
        return repr(value), None

    full_hex = raw.hex()
    preview = full_hex if len(full_hex) <= 220 else full_hex[:220] + "..."
    return preview, len(raw)


class SecureClientGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.client_socket = None
        self.channel = None
        self.connected = False
        self.send_lock = threading.Lock()
        self.last_protected_data = ""

        self.root.title("SecureChannel • Client")
        self.root.geometry("1180x760")
        self.root.minsize(1000, 680)
        self.root.configure(bg=BG)

        self._build_ui()
        self._update_controls()
        self.root.protocol("WM_DELETE_WINDOW", self.close_program)

    @staticmethod
    def _time() -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _button(self, parent, text, command, color, active, width=12):
        return tk.Button(
            parent,
            text=text,
            command=command,
            width=width,
            bg=color,
            fg="white",
            activebackground=active,
            activeforeground="white",
            disabledforeground="#64748b",
            relief="flat",
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=10,
            pady=8,
        )

    def _entry(self, parent, width, show=None):
        return tk.Entry(
            parent,
            width=width,
            show=show,
            bg=ENTRY,
            fg=TEXT,
            insertbackground=TEXT,
            disabledbackground="#172033",
            disabledforeground=MUTED,
            relief="flat",
            font=("Segoe UI", 10),
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=CYAN,
        )

    def _build_ui(self) -> None:
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=18, pady=(14, 7))

        title_box = tk.Frame(header, bg=BG)
        title_box.pack(side="left")
        tk.Label(
            title_box,
            text="SECURECHANNEL",
            bg=BG,
            fg=TEXT,
            font=("Segoe UI", 22, "bold"),
        ).pack(anchor="w")
        tk.Label(
            title_box,
            text="Encrypted Client Console",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor="w")

        self.status_label = tk.Label(
            header,
            text="● OFFLINE",
            bg=BG,
            fg=RED,
            font=("Segoe UI", 11, "bold"),
        )
        self.status_label.pack(side="right", padx=8)

        settings = tk.Frame(self.root, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        settings.pack(fill="x", padx=18, pady=7)

        tk.Label(
            settings,
            text="CONNECTION SETTINGS",
            bg=PANEL,
            fg=CYAN,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=0, columnspan=9, sticky="w", padx=15, pady=(11, 4))

        labels = ("Host", "Port", "Shared PSK")
        positions = (0, 2, 4)
        for text, column in zip(labels, positions):
            tk.Label(settings, text=text, bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).grid(
                row=1, column=column, padx=(15, 5), pady=11
            )

        self.host_entry = self._entry(settings, 18)
        self.host_entry.grid(row=1, column=1, padx=5, pady=11)
        self.host_entry.insert(0, DEFAULT_HOST)

        self.port_entry = self._entry(settings, 9)
        self.port_entry.grid(row=1, column=3, padx=5, pady=11)
        self.port_entry.insert(0, str(DEFAULT_PORT))

        self.psk_entry = self._entry(settings, 23, show="●")
        self.psk_entry.grid(row=1, column=5, padx=5, pady=11)

        self.show_psk_button = self._button(settings, "Show", self.toggle_psk, "#334155", "#475569", 7)
        self.show_psk_button.grid(row=1, column=6, padx=5, pady=11)

        self.connect_button = self._button(settings, "Connect", self.connect_clicked, GREEN, GREEN_DARK, 12)
        self.connect_button.grid(row=1, column=7, padx=8, pady=11)

        self.tests_button = self._button(settings, "Run Tests", self.run_tests_clicked, BLUE, "#0284c7", 12)
        self.tests_button.grid(row=1, column=8, padx=(0, 15), pady=11)

        content = tk.Frame(self.root, bg=BG)
        content.pack(fill="both", expand=True, padx=18, pady=7)
        content.grid_columnconfigure(0, weight=1)
        content.grid_columnconfigure(1, weight=1)
        content.grid_rowconfigure(0, weight=1)

        chat_panel = tk.Frame(content, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        chat_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        tk.Label(chat_panel, text="ENCRYPTED CHAT • PLAINTEXT VIEW", bg=PANEL, fg=GREEN,
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=14, pady=(11, 5))

        self.chat_area = scrolledtext.ScrolledText(
            chat_panel,
            bg=ENTRY,
            fg=TEXT,
            insertbackground=TEXT,
            font=("Consolas", 10),
            relief="flat",
            wrap="word",
            state="disabled",
            padx=10,
            pady=10,
        )
        self.chat_area.pack(fill="both", expand=True, padx=12, pady=(0, 9))
        self.chat_area.tag_configure("system", foreground=CYAN)
        self.chat_area.tag_configure("me", foreground=GREEN)
        self.chat_area.tag_configure("peer", foreground=PURPLE)
        self.chat_area.tag_configure("error", foreground=RED)

        message_row = tk.Frame(chat_panel, bg=PANEL)
        message_row.pack(fill="x", padx=12, pady=(0, 12))
        self.message_entry = self._entry(message_row, 50)
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 8), ipady=6)
        self.message_entry.bind("<Return>", self.enter_pressed)
        self.send_button = self._button(message_row, "Send", self.send_clicked, GREEN, GREEN_DARK, 10)
        self.send_button.pack(side="right")

        log_panel = tk.Frame(content, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        log_panel.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        tk.Label(log_panel, text="CRYPTO & PROTOCOL LOG", bg=PANEL, fg=ORANGE,
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=14, pady=(11, 5))

        self.log_area = scrolledtext.ScrolledText(
            log_panel,
            bg=ENTRY,
            fg=TEXT,
            insertbackground=TEXT,
            font=("Consolas", 9),
            relief="flat",
            wrap="word",
            state="disabled",
            padx=10,
            pady=10,
        )
        self.log_area.pack(fill="both", expand=True, padx=12, pady=(0, 9))
        self.log_area.tag_configure("info", foreground=CYAN)
        self.log_area.tag_configure("crypto", foreground=ORANGE)
        self.log_area.tag_configure("success", foreground=GREEN)
        self.log_area.tag_configure("hex", foreground=PURPLE)
        self.log_area.tag_configure("error", foreground=RED)

        log_buttons = tk.Frame(log_panel, bg=PANEL)
        log_buttons.pack(fill="x", padx=12, pady=(0, 12))
        self.copy_button = self._button(log_buttons, "Copy Protected Data", self.copy_protected_data,
                                        "#7c3aed", "#6d28d9", 18)
        self.copy_button.pack(side="left")
        self.clear_log_button = self._button(log_buttons, "Clear Log", self.clear_log,
                                             "#334155", "#475569", 11)
        self.clear_log_button.pack(side="left", padx=8)

        bottom = tk.Frame(self.root, bg=BG)
        bottom.pack(fill="x", padx=18, pady=(2, 13))
        self.clear_chat_button = self._button(bottom, "Clear Chat", self.clear_chat,
                                              "#334155", "#475569", 12)
        self.clear_chat_button.pack(side="left")
        self.disconnect_button = self._button(bottom, "Disconnect", self.disconnect_clicked,
                                              RED, RED_DARK, 13)
        self.disconnect_button.pack(side="right")

    def append_chat(self, text: str, tag: str = "system") -> None:
        self.chat_area.config(state="normal")
        self.chat_area.insert(tk.END, f"[{self._time()}] {text}\n", tag)
        self.chat_area.config(state="disabled")
        self.chat_area.see(tk.END)

    def append_log(self, text: str, tag: str = "info") -> None:
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, f"[{self._time()}] {text}\n", tag)
        self.log_area.config(state="disabled")
        self.log_area.see(tk.END)

    def log_from_thread(self, text: str, tag: str = "info") -> None:
        self.root.after(0, self.append_log, text, tag)

    def set_status(self, text: str, color: str) -> None:
        self.status_label.config(text=f"● {text}", fg=color)

    def _update_controls(self) -> None:
        online = tk.NORMAL if self.connected else tk.DISABLED
        offline = tk.DISABLED if self.connected else tk.NORMAL
        self.connect_button.config(state=offline)
        self.send_button.config(state=online)
        self.disconnect_button.config(state=online)
        self.host_entry.config(state=offline)
        self.port_entry.config(state=offline)
        self.psk_entry.config(state=offline)
        self.show_psk_button.config(state=offline)

    def toggle_psk(self) -> None:
        visible = self.psk_entry.cget("show") == ""
        self.psk_entry.config(show="●" if visible else "")
        self.show_psk_button.config(text="Show" if visible else "Hide")

    def copy_protected_data(self) -> None:
        if not self.last_protected_data:
            self.append_log("No protected packet is available yet.", "error")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.last_protected_data)
        self.append_log("Protected data copied to the clipboard.", "success")

    def connect_clicked(self) -> None:
        host = self.host_entry.get().strip()
        psk_text = self.psk_entry.get()
        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            self.append_chat("Port must be a number.", "error")
            return

        if not host or not 1 <= port <= 65535 or not psk_text:
            self.append_chat("Enter a valid host, port, and non-empty PSK.", "error")
            return

        self.connect_button.config(state=tk.DISABLED)
        self.set_status("CONNECTING", ORANGE)
        self.append_log(f"Opening TCP connection to {host}:{port}.", "info")

        threading.Thread(
            target=self.connect_worker,
            args=(host, port, psk_text.encode("utf-8")),
            daemon=True,
        ).start()

    def connect_worker(self, host: str, port: int, psk: bytes) -> None:
        connection = None
        try:
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.settimeout(8)
            connection.connect((host, port))
            self.log_from_thread("TCP connection established.", "success")
            self.log_from_thread("Starting authenticated handshake.", "info")
            self.log_from_thread("X25519 + HMAC-SHA256 + HKDF-SHA256.", "crypto")

            channel = client_handshake(
                connection,
                client_id=CLIENT_ID,
                expected_server_id=EXPECTED_SERVER_ID,
                psk=psk,
            )
            connection.settimeout(None)

            self.client_socket = connection
            self.channel = channel
            self.connected = True
            self.log_from_thread("Handshake authenticated successfully.", "success")
            self.log_from_thread("Directional keys and nonce bases are ready.", "crypto")
            self.root.after(0, self.connection_completed, host, port)

            threading.Thread(
                target=self.receive_loop,
                args=(connection, channel),
                daemon=True,
            ).start()
        except (OSError, ValueError, ConnectionError) as error:
            if connection is not None:
                connection.close()
            self.root.after(0, self.connection_failed, str(error))

    def connection_completed(self, host: str, port: int) -> None:
        self.append_chat(f"Securely connected to {host}:{port}.", "system")
        self.append_log("SecureChannel is ready for encrypted traffic.", "success")
        self.set_status("SECURE", GREEN)
        self._update_controls()
        self.message_entry.focus_set()

    def connection_failed(self, error_text: str) -> None:
        self.connected = False
        self.append_chat(f"Connection failed: {error_text}", "error")
        self.append_log("Connection or handshake failed.", "error")
        self.set_status("OFFLINE", RED)
        self._update_controls()

    def send_secure(self, connection, channel, text: str, message_type: int) -> None:
        plaintext = text.encode("utf-8")
        self.log_from_thread(f"Plaintext prepared: {len(plaintext)} bytes.", "info")

        protected_message = channel.encrypt_message(
            plaintext=plaintext,
            message_type=message_type,
        )

        preview, byte_count = protected_preview(protected_message)
        self.last_protected_data = preview
        self.log_from_thread("ChaCha20-Poly1305 encryption completed.", "crypto")
        if byte_count is None:
            self.log_from_thread("Protected message preview: " + preview, "hex")
        else:
            self.log_from_thread(f"Protected bytes ({byte_count} bytes): {preview}", "hex")

        send_protected_message(connection, protected_message)
        self.log_from_thread("Protected message sent through TCP.", "success")

    def receive_secure(self, connection, channel) -> tuple[int, str]:
        protected_message = receive_protected_message(connection)
        preview, byte_count = protected_preview(protected_message)
        self.last_protected_data = preview

        if byte_count is None:
            self.log_from_thread("Received protected message: " + preview, "hex")
        else:
            self.log_from_thread(f"Received protected bytes ({byte_count} bytes): {preview}", "hex")

        header, plaintext = channel.decrypt_message(protected_message)
        sequence = getattr(header, "sequence_number", getattr(header, "sequence", "verified"))
        self.log_from_thread(f"Tag and sequence check passed: {sequence}.", "success")
        self.log_from_thread("ChaCha20 decryption completed.", "crypto")

        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("Received message is not valid UTF-8") from error
        return header.message_type, text

    def send_clicked(self) -> None:
        if not self.connected:
            return
        text = self.message_entry.get()
        if not text.strip():
            return

        self.message_entry.delete(0, tk.END)
        self.send_button.config(state=tk.DISABLED)
        threading.Thread(
            target=self.send_worker,
            args=(self.client_socket, self.channel, text),
            daemon=True,
        ).start()

    def send_worker(self, connection, channel, text: str) -> None:
        try:
            with self.send_lock:
                self.send_secure(connection, channel, text, MESSAGE_TYPE_CHAT)
            self.root.after(0, self.append_chat, f"You: {text}", "me")
        except (OSError, ValueError, ConnectionError) as error:
            self.root.after(0, self.finish_disconnect, f"Send failed: {error}", connection)
        finally:
            self.root.after(0, self._update_controls)

    def receive_loop(self, connection, channel) -> None:
        reason = "Connection closed."
        try:
            while self.connected and connection is self.client_socket:
                message_type, text = self.receive_secure(connection, channel)
                if message_type == MESSAGE_TYPE_CLOSE:
                    reason = "Server closed the connection."
                    break
                if message_type != MESSAGE_TYPE_CHAT:
                    raise ValueError("Unknown message type")
                self.root.after(0, self.append_chat, f"Server: {text}", "peer")
        except (OSError, ValueError, ConnectionError) as error:
            if self.connected:
                reason = f"Receive failed: {error}"
        finally:
            self.root.after(0, self.finish_disconnect, reason, connection)

    def disconnect_clicked(self) -> None:
        if not self.connected:
            return
        self.send_button.config(state=tk.DISABLED)
        self.disconnect_button.config(state=tk.DISABLED)
        self.set_status("DISCONNECTING", ORANGE)
        threading.Thread(
            target=self.disconnect_worker,
            args=(self.client_socket, self.channel),
            daemon=True,
        ).start()

    def disconnect_worker(self, connection, channel) -> None:
        try:
            with self.send_lock:
                self.send_secure(connection, channel, "", MESSAGE_TYPE_CLOSE)
        except (OSError, ValueError, ConnectionError):
            pass
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        connection.close()
        self.root.after(0, self.finish_disconnect, "Disconnected by user.", connection)

    def finish_disconnect(self, reason: str, old_socket=None) -> None:
        if old_socket is not None and self.client_socket is not old_socket:
            return
        current = self.client_socket
        self.client_socket = None
        self.channel = None
        self.connected = False
        if current is not None:
            try:
                current.close()
            except OSError:
                pass
        self.append_chat(reason, "system")
        self.append_log("Secure session ended.", "info")
        self.set_status("OFFLINE", RED)
        self._update_controls()

    def run_tests_clicked(self) -> None:
        self.tests_button.config(state=tk.DISABLED)
        self.append_log("Running the complete pytest suite...", "info")
        threading.Thread(target=self.run_tests_worker, daemon=True).start()

    def run_tests_worker(self) -> None:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "-q"],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                check=False,
                timeout=180,
            )
            output = result.stdout.strip()
            if result.stderr.strip():
                output += "\n" + result.stderr.strip()
            self.root.after(0, self.show_test_result, result.returncode, output)
        except (OSError, subprocess.TimeoutExpired) as error:
            self.root.after(0, self.show_test_result, 1, str(error))

    def show_test_result(self, return_code: int, output: str) -> None:
        for line in output.splitlines():
            self.append_log(line, "info")
        self.append_log(
            "All tests passed successfully." if return_code == 0 else "One or more tests failed.",
            "success" if return_code == 0 else "error",
        )
        self.tests_button.config(state=tk.NORMAL)

    def clear_chat(self) -> None:
        self.chat_area.config(state="normal")
        self.chat_area.delete("1.0", tk.END)
        self.chat_area.config(state="disabled")

    def clear_log(self) -> None:
        self.log_area.config(state="normal")
        self.log_area.delete("1.0", tk.END)
        self.log_area.config(state="disabled")

    def enter_pressed(self, _event) -> str:
        self.send_clicked()
        return "break"

    def close_program(self) -> None:
        self.connected = False
        if self.client_socket is not None:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.client_socket.close()
            except OSError:
                pass
        self.root.destroy()


if __name__ == "__main__":
    app_root = tk.Tk()
    SecureClientGUI(app_root)
    app_root.mainloop()
