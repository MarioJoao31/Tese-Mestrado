from __future__ import annotations

import tkinter as tk


class ToolTip:
    """Lightweight hover tooltip for Tkinter widgets."""

    def __init__(self, widget: tk.Widget, text: str, delay_ms: int = 450) -> None:
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self._after_id: str | None = None
        self._tip_window: tk.Toplevel | None = None

        self.widget.bind("<Enter>", self._schedule_show, add="+")
        self.widget.bind("<Leave>", self._hide, add="+")
        self.widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule_show(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        self._cancel_scheduled()
        self._after_id = self.widget.after(self.delay_ms, self._show)

    def _cancel_scheduled(self) -> None:
        if self._after_id:
            self.widget.after_cancel(self._after_id)
            self._after_id = None

    def _show(self) -> None:
        self._after_id = None
        if self._tip_window or not self.text.strip():
            return

        x = self.widget.winfo_rootx() + 14
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6

        self._tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")

        label = tk.Label(
            tw,
            text=self.text,
            justify=tk.LEFT,
            background="#1c1b19",
            relief=tk.SOLID,
            borderwidth=1,
            padx=6,
            pady=4,
            font=("TkDefaultFont", 9),
            wraplength=360,
        )
        label.pack()

    def _hide(self, _event: tk.Event | None = None) -> None:  # type: ignore[type-arg]
        self._cancel_scheduled()
        if self._tip_window:
            self._tip_window.destroy()
            self._tip_window = None


def attach_tooltip(widget: tk.Widget, text: str) -> ToolTip:
    tooltip = ToolTip(widget, text)
    # Keep a reference on the widget to avoid accidental garbage collection.
    setattr(widget, "_tooltip", tooltip)
    return tooltip
