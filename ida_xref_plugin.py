"""
IDA Pro Plugin: Register XREFs in Function
Place cursor on a register and press 'x' to list every instruction in
the current function that uses that register, including all size aliases.

Install: copy to <IDA>/plugins/ or load via File > Script File.
"""

import re
import idaapi
import idautils
import idc
import ida_ida
import ida_ua
import ida_funcs
import ida_kernwin

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import Qt

PLUGIN_NAME = "Register XREFs in Function"
PLUGIN_VERSION = "1.5"
ACTION_NAME = "regxref:show_in_func"
ACTION_HOTKEY = "x"

# ── register alias table (x86 / x86-64) ──────────────────────────────────────

_ALIAS_GROUPS = [
    ("rax",  "eax",  "ax",   "al",  "ah"),
    ("rbx",  "ebx",  "bx",   "bl",  "bh"),
    ("rcx",  "ecx",  "cx",   "cl",  "ch"),
    ("rdx",  "edx",  "dx",   "dl",  "dh"),
    ("rsi",  "esi",  "si",   "sil"),
    ("rdi",  "edi",  "di",   "dil"),
    ("rbp",  "ebp",  "bp",   "bpl"),
    ("rsp",  "esp",  "sp",   "spl"),
    ("r8",   "r8d",  "r8w",  "r8b"),
    ("r9",   "r9d",  "r9w",  "r9b"),
    ("r10",  "r10d", "r10w", "r10b"),
    ("r11",  "r11d", "r11w", "r11b"),
    ("r12",  "r12d", "r12w", "r12b"),
    ("r13",  "r13d", "r13w", "r13b"),
    ("r14",  "r14d", "r14w", "r14b"),
    ("r15",  "r15d", "r15w", "r15b"),
]

_ALIAS_MAP: dict = {}
for _grp in _ALIAS_GROUPS:
    _fs = frozenset(n.lower() for n in _grp)
    for _n in _grp:
        _ALIAS_MAP[_n.lower()] = _fs


def _get_aliases(reg_name: str) -> frozenset:
    return _ALIAS_MAP.get(reg_name.lower(), frozenset({reg_name.lower()}))


# ── helpers ───────────────────────────────────────────────────────────────────

def _is_register(name: str) -> bool:
    return bool(name) and idaapi.str2reg(name) >= 0


def _get_disasm(ea: int) -> str:
    return idc.GetDisasm(ea) or ""


_CHG = (idaapi.CF_CHG1, idaapi.CF_CHG2, idaapi.CF_CHG3,
        idaapi.CF_CHG4, idaapi.CF_CHG5, idaapi.CF_CHG6)
_USE = (idaapi.CF_USE1, idaapi.CF_USE2, idaapi.CF_USE3,
        idaapi.CF_USE4, idaapi.CF_USE5, idaapi.CF_USE6)


def _ref_type(ea: int, reg_nums: frozenset) -> str:
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea):
        return "?"
    feat = insn.get_canon_feature()
    is_w = is_r = False
    for i, op in enumerate(insn.ops):
        if op.type == idaapi.o_void or i >= len(_CHG):
            break
        if op.type == idaapi.o_reg and op.reg in reg_nums:
            if feat & _CHG[i]: is_w = True
            if feat & _USE[i]: is_r = True
        elif op.type in (idaapi.o_phrase, idaapi.o_displ) and op.reg in reg_nums:
            is_r = True
    if is_w and is_r: return "rw"
    if is_w:          return "w"
    if is_r:          return "r"
    return "?"


def find_reg_uses(reg_name: str, func, current_ea: int) -> list:
    """
    Returns [(ea, direction, rtype, addr_label, disasm), ...].
    direction is 'Up' if ea <= current_ea, else 'Down'.
    addr_label is 'FuncName+HexOffset'.
    """
    aliases  = _get_aliases(reg_name)
    reg_nums = frozenset(n for a in aliases for n in [idaapi.str2reg(a)] if n >= 0)

    sorted_aliases = sorted(aliases, key=len, reverse=True)
    pat = re.compile(
        r"(?<![a-zA-Z0-9_])"
        + "(?:" + "|".join(re.escape(a) for a in sorted_aliases) + ")"
        + r"(?![a-zA-Z0-9_])",
        re.IGNORECASE,
    )

    func_name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
    results = []

    for ea in idautils.FuncItems(func.start_ea):
        disasm = _get_disasm(ea)
        if not (disasm and pat.search(disasm)):
            continue
        direction  = "Up" if ea <= current_ea else "Down"
        rtype      = _ref_type(ea, reg_nums)
        offset     = ea - func.start_ea
        addr_label = f"{func_name}+{offset:X}" if offset else func_name
        results.append((ea, direction, rtype, addr_label, disasm))

    return results


# ── dialog ────────────────────────────────────────────────────────────────────

class RegXrefDialog(QtWidgets.QDialog):
    """
    Modal XREFs dialog styled after IDA's native 'xrefs to/from' window.
    Columns: Direction · Type · Address · Text
    Buttons: OK · Cancel · Search · Help
    """

    _HEADERS = ["Direction", "Type", "Address", "Text"]

    def __init__(self, reg_name: str, rows: list, current_ea: int):
        parent = None
        try:
            twidget = ida_kernwin.get_current_viewer()
            parent  = idaapi.PluginForm.TWidgetToPyQtWidget(twidget)
        except Exception:
            pass

        super().__init__(parent)
        # rows: [(ea, direction, rtype, addr_label, disasm), ...]
        self._rows      = rows
        self._all_rows  = rows          # kept for resetting after search
        self._nav_ea    = None          # ea to jump to on accept

        self.setWindowTitle(f"xrefs to {reg_name}")
        self.setWindowFlags(Qt.Dialog | Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setMinimumWidth(600)

        # ── table ──────────────────────────────────────────────────────
        self._table = QtWidgets.QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(self._HEADERS)
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet("""
            QTableWidget {
                background-color: #2b2b2b;
                alternate-background-color: #313335;
                color: #bbbbbb;
                border: none;
            }
            QTableWidget::item:selected {
                background-color: #2d5a8e;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #3c3f41;
                color: #bbbbbb;
                padding: 4px;
                border: none;
                border-right: 1px solid #4d4d4d;
                border-bottom: 1px solid #4d4d4d;
            }
        """)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(
            0, QtWidgets.QHeaderView.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            2, QtWidgets.QHeaderView.ResizeToContents
        )

        # ── footer label ───────────────────────────────────────────────
        self._footer = QtWidgets.QLabel(f"Line 1 of {len(rows)}")

        self._populate(rows, current_ea)

        # ── buttons ────────────────────────────────────────────────────
        self._btn_ok     = QtWidgets.QPushButton("OK")
        self._btn_cancel = QtWidgets.QPushButton("Cancel")
        self._btn_search = QtWidgets.QPushButton("Search")
        self._btn_help   = QtWidgets.QPushButton("Help")

        self._btn_ok.setDefault(True)

        btn_layout = QtWidgets.QHBoxLayout()
        btn_layout.addStretch()
        for btn in (self._btn_ok, self._btn_cancel, self._btn_search, self._btn_help):
            btn_layout.addWidget(btn)

        # ── main layout ────────────────────────────────────────────────
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)
        layout.addWidget(self._table)
        layout.addWidget(self._footer)
        layout.addLayout(btn_layout)

        # ── signals ────────────────────────────────────────────────────
        self._table.cellActivated.connect(self._on_activate)
        self._table.currentCellChanged.connect(self._on_row_change)
        self._btn_ok.clicked.connect(self._on_ok)
        self._btn_cancel.clicked.connect(self.reject)
        self._btn_search.clicked.connect(self._on_search)
        self._btn_help.clicked.connect(self._on_help)

        # ── size ───────────────────────────────────────────────────────
        self._table.resizeColumnsToContents()
        col_w   = sum(self._table.columnWidth(c) for c in range(4))
        hdr_h   = self._table.horizontalHeader().height()
        row_h   = self._table.rowHeight(0) if rows else 22
        btn_h   = self._btn_ok.sizeHint().height()
        foot_h  = self._footer.sizeHint().height()

        self.resize(
            min(col_w + 60, 900),
            hdr_h + row_h * min(len(rows), 14) + foot_h + btn_h + 40,
        )

    # ── table population ───────────────────────────────────────────────────────

    def _populate(self, rows: list, current_ea: int = -1):
        self._table.setRowCount(0)
        first_up = -1

        for r, (ea, direction, rtype, addr_label, disasm) in enumerate(rows):
            self._table.insertRow(r)
            self._table.setItem(r, 0, QtWidgets.QTableWidgetItem(direction))
            self._table.setItem(r, 1, QtWidgets.QTableWidgetItem(rtype))
            self._table.setItem(r, 2, QtWidgets.QTableWidgetItem(addr_label))
            self._table.setItem(r, 3, QtWidgets.QTableWidgetItem(disasm))
            # store ea in the first column item for retrieval
            self._table.item(r, 0).setData(Qt.UserRole, str(ea))

            if direction == "Up" and first_up < 0:
                first_up = r

        # pre-select: last 'Up' row (closest above cursor), else first row
        sel = 0
        for r, (ea, direction, *_) in enumerate(rows):
            if direction == "Up":
                sel = r
        self._table.selectRow(sel)
        self._table.scrollToItem(self._table.item(sel, 0))
        self._footer.setText(f"Line {sel + 1} of {len(rows)}")

    # ── slots ──────────────────────────────────────────────────────────────────

    def _selected_ea(self) -> int:
        row = self._table.currentRow()
        if row < 0:
            return -1
        item = self._table.item(row, 0)
        return int(item.data(Qt.UserRole)) if item else -1

    def _on_activate(self, row: int, _col: int):
        """Double-click or Enter: navigate and close."""
        item = self._table.item(row, 0)
        if item:
            ida_kernwin.jumpto(int(item.data(Qt.UserRole)))
        self.accept()

    def _on_row_change(self, row: int, _col, _prev, _pc):
        if row >= 0:
            self._footer.setText(f"Line {row + 1} of {self._table.rowCount()}")

    def _on_ok(self):
        ea = self._selected_ea()
        if ea != -1:
            ida_kernwin.jumpto(ea)
        self.accept()

    def _on_search(self):
        term, ok = QtWidgets.QInputDialog.getText(
            self, "Search", "Find text in Address or Instruction:"
        )
        if not ok or not term:
            return
        term = term.lower()
        for row in range(self._table.rowCount()):
            addr = (self._table.item(row, 2) or QtWidgets.QTableWidgetItem()).text()
            text = (self._table.item(row, 3) or QtWidgets.QTableWidgetItem()).text()
            if term in addr.lower() or term in text.lower():
                self._table.selectRow(row)
                self._table.scrollToItem(self._table.item(row, 0))
                return
        QtWidgets.QMessageBox.information(self, "Search", f"'{term}' not found.")

    def _on_help(self):
        QtWidgets.QMessageBox.information(
            self, "Register XREFs — Help",
            "Shows every instruction in the current function that references\n"
            "the selected register or any of its size aliases (e.g. rax/eax/ax/al/ah).\n\n"
            "Direction  Up = above cursor position, Down = below.\n"
            "Type       r = read, w = write, rw = read+write.\n\n"
            "Double-click or OK to navigate. Search finds the first matching row.",
        )


# ── action ────────────────────────────────────────────────────────────────────

class RegXrefAction(idaapi.action_handler_t):

    def activate(self, ctx):
        current_ea = idc.get_screen_ea()

        viewer = idaapi.get_current_viewer()
        highlight = idaapi.get_highlight(viewer)
        if not highlight:
            return 0
        reg_name, _ = highlight

        if not _is_register(reg_name):
            return 0

        func = ida_funcs.get_func(current_ea)
        if not func:
            idaapi.warning("Cursor is not inside a function.")
            return 0

        rows = find_reg_uses(reg_name, func, current_ea)
        func_name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"

        if not rows:
            idaapi.info(f"Register '{reg_name}' — no references found in '{func_name}'.")
            return 1

        RegXrefDialog(reg_name, rows, current_ea).exec()
        return 1

    def update(self, ctx):
        if ctx.widget_type != idaapi.BWN_DISASM:
            return idaapi.AST_DISABLE_FOR_WIDGET
        viewer = idaapi.get_current_viewer()
        highlight = idaapi.get_highlight(viewer)
        if highlight:
            name, _ = highlight
            if _is_register(name):
                return idaapi.AST_ENABLE
        return idaapi.AST_DISABLE


# ── right-click popup hook ────────────────────────────────────────────────────

class _PopupHook(idaapi.UI_Hooks):
    def populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(
                widget, popup, ACTION_NAME, "Register XREFs/", idaapi.SETMENU_APP
            )


# ── plugin entry point ────────────────────────────────────────────────────────

class RegXrefPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Show register XREFs within the current function"
    help = "Press 'x' on a register in the disassembly view"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        action_desc = idaapi.action_desc_t(
            ACTION_NAME,
            "Register XREFs in function",
            RegXrefAction(),
            ACTION_HOTKEY,
            "List every use of the selected register inside the current function",
            -1,
        )
        if not idaapi.register_action(action_desc):
            print(f"[{PLUGIN_NAME}] ERROR: could not register action — aborting.")
            return idaapi.PLUGIN_SKIP

        self._popup_hook = _PopupHook()
        self._popup_hook.hook()
        print(f"[{PLUGIN_NAME}] v{PLUGIN_VERSION} ready. Press '{ACTION_HOTKEY}' on a register.")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if hasattr(self, "_popup_hook"):
            self._popup_hook.unhook()
        idaapi.unregister_action(ACTION_NAME)
        print(f"[{PLUGIN_NAME}] Unloaded.")


def PLUGIN_ENTRY():
    return RegXrefPlugin()
