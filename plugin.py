import traceback
import cutter
from . import drcov
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QLabel, QFileDialog, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QCheckBox, QAbstractItemView
)
from PySide6.QtGui import QAction, QColor


class NumericTableItem(QTableWidgetItem):
    """Сортировка по числовому значению (для % покрытия)"""
    def __lt__(self, other):
        try:
            return float(self.text().rstrip('%')) < float(other.text().rstrip('%'))
        except (ValueError, AttributeError):
            return super().__lt__(other)


class HexTableItem(QTableWidgetItem):
    """Сортировка по hex-значению адреса"""
    def __lt__(self, other):
        try:
            return int(self.text(), 16) < int(other.text(), 16)
        except (ValueError, AttributeError):
            return super().__lt__(other)


class DRCovWidget(cutter.CutterDockWidget):
    def __init__(self, parent, action):
        super().__init__(parent, action)
        self.setObjectName("DRCovWidget")
        self.setWindowTitle("DynamoRIO Coverage")

        self.normalized_coverage = {}   # {norm_addr: True}
        self.modules = {}
        self.pe_base = 0x140000000
        self.drcov_base = 0
        self.ignored_blocks = set()     # адреса блоков, исключённых из статистики
        self._func_blocks_cache = {}    # {func_addr: [block_dict, ...]}
        self._highlighted_addrs = set() # адреса подсвеченных блоков в CFG

        self._init_ui()
        try:
            cutter.core().seekChanged.connect(self._on_seek_changed)
        except Exception:
            pass


    # UI

    def _init_ui(self):
        root = QWidget()
        root_layout = QVBoxLayout()
        root_layout.setContentsMargins(4, 4, 4, 4)

        # Верхняя панель
        top_bar = QHBoxLayout()
        self.load_btn = QPushButton("Load Coverage File")
        self.load_btn.clicked.connect(self.load_coverage_file)
        self.status_label = QLabel("No coverage data loaded")
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_coverage)
        self.clear_btn.setEnabled(False)
        self.highlight_btn = QPushButton("Подсветить покрытие в графе")
        self.highlight_btn.clicked.connect(self._highlight_current_function)
        self.highlight_btn.setEnabled(False)
        self.reset_highlight_btn = QPushButton("Сбросить подсветку графа")
        self.reset_highlight_btn.clicked.connect(self._reset_graph_highlight)
        self.reset_highlight_btn.setEnabled(False)
        top_bar.addWidget(self.load_btn)
        top_bar.addWidget(self.status_label, 1)
        top_bar.addWidget(self.highlight_btn)
        top_bar.addWidget(self.reset_highlight_btn)
        top_bar.addWidget(self.clear_btn)
        root_layout.addLayout(top_bar)

        # Главный сплиттер: 2/3 верх / 1/3 низ
        main_splitter = QSplitter(Qt.Vertical)

        # ---- Верхняя часть: таблица функций + таблица блоков ----
        top_widget = QWidget()
        top_layout = QHBoxLayout()
        top_layout.setContentsMargins(0, 0, 0, 0)

        # Левая панель — функции
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 2, 0)

        func_header = QHBoxLayout()
        func_header.addWidget(QLabel("Functions"))
        self.hide_100_cb = QCheckBox("Hide 100% covered")
        self.hide_100_cb.stateChanged.connect(self._apply_hide_100)
        func_header.addWidget(self.hide_100_cb)
        left_layout.addLayout(func_header)

        self.func_table = QTableWidget(0, 3)
        self.func_table.setHorizontalHeaderLabels(["Function", "Covered / Total", "Coverage %"])
        self.func_table.setSortingEnabled(True)
        self.func_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.func_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.func_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.func_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.func_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.func_table.itemSelectionChanged.connect(self._on_func_selected)
        self.func_table.itemDoubleClicked.connect(self._on_func_double_clicked)
        left_layout.addWidget(self.func_table)
        left_panel.setLayout(left_layout)

        # Правая панель — базовые блоки
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(2, 0, 0, 0)

        bb_header = QHBoxLayout()
        self.bb_label = QLabel("Basic Blocks")
        bb_header.addWidget(self.bb_label)
        self.ignore_single_cb = QCheckBox("Ignore single-instr blocks")
        self.ignore_single_cb.stateChanged.connect(self._on_ignore_single_changed)
        bb_header.addWidget(self.ignore_single_cb)
        right_layout.addLayout(bb_header)

        self.bb_table = QTableWidget(0, 4)
        self.bb_table.setHorizontalHeaderLabels(["Address", "First Instruction", "Covered", "Ignore"])
        self.bb_table.setSortingEnabled(True)
        self.bb_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.bb_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.bb_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.bb_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.bb_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.bb_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        right_layout.addWidget(self.bb_table)

        bb_btns = QHBoxLayout()
        self.ignore_sel_btn = QPushButton("Ignore Selected")
        self.ignore_sel_btn.clicked.connect(self._ignore_selected_blocks)
        self.unignore_all_btn = QPushButton("Unignore All")
        self.unignore_all_btn.clicked.connect(self._unignore_all_blocks)
        bb_btns.addWidget(self.ignore_sel_btn)
        bb_btns.addWidget(self.unignore_all_btn)
        right_layout.addLayout(bb_btns)
        right_panel.setLayout(right_layout)

        top_splitter = QSplitter(Qt.Horizontal)
        top_splitter.addWidget(left_panel)
        top_splitter.addWidget(right_panel)
        top_splitter.setSizes([500, 500])
        top_layout.addWidget(top_splitter)
        top_widget.setLayout(top_layout)

        # ---- Нижняя часть — лог ----
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout()
        bottom_layout.setContentsMargins(0, 2, 0, 0)

        log_bar = QHBoxLayout()
        log_bar.addWidget(QLabel("Log"))
        log_bar.addStretch()
        clear_log_btn = QPushButton("Clear Log")
        clear_log_btn.clicked.connect(lambda: self.log_text.clear())
        log_bar.addWidget(clear_log_btn)
        bottom_layout.addLayout(log_bar)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        bottom_layout.addWidget(self.log_text)
        bottom_widget.setLayout(bottom_layout)

        main_splitter.addWidget(top_widget)
        main_splitter.addWidget(bottom_widget)
        main_splitter.setSizes([667, 333])

        root_layout.addWidget(main_splitter)
        root.setLayout(root_layout)
        self.setWidget(root)


    # Лог

    def _log(self, msg, level="info"):
        colors = {
            "info":  "#aaaaaa",
            "ok":    "#00cc44",
            "warn":  "#ffaa00",
            "error": "#ff4444",
        }
        color = colors.get(level, "#aaaaaa")
        self.log_text.append(f'<span style="color:{color};">{msg}</span>')


    # Cutter API

    def get_image_base(self):
        try:
            info = cutter.cmdj("ij")
            if info and 'bin' in info:
                baddr = info['bin'].get('baddr', 0)
                if baddr:
                    return baddr
        except Exception:
            pass
        return 0x140000000

    def is_address_covered(self, addr):
        return addr in self.normalized_coverage and addr not in self.ignored_blocks


    # Загрузка файла покрытия

    def load_coverage_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open drcov File", "",
            "drcov Files (*.log *.drcov);;All Files (*)"
        )
        if not file_path:
            return
        try:
            modules, bbs = drcov.load(file_path)
        except drcov.DRCovVersionMisMatch:
            QMessageBox.warning(self, "Unsupported",
                "Only drcov v3 supported. Use DynamoRIO 10.x to generate traces.")
            return
        except Exception as e:
            QMessageBox.critical(self, "Error", f"{e}\n\n{traceback.format_exc()}")
            return
        self._apply_coverage(modules, bbs)

    def _apply_coverage(self, modules, bbs):
        try:
            self.normalized_coverage.clear()
            self.modules.clear()
            self._func_blocks_cache.clear()
            self.ignored_blocks.clear()
            self._highlighted_addrs.clear()

            self.pe_base = self.get_image_base()
            self._log(f"Cutter image base: 0x{self.pe_base:x}")

            # Найти основной .exe модуль
            main_module = None
            for mod in modules:
                if mod.get('name', '').lower().endswith('.exe'):
                    main_module = mod
                    self.drcov_base = mod.get('start', 0)
                    self._log(f"Main module: {mod['name']} @ 0x{self.drcov_base:x}")
                    break

            if not main_module:
                self._log("Warning: no .exe module found, using first module", "warn")
                if modules:
                    main_module = modules[0]
                    self.drcov_base = main_module.get('start', 0)
                else:
                    self._log("No modules in coverage file", "error")
                    return

            main_name = main_module.get('name', '')

            # Нормализуем адреса основного модуля
            for i, (mod, bb_dict) in enumerate(zip(modules, bbs)):
                base = mod.get('start', 0)
                name = mod.get('name', f'mod_{i}')
                self.modules[i] = {'name': name, 'base': base}

                if name == main_name:
                    for offset in bb_dict:
                        abs_addr = base + offset
                        rva = abs_addr - self.drcov_base
                        norm_addr = self.pe_base + rva
                        self.normalized_coverage[norm_addr] = True

            if not self.normalized_coverage:
                self._log("No covered blocks in main module", "warn")
                self.status_label.setText("No covered blocks found")
                return

            # Проверка совместимости
            if not self._check_compatibility():
                answer = QMessageBox.question(
                    self, "Compatibility Warning",
                    "Coverage addresses don't match the loaded binary.\n"
                    "The .drcov file may be from a different version of the executable.\n\n"
                    "Load anyway?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if answer == QMessageBox.No:
                    self._log("Load cancelled: compatibility check failed", "warn")
                    return
                self._log("Proceeding despite compatibility mismatch", "warn")

            self._log(f"Loaded {len(self.normalized_coverage)} covered blocks", "ok")

            self._color_cfg_blocks()
            self._populate_function_coverage()
            self.clear_btn.setEnabled(True)
            self.highlight_btn.setEnabled(True)
            self.reset_highlight_btn.setEnabled(True)
            self.status_label.setText(f"✓ {len(self.normalized_coverage)} covered blocks loaded")

        except Exception as e:
            QMessageBox.critical(self, "Error",
                f"Failed to apply coverage: {e}\n\n{traceback.format_exc()}")


    # Проверка совместимости файла покрытия с бинарником в Cutter

    def _check_compatibility(self):
        sample = list(self.normalized_coverage.keys())[:20]
        if not sample:
            return True
        try:
            sections = cutter.cmdj("iSj") or []
            exec_sections = [s for s in sections if 'x' in s.get('perm', '')]
            if exec_sections:
                hits = 0
                for addr in sample:
                    for s in exec_sections:
                        s_start = s.get('vaddr', 0)
                        s_size = s.get('vsize', s.get('size', 0))
                        if s_start <= addr < s_start + s_size:
                            hits += 1
                            break
                return hits >= 3
            # Нет исполняемых секций — проверяем по диапазону функций
            funcs = cutter.cmdj("aflj") or []
            if not funcs:
                return True
            addrs = [f.get('offset', 0) for f in funcs if f.get('offset', 0)]
            if not addrs:
                return True
            lo, hi = min(addrs), max(addrs)
            hits = sum(1 for a in sample if lo <= a <= hi + 0x10000)
            return hits >= 3
        except Exception:
            return True  # не блокируем при ошибке API


    # Раскраска CFG блоков

    def _color_cfg_blocks(self):
        try:
            hl = cutter.core().getBBHighlighter()
            self._hl_clear(hl)
            functions = cutter.cmdj("aflj") or []
            for func in functions:
                func_addr = func.get('offset', 0)
                blocks = cutter.cmdj(f"afbj @ {func_addr}") or []
                for block in blocks:
                    addr = block.get('addr', 0)
                    if not addr:
                        continue
                    color = QColor("green") if addr in self.normalized_coverage else QColor("red")
                    hl.highlight(addr, color)
                    self._highlighted_addrs.add(addr)
        except Exception as e:
            self._log(f"CFG coloring failed: {e}", "warn")


    # Таблица функций

    def _populate_function_coverage(self):
        self.func_table.setSortingEnabled(False)
        self.func_table.setRowCount(0)
        self._func_blocks_cache.clear()

        try:
            functions = cutter.cmdj("aflj") or []
            self._log(f"Analysing {len(functions)} functions...")

            covered_funcs = 0
            for func in functions:
                func_addr = func.get('offset', 0)
                func_name = func.get('name', f'fcn.{func_addr:x}')
                blocks = cutter.cmdj(f"afbj @ {func_addr}") or []
                if not blocks:
                    continue

                self._func_blocks_cache[func_addr] = blocks
                total, covered = self._calc_coverage(blocks)
                pct = covered / total * 100 if total > 0 else 0.0
                if covered > 0:
                    covered_funcs += 1

                row = self.func_table.rowCount()
                self.func_table.insertRow(row)

                name_item = QTableWidgetItem(func_name)
                name_item.setData(Qt.UserRole, func_addr)

                ratio_item = QTableWidgetItem(f"{covered} / {total}")
                ratio_item.setData(Qt.UserRole, func_addr)

                pct_item = NumericTableItem(f"{pct:.1f}%")
                if pct >= 100:
                    pct_item.setForeground(QColor(0, 180, 0))
                elif pct > 0:
                    pct_item.setForeground(QColor(200, 160, 0))
                else:
                    pct_item.setForeground(QColor(200, 0, 0))

                self.func_table.setItem(row, 0, name_item)
                self.func_table.setItem(row, 1, ratio_item)
                self.func_table.setItem(row, 2, pct_item)

            self.func_table.setSortingEnabled(True)
            self._log(f"Done: {covered_funcs}/{len(functions)} functions with coverage", "ok")

        except Exception as e:
            self._log(f"Function table error: {e}", "error")
            self._log(traceback.format_exc(), "error")

    def _calc_coverage(self, blocks):
        """Подсчёт покрытия с учётом ignored_blocks"""
        total = covered = 0
        for block in blocks:
            addr = block.get('addr', 0)
            if addr in self.ignored_blocks:
                continue
            total += 1
            if addr in self.normalized_coverage:
                covered += 1
        return total, covered

    def _refresh_function_coverage(self):
        """Пересчитать проценты без полного перестроения таблицы"""
        self.func_table.setSortingEnabled(False)
        for row in range(self.func_table.rowCount()):
            name_item = self.func_table.item(row, 0)
            if not name_item:
                continue
            func_addr = name_item.data(Qt.UserRole)
            blocks = self._func_blocks_cache.get(func_addr, [])
            total, covered = self._calc_coverage(blocks)
            pct = covered / total * 100 if total > 0 else 0.0

            ratio_item = self.func_table.item(row, 1)
            if ratio_item:
                ratio_item.setText(f"{covered} / {total}")

            pct_item = NumericTableItem(f"{pct:.1f}%")
            if pct >= 100:
                pct_item.setForeground(QColor(0, 180, 0))
            elif pct > 0:
                pct_item.setForeground(QColor(200, 160, 0))
            else:
                pct_item.setForeground(QColor(200, 0, 0))
            self.func_table.setItem(row, 2, pct_item)

        self.func_table.setSortingEnabled(True)


    # Фильтр "Скрыть 100% покрытых"

    def _apply_hide_100(self):
        hide = self.hide_100_cb.isChecked()
        for row in range(self.func_table.rowCount()):
            pct_item = self.func_table.item(row, 2)
            if pct_item:
                try:
                    val = float(pct_item.text().rstrip('%'))
                except ValueError:
                    val = 0.0
                self.func_table.setRowHidden(row, hide and val >= 100.0)


    # Выбор функции

    def _on_func_selected(self):
        row = self.func_table.currentRow()
        if row < 0:
            return
        name_item = self.func_table.item(row, 0)
        if not name_item:
            return
        func_addr = name_item.data(Qt.UserRole)
        func_name = name_item.text()
        self._populate_bb_table(func_addr, func_name)

    def _on_func_double_clicked(self, item):
        """Двойной клик — переход к функции в дизассемблере (фича 2)"""
        row = item.row()
        name_item = self.func_table.item(row, 0)
        if not name_item:
            return
        func_addr = name_item.data(Qt.UserRole)
        try:
            cutter.core().seekAndShow(func_addr)
        except Exception:
            try:
                cutter.cmd(f"s {func_addr}")
            except Exception as e:
                self._log(f"Jump to 0x{func_addr:x} failed: {e}", "error")


    # Таблица базовых блоков + подсветка

    def _populate_bb_table(self, func_addr, func_name):
        self.bb_label.setText(f"Basic Blocks: {func_name}")
        self.bb_table.setSortingEnabled(False)
        self.bb_table.setRowCount(0)

        blocks = self._func_blocks_cache.get(func_addr)
        if blocks is None:
            blocks = cutter.cmdj(f"afbj @ {func_addr}") or []
            self._func_blocks_cache[func_addr] = blocks

        for block in blocks:
            addr = block.get('addr', 0)
            if not addr:
                continue

            covered = addr in self.normalized_coverage
            ignored = addr in self.ignored_blocks
            first_instr = self._get_first_instr(addr)

            row = self.bb_table.rowCount()
            self.bb_table.insertRow(row)

            addr_item = HexTableItem(f"0x{addr:x}")
            addr_item.setData(Qt.UserRole, addr)

            instr_item = QTableWidgetItem(first_instr)

            cov_item = QTableWidgetItem("Yes" if covered else "No")

            ignore_item = QTableWidgetItem("✓" if ignored else "")
            ignore_item.setData(Qt.UserRole, addr)
            ignore_item.setTextAlignment(Qt.AlignCenter)

            # Раскраска строки
            if ignored:
                bg = QColor(55, 55, 55)
                fg = QColor(120, 120, 120)
            elif covered:
                bg = QColor(0, 70, 0)
                fg = QColor(180, 255, 180)
            else:
                bg = QColor(70, 0, 0)
                fg = QColor(255, 180, 180)

            for cell in [addr_item, instr_item, cov_item, ignore_item]:
                cell.setBackground(bg)
                cell.setForeground(fg)

            self.bb_table.setItem(row, 0, addr_item)
            self.bb_table.setItem(row, 1, instr_item)
            self.bb_table.setItem(row, 2, cov_item)
            self.bb_table.setItem(row, 3, ignore_item)

        self.bb_table.setSortingEnabled(True)

    def _get_first_instr(self, addr):
        try:
            result = cutter.cmdj(f"pdj 1 @ {addr}")
            if result:
                return result[0].get('opcode', '???')
        except Exception:
            pass
        return '???'


    # Игнорирование блоков

    def _ignore_selected_blocks(self):
        selected_rows = set(idx.row() for idx in self.bb_table.selectedIndexes())
        if not selected_rows:
            return
        for row in selected_rows:
            item = self.bb_table.item(row, 3)
            if item:
                addr = item.data(Qt.UserRole)
                if addr:
                    self.ignored_blocks.add(addr)
        self._log(f"Ignored {len(selected_rows)} block(s). Total ignored: {len(self.ignored_blocks)}", "warn")
        self._after_ignore_change()

    def _unignore_all_blocks(self):
        self.ignored_blocks.clear()
        self.ignore_single_cb.blockSignals(True)
        self.ignore_single_cb.setChecked(False)
        self.ignore_single_cb.blockSignals(False)
        self._log("All blocks unignored", "ok")
        self._after_ignore_change()

    def _on_ignore_single_changed(self):
        if self.ignore_single_cb.isChecked():
            count = 0
            for blocks in self._func_blocks_cache.values():
                for block in blocks:
                    if block.get('ninstr', 0) == 1:
                        addr = block.get('addr', 0)
                        if addr:
                            self.ignored_blocks.add(addr)
                            count += 1
            self._log(f"Auto-ignored {count} single-instruction blocks", "warn")
        else:
            to_remove = set()
            for blocks in self._func_blocks_cache.values():
                for block in blocks:
                    if block.get('ninstr', 0) == 1:
                        addr = block.get('addr', 0)
                        if addr:
                            to_remove.add(addr)
            self.ignored_blocks -= to_remove
            self._log(f"Unignored {len(to_remove)} single-instruction blocks", "ok")
        self._after_ignore_change()

    def _after_ignore_change(self):
        row = self.func_table.currentRow()
        name_item = self.func_table.item(row, 0) if row >= 0 else None
        if name_item:
            self._populate_bb_table(name_item.data(Qt.UserRole), name_item.text())
        self._refresh_function_coverage()


    # callback

    def _on_seek_changed(self):
        try:
            addr = cutter.core().getOffset()
            if not self.normalized_coverage:
                return
            if self.is_address_covered(addr):
                self.status_label.setText(f"✓ 0x{addr:x} — covered")
            else:
                self.status_label.setText(f"○ 0x{addr:x} — not covered")
        except Exception:
            pass

    # Подсветка текущей функции в графе

    def _highlight_current_function(self):
        """Красит блоки выбранной функции в CFG через getBBHighlighter"""
        func_addr = None
        row = self.func_table.currentRow()
        if row >= 0:
            name_item = self.func_table.item(row, 0)
            if name_item:
                func_addr = name_item.data(Qt.UserRole)

        if func_addr is None:
            try:
                func_addr = cutter.core().getOffset()
            except Exception:
                self._log("Не удалось определить текущую функцию", "error")
                return

        try:
            blocks = self._func_blocks_cache.get(func_addr)
            if blocks is None:
                blocks = cutter.cmdj(f"afbj @ {func_addr}") or []
                self._func_blocks_cache[func_addr] = blocks

            if not blocks:
                self._log(f"Нет блоков для 0x{func_addr:x}", "warn")
                return

            hl = cutter.core().getBBHighlighter()
            colored = 0
            for block in blocks:
                addr = block.get('addr', 0)
                if not addr:
                    continue
                color = QColor("green") if addr in self.normalized_coverage else QColor("red")
                hl.highlight(addr, color)
                self._highlighted_addrs.add(addr)
                colored += 1

            self._log(f"Подсвечено {colored} блоков функции 0x{func_addr:x}", "ok")

        except Exception as e:
            self._log(f"Ошибка подсветки: {e}", "error")

    def _reset_graph_highlight(self):
        """Сбрасывает все цвета блоков в CFG"""
        try:
            hl = cutter.core().getBBHighlighter()
            self._hl_clear(hl)
            self._log("Подсветка графа сброшена", "ok")
        except Exception as e:
            self._log(f"Ошибка сброса: {e}", "error")

    def _hl_clear(self, hl):
        """clear(addr) для каждого подсвеченного блока — clear() без аргументов не существует"""
        for addr in self._highlighted_addrs:
            hl.clear(addr)
        self._highlighted_addrs.clear()


    # Очистка

    def clear_coverage(self):
        self.normalized_coverage.clear()
        self.modules.clear()
        self.ignored_blocks.clear()
        self._func_blocks_cache.clear()
        self.func_table.setRowCount(0)
        self.bb_table.setRowCount(0)
        self.bb_label.setText("Basic Blocks")
        self.log_text.clear()
        self.clear_btn.setEnabled(False)
        self.highlight_btn.setEnabled(False)
        self.reset_highlight_btn.setEnabled(False)
        self.status_label.setText("No coverage data loaded")
        self.hide_100_cb.setChecked(False)
        self.ignore_single_cb.setChecked(False)
        try:
            self._hl_clear(cutter.core().getBBHighlighter())
        except Exception:
            pass
        self._highlighted_addrs.clear()


class DRCovPlugin(cutter.CutterPlugin):
    name = "DynamoRIO Coverage"
    description = "Visualize DynamoRIO code coverage in Cutter"
    version = "2.0"
    author = "CutterDRcov"

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        action = QAction("DRCov Plugin", main)
        action.setCheckable(True)
        widget = DRCovWidget(main, action)
        main.addPluginDockWidget(widget, action)

    def terminate(self):
        pass


def create_cutter_plugin():
    return DRCovPlugin()
