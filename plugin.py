import traceback
import cutter
from . import drcov
from .coverage_data import CoverageData
from .ui_items import NumericTableItem, HexTableItem, FlowLayout
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QLabel, QFileDialog, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QCheckBox, QAbstractItemView,
    QApplication, QMenu, QSizePolicy,
)
from PySide6.QtGui import QAction, QColor


class DRCovWidget(cutter.CutterDockWidget):
    def __init__(self, parent, action):
        super().__init__(parent, action)
        self.setObjectName("DRCovWidget")
        self.setWindowTitle("DynamoRIO Coverage")

        self.coverage = CoverageData()
        self.ignored_blocks: set[int] = set()
        self._func_blocks_cache: dict[int, list] = {}
        self._highlighted_addrs: set[int] = set()
        self._narrow_mode = False   # текущий режим раскладки (True = узкий)

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

        # Верхняя панель кнопок
        top_bar = FlowLayout(spacing=4)
        self.load_btn = QPushButton("Load Coverage File(s)")
        self.load_btn.clicked.connect(self.load_coverage_files)
        self.status_label = QLabel("No coverage data loaded")
        self.status_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.status_label.setMinimumWidth(0)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_coverage)
        self.clear_btn.setEnabled(False)
        self.highlight_btn = QPushButton("Highlight Coverage")
        self.highlight_btn.clicked.connect(self._highlight_current_function)
        self.highlight_btn.setEnabled(False)
        self.reset_highlight_btn = QPushButton("Reset Highlight")
        self.reset_highlight_btn.clicked.connect(self._reset_graph_highlight)
        self.reset_highlight_btn.setEnabled(False)
        top_bar.addWidget(self.load_btn)
        top_bar.addWidget(self.status_label)
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

        # Левая панель — функции (сохраняем ссылку для адаптивной раскладки)
        self.left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 2, 0)

        func_header = FlowLayout(spacing=4)
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
        self.func_table.setMinimumWidth(0)
        left_layout.addWidget(self.func_table)
        self.left_panel.setLayout(left_layout)

        # Правая панель — базовые блоки
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(2, 0, 0, 0)

        bb_header = FlowLayout(spacing=4)
        self.bb_label = QLabel("Basic Blocks")
        bb_header.addWidget(self.bb_label)
        self.ignore_single_cb = QCheckBox("Ignore single-instr blocks")
        self.ignore_single_cb.stateChanged.connect(self._on_ignore_single_changed)
        bb_header.addWidget(self.ignore_single_cb)
        right_layout.addLayout(bb_header)

        self.bb_table = QTableWidget(0, 4)
        self.bb_table.setHorizontalHeaderLabels(["Address", "Using Files", "Hits", "Ignore"])
        self.bb_table.setSortingEnabled(True)
        self.bb_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.bb_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.bb_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.bb_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.bb_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.bb_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.bb_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.bb_table.customContextMenuRequested.connect(self._bb_context_menu)
        self.bb_table.setMinimumWidth(0)
        right_layout.addWidget(self.bb_table)

        bb_btns = FlowLayout(spacing=4)
        self.ignore_sel_btn = QPushButton("Ignore Selected")
        self.ignore_sel_btn.clicked.connect(self._ignore_selected_blocks)
        self.unignore_all_btn = QPushButton("Unignore All")
        self.unignore_all_btn.clicked.connect(self._unignore_all_blocks)
        bb_btns.addWidget(self.ignore_sel_btn)
        bb_btns.addWidget(self.unignore_all_btn)
        right_layout.addLayout(bb_btns)
        right_panel.setLayout(right_layout)

        top_splitter = QSplitter(Qt.Horizontal)
        top_splitter.addWidget(self.left_panel)
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

        # Масштабируемость: разрешаем доку становиться узким
        self.setMinimumWidth(120)
        root.setMinimumWidth(0)

    # Адаптивная раскладка

    def resizeEvent(self, event):
        """Скрывать панель Functions при ширине < 400 px."""
        super().resizeEvent(event)
        is_narrow = event.size().width() < 400
        if is_narrow != self._narrow_mode:
            self._narrow_mode = is_narrow
            self.left_panel.setVisible(not is_narrow)

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

    def get_image_base(self) -> int:
        try:
            info = cutter.cmdj("ij")
            if info and 'bin' in info:
                baddr = info['bin'].get('baddr', 0)
                if baddr:
                    return baddr
        except Exception:
            pass
        return 0x140000000

    def is_address_covered(self, addr: int) -> bool:
        return self.coverage.is_covered(addr) and addr not in self.ignored_blocks

    # Загрузка файлов покрытия

    def load_coverage_files(self):
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, "Open drcov File(s)", "",
            "drcov Files (*.log *.drcov);;All Files (*)"
        )
        if not file_paths:
            return
        self._apply_coverage_from_files(file_paths)

    def _apply_coverage_from_files(self, file_paths: list[str]):
        """Загрузить несколько drcov-файлов и объединить покрытие."""
        self.coverage.clear()
        self._func_blocks_cache.clear()
        self.ignored_blocks.clear()
        self._highlighted_addrs.clear()
        try:
            self._hl_clear(cutter.core().getBBHighlighter())
        except Exception:
            pass

        pe_base = self.get_image_base()
        self._log(f"Cutter image base: 0x{pe_base:x}")

        load_errors: list[str] = []
        for path in file_paths:
            try:
                modules, bbs = drcov.load(path)
            except drcov.DRCovVersionMisMatch:
                load_errors.append(f"{path}: только drcov v3 поддерживается (используйте DynamoRIO 10.x)")
                continue
            except Exception as e:
                load_errors.append(f"{path}: {e}")
                continue
            new_blocks, main_name = self.coverage.add_file(path, modules, bbs, pe_base)
            self._log(
                f"[{self.coverage.total_files}/{len(file_paths)}] {path}: "
                "ok"
            )

        if load_errors:
            QMessageBox.warning(self, "Ошибки загрузки", "\n".join(load_errors))

        if not self.coverage.total_covered:
            self._log("Покрытых блоков не найдено", "warn")
            self.status_label.setText("No covered blocks found")
            return

        if not self._check_compatibility():
            answer = QMessageBox.question(
                self, "Предупреждение совместимости",
                "Адреса покрытия не совпадают с загруженным бинарником.\n"
                "Возможно, файл .drcov получен для другой версии программы.\n\n"
                "Продолжить загрузку?",
                QMessageBox.Yes | QMessageBox.No
            )
            if answer == QMessageBox.No:
                self.coverage.clear()
                self._log("Загрузка отменена: несовместимость адресов", "warn")
                return
            self._log("Продолжаем несмотря на несовместимость адресов", "warn")

        total_f = self.coverage.total_files
        total_b = self.coverage.total_covered
        self._log(f"Итого: {total_f} файл(а/ов), {total_b} покрытых блоков", "ok")

        self._color_cfg_blocks()
        self._populate_function_coverage()
        self.clear_btn.setEnabled(True)
        self.highlight_btn.setEnabled(True)
        self.reset_highlight_btn.setEnabled(True)
        self.status_label.setText(
            f"✓ {total_f} файл(а/ов)  ·  {total_b} покрытых блоков"
        )

    # Проверка совместимости

    def _check_compatibility(self) -> bool:
        sample = list(self.coverage.hits.keys())[:20]
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
            funcs = cutter.cmdj("aflj") or []
            if not funcs:
                return True
            addrs = [f.get('offset', 0) for f in funcs if f.get('offset', 0)]
            if not addrs:
                return True
            lo, hi = min(addrs), max(addrs)
            return sum(1 for a in sample if lo <= a <= hi + 0x10000) >= 3
        except Exception:
            return True

    # Цветовая карта цветов

    def _hit_color(self, addr: int) -> QColor:
        pct = self.coverage.hit_pct(addr)
        if pct == 0:
            return QColor(180, 70, 70)       # Красный (0%)
        elif pct >= 100:
            return QColor(70, 255, 70)       # Зеленый (100%)
        elif pct < 34:
            return QColor(255, 255, 190)     # Светло-желтый (1% - 33%)
        elif pct < 67:
            return QColor(255, 230, 0)       # Насыщенный желтый (34% - 66%)
        else:
            return QColor(255, 170, 0)       # Темно-желтый / золотистый (67% - 99%)

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
                    color = self._hit_color(addr)
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
            self._log(f"Анализируем {len(functions)} функций...")

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
            self._log(f"Готово: {covered_funcs}/{len(functions)} функций с покрытием", "ok")

        except Exception as e:
            self._log(f"Function table error: {e}", "error")
            self._log(traceback.format_exc(), "error")

    def _calc_coverage(self, blocks: list[dict]) -> tuple[int, int]:
        # Подсчёт покрытых/всего блоков с учётом ignored_blocks.
        total = covered = 0
        for block in blocks:
            addr = block.get('addr', 0)
            if addr in self.ignored_blocks:
                continue
            total += 1
            if self.coverage.is_covered(addr):
                covered += 1
        return total, covered

    def _refresh_function_coverage(self):
        # Пересчитать проценты без полного перестроения таблицы.
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

    # Выбор функции => таблица базовых блоков

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
        # Двойной клик — переход к функции в дизассемблере.
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

    # Таблица базовых блоков с тепловой картой

    def _populate_bb_table(self, func_addr: int, func_name: str):
        self.bb_label.setText(f"Basic Blocks: {func_name}")
        self.bb_table.setSortingEnabled(False)
        self.bb_table.setRowCount(0)

        blocks = self._func_blocks_cache.get(func_addr)
        if blocks is None:
            blocks = cutter.cmdj(f"afbj @ {func_addr}") or []
            self._func_blocks_cache[func_addr] = blocks

        total_files = self.coverage.total_files

        for block in blocks:
            addr = block.get('addr', 0)
            if not addr:
                continue

            ignored = addr in self.ignored_blocks
            hit_count = self.coverage.hit_count(addr)
            hit_pct = self.coverage.hit_pct(addr)
            file_list = self.coverage.files_for_block(addr)

            row = self.bb_table.rowCount()
            self.bb_table.insertRow(row)

            addr_item = HexTableItem(f"0x{addr:x}")
            addr_item.setData(Qt.UserRole, addr)

            # Столбец "Using Files" — имена файлов, покрывших блок
            files_item = QTableWidgetItem(", ".join(file_list))
            if file_list:
                files_item.setToolTip("\n".join(file_list))

            hits_text = f"{hit_count}/{total_files}" if hit_count > 0 else "0"
            hits_item = NumericTableItem(hits_text)

            ignore_item = QTableWidgetItem("✓" if ignored else "")
            ignore_item.setData(Qt.UserRole, addr)
            ignore_item.setTextAlignment(Qt.AlignCenter)

            if ignored:
                bg = QColor(55, 55, 55)
                fg = QColor(120, 120, 120)
            elif hit_count == 0:
                bg = QColor(70, 20, 20)            # Темно-красный фон
                fg = QColor(210, 100, 100)         # Светло-красный текст (0%)
            elif hit_pct < 34:
                bg = QColor(60, 60, 15)            # Темно-желтый фон
                fg = QColor(255, 255, 190)         # Светло-желтый текст (1% - 33%)
            elif hit_pct < 67:
                bg = QColor(70, 65, 0)             # Темно-насыщенный желтый фон
                fg = QColor(255, 230, 0)           # Насыщенный желтый текст (34% - 66%)
            elif hit_pct < 100:
                bg = QColor(80, 50, 0)             # Темно-золотистый/оранжевый фон
                fg = QColor(255, 170, 0)           # Золотистый текст (67% - 99%)
            else:
                bg = QColor(0, 60, 0)              # Темно-зеленый фон
                fg = QColor(120, 255, 120)         # Светло-зеленый текст (100%)
                
                
            for cell in [addr_item, files_item, hits_item, ignore_item]:
                cell.setBackground(bg)
                cell.setForeground(fg)

            self.bb_table.setItem(row, 0, addr_item)
            self.bb_table.setItem(row, 1, files_item)
            self.bb_table.setItem(row, 2, hits_item)
            self.bb_table.setItem(row, 3, ignore_item)

        self.bb_table.setSortingEnabled(True)

    # Контекстное меню таблицы блоков — копировать адрес

    def _bb_context_menu(self, pos):
        row = self.bb_table.rowAt(pos.y())
        if row < 0:
            return
        addr_item = self.bb_table.item(row, 0)
        if not addr_item:
            return
        addr = addr_item.data(Qt.UserRole)
        if not addr:
            return

        menu = QMenu(self)
        copy_action = menu.addAction(f"Copy Address  (0x{addr:x})")
        action = menu.exec(self.bb_table.viewport().mapToGlobal(pos))
        if action == copy_action:
            QApplication.clipboard().setText(f"0x{addr:x}")
            self._log(f"Адрес 0x{addr:x} скопирован в буфер обмена", "ok")

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
        self._log(
            f"Игнорировано {len(selected_rows)} блок(а/ов). "
            f"Всего: {len(self.ignored_blocks)}",
            "warn"
        )
        self._after_ignore_change()

    def _unignore_all_blocks(self):
        self.ignored_blocks.clear()
        self.ignore_single_cb.blockSignals(True)
        self.ignore_single_cb.setChecked(False)
        self.ignore_single_cb.blockSignals(False)
        self._log("Все блоки разигнорированы", "ok")
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
            self._log(f"Авто-игнор: {count} однострочных блоков", "warn")
        else:
            to_remove = set()
            for blocks in self._func_blocks_cache.values():
                for block in blocks:
                    if block.get('ninstr', 0) == 1:
                        addr = block.get('addr', 0)
                        if addr:
                            to_remove.add(addr)
            self.ignored_blocks -= to_remove
            self._log(f"Разигнорировано {len(to_remove)} однострочных блоков", "ok")
        self._after_ignore_change()

    def _after_ignore_change(self):
        row = self.func_table.currentRow()
        name_item = self.func_table.item(row, 0) if row >= 0 else None
        if name_item:
            self._populate_bb_table(name_item.data(Qt.UserRole), name_item.text())
        self._refresh_function_coverage()

    # Seek callback

    def _on_seek_changed(self):
        try:
            addr = cutter.core().getOffset()
            if not self.coverage.total_covered:
                return
            if self.is_address_covered(addr):
                hits = self.coverage.hit_count(addr)
                pct = self.coverage.hit_pct(addr)
                self.status_label.setText(
                    f"✓ 0x{addr:x} — покрыт ({hits}/{self.coverage.total_files} файлов, {pct:.0f}%)"
                )
            else:
                self.status_label.setText(f"○ 0x{addr:x} — не покрыт")
        except Exception:
            pass

    # Подсветка функции в графе

    def _highlight_current_function(self):
        # Красит блоки выбранной функции в CFG через getBBHighlighter.
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
                color = self._hit_color(addr)
                hl.highlight(addr, color)
                self._highlighted_addrs.add(addr)
                colored += 1

            self._log(f"Подсвечено {colored} блоков функции 0x{func_addr:x}", "ok")

            # Переход к функции — граф откроется с уже применёнными цветами
            cutter.core().seekAndShow(func_addr)

        except Exception as e:
            self._log(f"Ошибка подсветки: {e}", "error")

    def _reset_graph_highlight(self):
        # Сбрасывает все цвета блоков в CFG.
        try:
            hl = cutter.core().getBBHighlighter()
            self._hl_clear(hl)
            self._log("Подсветка графа сброшена", "ok")
        except Exception as e:
            self._log(f"Ошибка сброса: {e}", "error")

    def _hl_clear(self, hl):
        # Очистить подсветку всех отслеживаемых блоков.
        for addr in self._highlighted_addrs:
            hl.clear(addr)
        self._highlighted_addrs.clear()

    # Очистка всех данных

    def clear_coverage(self):
        self.coverage.clear()
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


class DRCovPlugin(cutter.CutterPlugin):
    name = "DynamoRIO Coverage"
    description = "Visualize DynamoRIO code coverage in Cutter V2"
    version = "2.2"
    author = "Shanya"

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
