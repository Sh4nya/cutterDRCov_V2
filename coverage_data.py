# Агрегатор данных покрытия из нескольких drcov-файлов.

from __future__ import annotations
import os


class CoverageData:
    """Хранит объединённое покрытие из нескольких drcov-файлов.

    Атрибуты:
        files       — список путей к загруженным файлам
        hits        — {norm_addr: hit_count}: сколько файлов покрыло данный блок
        file_hits   — {norm_addr: [filename, ...]}: имена файлов, покрывших блок
        pe_base     — предпочтительный базовый адрес PE (из Cutter)
        drcov_base  — базовый адрес основного модуля из первого drcov-файла
    """

    def __init__(self):
        self.files: list[str] = []
        self.hits: dict[int, int] = {}
        self.file_hits: dict[int, list[str]] = {}   # {norm_addr: [basename, ...]}
        self.pe_base: int = 0
        self.drcov_base: int = 0
        self._main_module_name: str = ""

    # Свойства

    @property
    def total_files(self) -> int:
        # Количество загруженных файлов.
        return len(self.files)

    @property
    def total_covered(self) -> int:
        # Количество уникальных покрытых блоков.
        return len(self.hits)

    # Запросы к данным

    def is_covered(self, addr: int) -> bool:
        # Возвращает True, если адрес покрыт хотя бы одним файлом.
        return addr in self.hits

    def hit_count(self, addr: int) -> int:
        # Количество файлов, покрывших данный блок.
        return self.hits.get(addr, 0)

    def hit_pct(self, addr: int) -> float:
        # Процент фаззинг-запусков, в которых данный блок был покрыт.
        if not self.files or addr not in self.hits:
            return 0.0
        return self.hits[addr] / len(self.files) * 100.0

    def files_for_block(self, addr: int) -> list[str]:
        """Имена файлов (basename), в которых данный блок был покрыт."""
        return self.file_hits.get(addr, [])

    # Изменение состояния

    def clear(self):
        # Сбросить все данные покрытия.
        self.files.clear()
        self.hits.clear()
        self.file_hits.clear()
        self.pe_base = 0
        self.drcov_base = 0
        self._main_module_name = ""

    def add_file(
        self,
        path: str,
        modules: list[dict],
        bbs: list[dict],
        pe_base: int,
    ) -> tuple[int, str]:
        """Добавить данные из одного drcov-файла в агрегатор.

        Для каждого базового блока основного .exe модуля вычисляется
        нормализованный адрес по формуле:
            rva = abs_runtime_addr - drcov_base
            norm_addr = pe_base + rva

        Это компенсирует ASLR: drcov_base — адрес загрузки при фаззинге,
        pe_base — предпочтительный адрес PE в Cutter.

        Возвращает:
            (количество_новых_блоков, имя_главного_модуля)
        """
        self.pe_base = pe_base
        basename = os.path.basename(path)

        # Найти главный .exe модуль (или первый из списка)
        main_module: dict | None = None
        drcov_base = 0
        main_name = ""
        for mod in modules:
            name = mod.get("name", "")
            if name.lower().endswith(".exe"):
                main_module = mod
                drcov_base = mod.get("start", 0)
                main_name = name
                break
        if main_module is None and modules:
            main_module = modules[0]
            drcov_base = main_module.get("start", 0)
            main_name = main_module.get("name", "")

        if main_module is None:
            return 0, ""

        # При первом файле запоминаем базу модуля и его имя
        if not self.files:
            self.drcov_base = drcov_base
            self._main_module_name = main_name

        # Нормализуем адреса и обновляем счётчики попаданий
        new_blocks = 0
        for mod, bb_dict in zip(modules, bbs):
            if mod.get("name", "") != main_name:
                continue
            base = mod.get("start", 0)
            for offset in bb_dict:
                abs_addr = base + offset
                rva = abs_addr - drcov_base
                norm_addr = pe_base + rva
                if norm_addr not in self.hits:
                    new_blocks += 1
                    self.file_hits[norm_addr] = []
                self.hits[norm_addr] = self.hits.get(norm_addr, 0) + 1
                self.file_hits[norm_addr].append(basename)

        self.files.append(path)
        return new_blocks, main_name
