from PySide6.QtWidgets import QTableWidgetItem
from PySide6.QtCore import Qt, QRect, QSize, QPoint
from PySide6.QtWidgets import QLayout


class NumericTableItem(QTableWidgetItem):
    """QTableWidgetItem с числовой сортировкой (для % покрытия)."""

    def __lt__(self, other):
        try:
            return float(self.text().rstrip('%')) < float(other.text().rstrip('%'))
        except (ValueError, AttributeError):
            return super().__lt__(other)


class HexTableItem(QTableWidgetItem):
    """QTableWidgetItem с сортировкой по шестнадцатеричному значению адреса."""

    def __lt__(self, other):
        try:
            return int(self.text(), 16) < int(other.text(), 16)
        except (ValueError, AttributeError):
            return super().__lt__(other)


class FlowLayout(QLayout):
    """Раскладка с переносом элементов на новую строку при нехватке ширины.

    Минимальная ширина = ширина самого широкого элемента (а не сумма всех),
    поэтому панель кнопок может свободно сжиматься.
    """

    def __init__(self, parent=None, margin=0, spacing=4):
        super().__init__(parent)
        self.setContentsMargins(margin, margin, margin, margin)
        self.setSpacing(spacing)
        self._items = []

    def __del__(self):
        while self.count():
            self.takeAt(0)

    def addItem(self, item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        if 0 <= index < len(self._items):
            return self._items[index]
        return None

    def takeAt(self, index):
        if 0 <= index < len(self._items):
            return self._items.pop(index)
        return None

    def expandingDirections(self):
        return Qt.Orientations(Qt.Orientation(0))

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._do_layout(QRect(0, 0, width, 0), test_only=True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._do_layout(rect, test_only=False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        m = self.contentsMargins()
        size += QSize(m.left() + m.right(), m.top() + m.bottom())
        return size

    def _do_layout(self, rect, test_only):
        m = self.contentsMargins()
        eff = rect.adjusted(m.left(), m.top(), -m.right(), -m.bottom())
        x, y = eff.x(), eff.y()
        line_height = 0
        spacing = self.spacing()

        for item in self._items:
            w = item.sizeHint().width()
            h = item.sizeHint().height()
            next_x = x + w + spacing
            if next_x - spacing > eff.right() and line_height > 0:
                x = eff.x()
                y = y + line_height + spacing
                next_x = x + w + spacing
                line_height = 0
            if not test_only:
                item.setGeometry(QRect(QPoint(x, y), item.sizeHint()))
            x = next_x
            line_height = max(line_height, h)

        return y + line_height - rect.y() + m.bottom()
