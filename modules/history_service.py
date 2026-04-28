from typing import List, Dict
from datetime import datetime

class HistoryService:
    def __init__(self):
        self._history: List[Dict] = []

    def save(self, record: dict):
        self._history.append(record)

    def get_all(self):
        return self._history

    def get_by_id(self, index: int):
        if index < 0 or index >= len(self._history):
            return None
        return self._history[index]

    def mark_false_positive(self, index: int):
        record = self.get_by_id(index)
        if record:
            record["false_positive"] = True
            return True
        return False