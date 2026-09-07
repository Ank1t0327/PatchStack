import json
import os
from abc import ABC, abstractmethod
from patchstack.scanner.engine import ScanResult


class BaseReportExporter(ABC):
    """
    Abstract report exporter interface.
    """

    @abstractmethod
    def export(self, scan_result: ScanResult, output_path: str) -> str:
        pass


class JSONReportExporter(BaseReportExporter):
    """
    Exports scan results to a formatted JSON document.
    """

    def export(self, scan_result: ScanResult, output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        data = scan_result.to_dict()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return output_path
