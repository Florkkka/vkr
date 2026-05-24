from dataclasses import dataclass
from enum import Enum


class StrideCategory(str, Enum):
    SPOOFING = "S"
    TAMPERING = "T"
    REPUDIATION = "R"
    INFORMATION_DISCLOSURE = "I"
    DENIAL_OF_SERVICE = "D"
    ELEVATION_OF_PRIVILEGE = "E"

    @property
    def full_name(self):
        return {
            "S": "Spoofing (Подмена)",
            "T": "Tampering (Изменение данных)",
            "R": "Repudiation (Отрицание действий)",
            "I": "Information Disclosure (Разглашение информации)",
            "D": "Denial of Service (Отказ в обслуживании)",
            "E": "Elevation of Privilege (Повышение привилегий)",
        }[self.value]

    @property
    def description(self):
        return {
            "S": "Атаки, связанные с подменой субъекта или устройства",
            "T": "Несанкционированное изменение данных или конфигурации",
            "R": "Невозможность доказать факт совершения действия",
            "I": "Несанкционированный доступ к конфиденциальной информации",
            "D": "Блокирование доступа к ресурсам или услугам",
            "E": "Получение прав доступа выше разрешённых",
        }[self.value]


class RiskLevel(str, Enum):
    LOW = "низкий"
    MEDIUM = "средний"
    HIGH = "высокий"
    CRITICAL = "критический"


@dataclass
class RiskResult:
    probability: int
    impact: int
    score: int
    level: RiskLevel

    @property
    def color(self):
        return {
            RiskLevel.LOW: "#22c55e",
            RiskLevel.MEDIUM: "#eab308",
            RiskLevel.HIGH: "#f97316",
            RiskLevel.CRITICAL: "#ef4444",
        }[self.level]

    @property
    def color_class(self):
        return {
            RiskLevel.LOW: "risk-low",
            RiskLevel.MEDIUM: "risk-medium",
            RiskLevel.HIGH: "risk-high",
            RiskLevel.CRITICAL: "risk-critical",
        }[self.level]


POSSIBLE_VALUES = [1, 2, 3]


def calculate_risk(probability: int, impact: int) -> RiskResult:
    if probability not in POSSIBLE_VALUES:
        raise ValueError(f"Вероятность должна быть 1, 2 или 3, получено {probability}")
    if impact not in POSSIBLE_VALUES:
        raise ValueError(f"Последствия должны быть 1, 2 или 3, получено {impact}")

    score = probability * impact

    if score <= 2:
        level = RiskLevel.LOW
    elif score <= 4:
        level = RiskLevel.MEDIUM
    elif score <= 6:
        level = RiskLevel.HIGH
    else:
        level = RiskLevel.CRITICAL

    return RiskResult(
        probability=probability,
        impact=impact,
        score=score,
        level=level,
    )


def format_risk_matrix() -> list[list[RiskResult | None]]:
    rows = []
    for p in [3, 2, 1]:
        row = []
        for i in [1, 2, 3]:
            row.append(calculate_risk(p, i))
        rows.append(row)
    return rows


def score_to_display(score: int) -> str:
    mapping = {1: "1 (низкий)", 2: "2 (низкий)", 3: "3 (средний)",
               4: "4 (средний)", 6: "6 (высокий)", 9: "9 (критический)"}
    return mapping.get(score, str(score))
