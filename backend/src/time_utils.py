import numbers

import numpy as np
import pandas as pd


def _timestamp_unit(values: pd.Series) -> str:
    numeric_values = pd.to_numeric(values, errors="coerce").dropna().abs()
    if numeric_values.empty:
        return "s"

    magnitude = float(numeric_values.median())
    if magnitude >= 1e17:
        return "ns"
    if magnitude >= 1e14:
        return "us"
    if magnitude >= 1e11:
        return "ms"
    return "s"


def parse_timestamp_series(values: pd.Series) -> pd.Series:
    if pd.api.types.is_numeric_dtype(values):
        return pd.to_datetime(
            values,
            unit=_timestamp_unit(values),
            errors="coerce",
            utc=True,
        )
    return pd.to_datetime(values, errors="coerce", utc=True)


def normalize_timestamp(value: object) -> pd.Timestamp:
    if isinstance(value, numbers.Real) and not pd.isna(value):
        numeric_value = float(value)
        unit = _timestamp_unit(pd.Series([numeric_value], dtype=np.float64))
        return pd.to_datetime(numeric_value, unit=unit, errors="coerce", utc=True)
    return pd.to_datetime(value, errors="coerce", utc=True)
