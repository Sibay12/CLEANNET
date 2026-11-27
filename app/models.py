from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DeviceCreate(BaseModel):
    device_id: str = Field(min_length=4, max_length=64, pattern=r"^(?:[A-Za-z0-9_-]{4,64}|(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})$")
    hardware_model: str = Field(default="ESP32-C3-SuperMini", max_length=80)
    notes: str | None = Field(default=None, max_length=300)


class DeviceRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    device_id: str
    hardware_model: str
    status: Literal["inventory", "claimed", "blocked"]
    created_at: str
    updated_at: str
