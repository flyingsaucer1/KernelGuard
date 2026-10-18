"""Declarative configuration validation; settings() retains the existing dict API."""
import posixpath
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProjectSettings(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", validate_default=True)

    host_id: str = Field(default="kernelguard-lab", min_length=1, max_length=128)
    protected_path: str = Field(default="/srv/kernelguard/protected", pattern=r"^/")
    timezone: str = "Asia/Kolkata"
    allowed_start_hour: int = Field(default=9, ge=0, le=23)
    allowed_end_hour: int = Field(default=18, ge=0, le=23)
    login_threshold: int = Field(default=5, ge=2)
    login_window_seconds: int = Field(default=300, ge=1)

    @model_validator(mode="after")
    def validate_policy(self):
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("timezone must be an installed IANA timezone") from exc
        if self.allowed_start_hour == self.allowed_end_hour:
            raise ValueError("Allowed start and end hours must differ")
        self.protected_path = posixpath.normpath(self.protected_path)
        return self


def settings(path=None):
    model = (ProjectSettings.model_validate_json(Path(path).read_text(encoding="utf-8"))
             if path else ProjectSettings())
    return model.model_dump()
