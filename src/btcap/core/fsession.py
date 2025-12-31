#!/usr/bin/venv python
# Copyright 2025 - 2025, Kevin Leon
# SPDX-License-Identifier: GPL-3.0-only

from pathlib import Path
from bt.bt import BTConnection

class FSession:
  def __init__(self, filepath: Path):
    self.path        = filepath
    self.id          = 0
    self.name        = ""
    self.alias       = None
    self.connection = BTConnection(self.path)
    
    self._set_file_props()
  
  def _set_file_props(self):
    self.name = self.path.name
  
  def set_name(self, name: str) -> None:
    self.name = name
  
  def set_alias(self, alias: str) -> None:
    self.alias = alias
  
  def _set_id(self, sid: int) -> None:
    self.id = sid