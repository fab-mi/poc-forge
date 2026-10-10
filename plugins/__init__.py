import importlib, pkgutil

REGISTRY = {}
for m in pkgutil.iter_modules(__path__):
    if m.name in ("base",):
        continue
    mod = importlib.import_module(f"plugins.{m.name}")
    REGISTRY[mod.NAME] = mod
