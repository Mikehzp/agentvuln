"""Attack registry — separate module to avoid circular imports."""

_registry: dict[str, type] = {}


def register(cls: type):
    """Register an attack class by its name."""
    name = getattr(cls, "name", cls.__name__)
    _registry[name] = cls
    return cls


def get_attack(name: str):
    """Get an attack class by name."""
    return _registry.get(name)


def list_attacks() -> dict[str, type]:
    """Return all registered attack classes."""
    return dict(_registry)


__all__ = ["register", "get_attack", "list_attacks"]
