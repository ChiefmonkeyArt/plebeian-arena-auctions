"""Placeholder for Nutshell's optional Spark Lightning backend.

The arena mint runs FakeWallet only. Nutshell 0.21.0 imports every Lightning
backend at start-up, and the Spark SDK it pins has no CPython 3.12 wheel, so
this module stands in for it. Any real use fails loudly.
"""


class EventListener:  # base class referenced at import time
    pass


class _Unavailable:
    def __getattr__(self, name):
        return self

    def __call__(self, *args, **kwargs):
        raise RuntimeError("Spark Lightning backend is not installed in this runtime")


def __getattr__(name):
    return _Unavailable()
