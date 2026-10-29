"""
The local try-it app: the try-it page served from this computer for one tester.

It runs a small server on 127.0.0.1, keeps its own app home (logs and state)
in a per-user folder, and never sends anything anywhere: nothing leaves the
machine unless the tester exports a feedback file and passes it on themselves.
"""
