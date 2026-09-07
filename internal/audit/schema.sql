CREATE TABLE IF NOT EXISTS tool_calls (
  id           INTEGER PRIMARY KEY,
  ts           INTEGER NOT NULL,
  namespace    TEXT    NOT NULL,
  server       TEXT    NOT NULL,
  tool         TEXT    NOT NULL,
  client_id    TEXT,
  session_id   TEXT,
  args_json    TEXT,
  result_size  INTEGER,
  result_json  TEXT,
  duration_ms  INTEGER NOT NULL,
  status       TEXT    NOT NULL,
  error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_calls_ts   ON tool_calls(ts DESC);
CREATE INDEX IF NOT EXISTS idx_calls_tool ON tool_calls(namespace, server, tool, ts DESC);
