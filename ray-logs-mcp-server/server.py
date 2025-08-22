import os
import re
import io
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

from mcp.server.fastmcp import FastMCP

# ------------- Config -------------
APP_NAME = "ray-log-inspector"
DEFAULT_LOG_DIR = "/tmp/ray/session_latest/logs"
DB_PATH = os.environ.get("RAY_LOG_INDEX_DB", str(Path.home() / ".ray_logs_index.sqlite"))
LOG_DIR = os.environ.get("RAY_LOG_DIR", DEFAULT_LOG_DIR)

# Chunking / indexing
CHUNK_BYTES = 4096  # target size per chunk

# 3-tier signal classification for Ray logs
# High priority (3): Critical errors, exceptions, failures
HIGH_SIGNAL_PAT = re.compile(
    r"\b(ERROR|CRITICAL|Exception|Traceback|FATAL|Failed|FAILED|"
    r"Task failed|Actor died|Worker died|Raylet died|Node failed|"
    r"OutOfMemoryError|MemoryError|RuntimeError|ConnectionError|"
    r"TimeoutError|AssertionError|KeyError|ValueError|TypeError|"
    r"RayTaskError|RayActorError|RaySystemError|"
    r"Segmentation fault|Core dumped|Killed|SIGKILL|SIGTERM|"
    r"Cluster shutdown|Emergency shutdown|Panic|Abort|"
    r"Connection lost|Network unreachable|Connection refused|"
    r"Resource exhausted|Out of memory|OOM|Memory limit exceeded|"
    # Enhanced Ray-specific patterns
    r"Task execution failed|Task raised exception|Task crashed|"
    r"User code exception|Application error|Task exception|"
    r"ray\.get.*Exception|ray\.get.*Error|"
    r"crash|raised.*Error|raised.*Exception|"
    # Better Python exception detection
    r"Traceback \(most recent call last\)|"
    r"raise \w+Error|raise \w+Exception|"
    r"task\s+\w+\s+failed|worker.*crashed|"
    # Better task-specific patterns
    r"RemoteFunction.*failed|@ray\.remote.*failed)\b", 
    re.IGNORECASE
)

# Medium priority (2): Warnings, deprecations, performance issues, recoverable problems
MEDIUM_SIGNAL_PAT = re.compile(
    r"\b(WARNING|WARN|Deprecated|Deprecation|"
    r"Retrying|Retry|Timeout|Slow|Performance|"
    r"Memory pressure|High memory usage|"
    r"Queue full|Backpressure|Throttling|"
    r"Resource contention|Lock contention|"
    r"Spilling|Fallback|Recovery|Recovered|"
    r"Stalled|Blocked|Waiting|"
    r"Configuration|Config|Setting|"
    r"Degraded performance|Suboptimal)\b", 
    re.IGNORECASE
)

# New patterns for better user code detection
USER_CODE_PAT = re.compile(
    r"(crash|raise \w+|Traceback.*most recent|"
    r"def \w+\(.*\):|@ray\.remote|"
    r"File.*\.py.*line \d+|"
    r"RuntimeError.*|ValueError.*|"
    r"in user code|user function|remote function)",
    re.IGNORECASE | re.MULTILINE
)

# Pattern for Ray task execution context
TASK_CONTEXT_PAT = re.compile(
    r"(task_id|worker_id|function_name|remote.*function|"
    r"@ray\.remote|ray\.get|ray\.put|"
    r"executing.*task|running.*task)",
    re.IGNORECASE
)

# Pattern specifically for Python exceptions and tracebacks
PYTHON_EXCEPTION_PAT = re.compile(
    r"(Traceback \(most recent call last\)|"
    r"^\s*File \".*\.py\", line \d+|"
    r"^\s*raise \w+Error|^\s*raise \w+Exception|"
    r"\w+Error: .*|"
    r"\w+Exception: .*)",
    re.MULTILINE
)
TS_PAT = re.compile(
    # common Ray/py logging timestamps like: 2025-08-22 12:34:56,789
    r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?)"
)
TS_PARSE_FORMATS = [
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S,%f",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
]

# Safety & limits
TOOL_TIMEOUT_SEC = 6.0
MAX_RESULTS = 50
MAX_TOTAL_CHARS = 25_000

mcp = FastMCP(APP_NAME)
_executor = ThreadPoolExecutor(max_workers=4)

# ------------- Utilities -------------

def _ensure_db(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    # Basic metadata to avoid reindexing unchanged files
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            path TEXT UNIQUE,
            mtime REAL NOT NULL
        )
        """
    )
    # Row-per-chunk metadata
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS chunks_meta (
            rowid INTEGER PRIMARY KEY, -- matches FTS rowid
            file_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            component TEXT,
            start_offset INTEGER,
            end_offset INTEGER,
            start_ts REAL,
            end_ts REAL,
            signal_priority INTEGER DEFAULT 1,
            FOREIGN KEY(file_id) REFERENCES files(id)
        )
        """
    )
    # Full-text searchable content
    conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS chunks
        USING fts5(
            content,
            file_path UNINDEXED,
            component UNINDEXED,
            start_offset UNINDEXED,
            end_offset UNINDEXED,
            start_ts UNINDEXED,
            end_ts UNINDEXED,
            signal_priority UNINDEXED,
            tokenize='porter'
        )
        """
    )
    conn.commit()


def _connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    try:
        # Ensure FTS5 exists
        conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _fts5_probe USING fts5(x);")
        conn.execute("DROP TABLE _fts5_probe;")
    except sqlite3.OperationalError as e:
        raise RuntimeError("Your Python SQLite build lacks FTS5 support.") from e
    _ensure_db(conn)
    return conn


def _infer_component(filename: str) -> str:
    """
    Extract meaningful component names from Ray log filenames.
    Enhanced to better detect worker logs where task failures occur.
    
    Examples:
    - dashboard.log -> dashboard
    - dashboard_DataHead.log -> dashboard_DataHead  
    - python-core-driver-01000000fff...log -> python-core-driver
    - python-core-worker-370ac7cd1ee...log -> python-core-worker
    - worker-370ac7cd1ee...err -> worker
    - gcs_server.out -> gcs_server
    - raylet.out -> raylet
    """
    base = os.path.basename(filename)
    # Remove file extension but remember if it was .err (important for task failures)
    name, ext = os.path.splitext(base)
    is_err_file = ext.lower() == '.err'
    
    # Handle different Ray log filename patterns
    if name.startswith('python-core-'):
        # python-core-driver-HASH or python-core-worker-HASH
        parts = name.split('-')
        if len(parts) >= 3:
            component = '-'.join(parts[:3])  # python-core-driver or python-core-worker
            # Add suffix for .err files to make them more visible
            return f"{component}_err" if is_err_file else component
    
    elif name.startswith('worker-') and len(name) > 20:
        # worker-HASH-suffix -> worker (these often contain task failures)
        return 'worker_err' if is_err_file else 'worker'
    
    elif 'worker' in name.lower():
        # Catch any other worker-related files
        return 'worker_err' if is_err_file else 'worker'
    
    elif '_' in name:
        # dashboard_DataHead, dashboard_EventHead etc.
        parts = name.split('_')
        # Keep meaningful parts, filter out random suffixes
        meaningful_parts = []
        for part in parts:
            # Skip parts that look like random hashes (long hex strings)
            if len(part) > 10 and all(c in '0123456789abcdefABCDEF' for c in part):
                break
            # Skip parts that are pure numbers (PIDs, etc.)
            if part.isdigit():
                break
            meaningful_parts.append(part)
        
        if meaningful_parts:
            component = '_'.join(meaningful_parts).lower()
            return f"{component}_err" if is_err_file else component
    
    elif '-' in name:
        # Handle other dash-separated names
        parts = name.split('-')
        meaningful_parts = []
        for part in parts:
            # Skip long hex strings and pure numbers
            if len(part) > 10 and all(c in '0123456789abcdefABCDEF' for c in part):
                break
            if part.isdigit() and len(part) > 4:  # Skip long numbers (PIDs)
                break
            meaningful_parts.append(part)
        
        if meaningful_parts:
            component = '-'.join(meaningful_parts).lower()
            return f"{component}_err" if is_err_file else component
    
    # Simple case: just the base name without random suffixes
    # Remove common suffixes that look like IDs/hashes
    clean_name = re.sub(r'[_-][0-9a-fA-F]{8,}.*$', '', name)  # Remove _HASH or -HASH suffixes
    clean_name = re.sub(r'[_-]\d{5,}.*$', '', clean_name)    # Remove _12345 suffixes
    
    result = clean_name.lower() if clean_name else "unknown"
    return f"{result}_err" if is_err_file else result


def _calculate_signal_priority(text: str, filename: str) -> int:
    """
    Calculate signal priority (1=low, 2=medium, 3=high) for a text chunk.
    
    High (3): Critical errors, exceptions, failures, .err files, user code exceptions
    Medium (2): Warnings, deprecations, performance issues  
    Low (1): Normal operations, info logs
    """
    # .err files automatically get high priority
    if filename.endswith('.err'):
        return 3
    
    # Check for Python exceptions and tracebacks first (highest priority)
    if PYTHON_EXCEPTION_PAT.search(text):
        return 3
    
    # Check for user code patterns (high priority) 
    if USER_CODE_PAT.search(text):
        return 3
        
    # Check for Ray task context + any error (high priority)
    if TASK_CONTEXT_PAT.search(text) and ('error' in text.lower() or 'exception' in text.lower() or 'failed' in text.lower()):
        return 3
    
    # Check for high priority patterns
    if HIGH_SIGNAL_PAT.search(text):
        # Exception: don't treat DeprecationWarning as high priority
        if 'DeprecationWarning' in text and 'ERROR' not in text.upper():
            return 2  # Treat as medium priority
        return 3
    
    # Check for medium priority patterns
    if MEDIUM_SIGNAL_PAT.search(text):
        return 2
    
    # Everything else is low priority
    return 1


def _parse_timestamp(s: str) -> Optional[float]:
    # return epoch seconds if any timestamp found in s
    m = TS_PAT.search(s)
    if not m:
        return None
    raw = m.group("ts").replace(",", ".")
    for fmt in TS_PARSE_FORMATS:
        try:
            return datetime.strptime(raw, fmt.replace(",", ".")).timestamp()
        except ValueError:
            continue
    # fallback: best-effort ISO-like parse
    try:
        return datetime.fromisoformat(raw).timestamp()
    except Exception:
        return None


def _chunk_file_bytes(path: Path) -> List[Tuple[int, int, str, Optional[float], Optional[float], int]]:
    """
    Returns a list of chunks for a file.
    Each item: (start_offset, end_offset, content, start_ts, end_ts, signal_priority)
    Enhanced to preserve exception tracebacks and error contexts.
    """
    chunks = []
    file_size = path.stat().st_size
    with path.open("rb") as f:
        start = 0
        while start < file_size:
            f.seek(start)
            blob = f.read(CHUNK_BYTES * 2)  # read a bit extra to find boundary
            if not blob:
                break
                
            # Special handling for exception tracebacks and user code
            text_preview = blob[:CHUNK_BYTES * 2].decode("utf-8", errors="replace")
            
            # Look for Python tracebacks (highest priority for preservation)
            traceback_start = text_preview.find("Traceback (most recent call last)")
            if traceback_start == -1:
                # Also look for other exception indicators
                for pattern in ["crash", "RuntimeError:", "ValueError:", "Exception:", "raise ", "Traceback", "Error:"]:
                    pos = text_preview.find(pattern)
                    if pos != -1:
                        traceback_start = pos
                        break
            
            if traceback_start != -1:
                # Try to capture the complete traceback/exception context
                # Look for the end by finding the next unrelated log entry
                traceback_end = len(text_preview)
                
                # Find next timestamp that's not part of the traceback
                lines = text_preview[traceback_start:].split('\n')
                accumulated_lines = []
                in_traceback = True
                
                for i, line in enumerate(lines):
                    accumulated_lines.append(line)
                    
                    # If we see a timestamp after some traceback content, this might be the end
                    if i > 3 and TS_PAT.match(line.strip()):  # Wait at least 3 lines before considering end
                        # Check if this line looks like start of new log entry vs continuation
                        if not any(marker in line.lower() for marker in ['file ', 'line ', 'in ', '  ']):
                            traceback_end = traceback_start + len('\n'.join(accumulated_lines[:-1]))
                            break
                    # Also end if we see Ray internal logs that aren't part of user exception
                    elif i > 3 and any(marker in line for marker in ['[I ', '[W ', '[E ', '] (raylet)', '] (gcs']):
                        traceback_end = traceback_start + len('\n'.join(accumulated_lines[:-1]))
                        break
                        
                # Ensure we capture the full context, allow larger chunks for important content
                exception_content_size = traceback_end - traceback_start
                if exception_content_size > CHUNK_BYTES:
                    cut = min(traceback_end, CHUNK_BYTES * 4)  # Allow up to 4x for critical exceptions
                else:
                    cut = traceback_end
            else:
                # Normal chunking logic - but still check for user code patterns
                if USER_CODE_PAT.search(text_preview) or TASK_CONTEXT_PAT.search(text_preview):
                    # If we find user code context, be more generous with chunk size
                    cut = min(len(blob), CHUNK_BYTES * 2)
                else:
                    # Standard chunking
                    cut = blob[:CHUNK_BYTES].rfind(b"\n")
                    if cut == -1:
                        cut = len(blob[:CHUNK_BYTES])
                    
            end = start + cut
            f.seek(start)
            data = f.read(end - start)
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = data.decode("latin-1", errors="replace")

            # timestamps (first & last)
            start_ts = None
            end_ts = None
            # scan first ~2 lines and last ~2 lines
            lines = text.splitlines()
            for ln in lines[:2]:
                ts = _parse_timestamp(ln)
                if ts:
                    start_ts = ts
                    break
            for ln in reversed(lines[-2:] if len(lines) >= 2 else lines):
                ts = _parse_timestamp(ln)
                if ts:
                    end_ts = ts
                    break

            signal_priority = _calculate_signal_priority(text, path.name)
            chunks.append((start, end, text, start_ts, end_ts, signal_priority))

            # advance to next chunk start at next byte after 'end' newline
            if end == start:
                # avoid infinite loop if no progress
                end = start + CHUNK_BYTES
            # move to next start (skip the newline if there)
            start = end + 1
    return chunks


def _index_logs(conn: sqlite3.Connection, log_dir: str) -> Dict[str, Any]:
    """
    Walk logs dir and index new/changed files.
    """
    root = Path(log_dir)
    if not root.exists():
        return {"indexed_files": 0, "indexed_chunks": 0, "note": f"{log_dir} not found"}

    indexed_files = 0
    indexed_chunks = 0

    for path in sorted(root.glob("**/*")):
        if not path.is_file():
            continue
        # skip obviously non-text/binary heavy files
        if path.suffix.lower() in {".gz", ".zip"}:
            continue

        stat = path.stat()
        cur = conn.execute("SELECT id, mtime FROM files WHERE path = ?", (str(path),)).fetchone()
        if cur and abs(cur[1] - stat.st_mtime) < 1e-6:
            continue  # unchanged

        # (re)index
        if cur:
            file_id = cur[0]
            # delete existing chunks for this file
            conn.execute("DELETE FROM chunks WHERE file_path = ?", (str(path),))
            conn.execute("DELETE FROM chunks_meta WHERE file_path = ?", (str(path),))
            conn.execute("UPDATE files SET mtime = ? WHERE id = ?", (stat.st_mtime, file_id))
        else:
            conn.execute("INSERT INTO files(path, mtime) VALUES (?, ?)", (str(path), stat.st_mtime))
            file_id = conn.execute("SELECT id FROM files WHERE path = ?", (str(path),)).fetchone()[0]

        component = _infer_component(path.name)
        for (start_off, end_off, content, start_ts, end_ts, signal_priority) in _chunk_file_bytes(path):
            conn.execute(
                "INSERT INTO chunks (content, file_path, component, start_offset, end_offset, start_ts, end_ts, signal_priority) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (content, str(path), component, start_off, end_off, start_ts, end_ts, signal_priority),
            )
            rowid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.execute(
                "INSERT INTO chunks_meta (rowid, file_id, file_path, component, start_offset, end_offset, start_ts, end_ts, signal_priority) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (rowid, file_id, str(path), component, start_off, end_off, start_ts, end_ts, signal_priority),
            )
            indexed_chunks += 1

        conn.commit()
        indexed_files += 1

    return {"indexed_files": indexed_files, "indexed_chunks": indexed_chunks}


def _maybe_index(conn: sqlite3.Connection) -> Dict[str, Any]:
    # Light heuristic: index on startup, then reindex if DB is empty or if
    # the newest file mtime is newer than any file we have stored.
    # For simplicity, re-run incremental index each tool call; it's fast with our checks.
    return _index_logs(conn, LOG_DIR)


def _limit_output(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    total_chars = 0
    for it in items[:MAX_RESULTS]:
        # clip content length
        c = it.get("content", "")
        if isinstance(c, str) and len(c) > 2000:
            it = dict(it)
            it["content"] = c[:2000] + " …[truncated]"
        total_chars += len(it.get("content", "")) if isinstance(it.get("content", ""), str) else 0
        out.append(it)
        if total_chars >= MAX_TOTAL_CHARS:
            break
    return out


def _run_with_timeout(fn, *args, **kwargs):
    fut = _executor.submit(fn, *args, **kwargs)
    return fut.result(timeout=TOOL_TIMEOUT_SEC)


# ------------- MCP Tools -------------

@mcp.tool()
def list_components() -> Dict[str, Any]:
    """
    **PURPOSE**: Discover Ray cluster topology and component health status - EXCELLENT for understanding cluster structure and active components.
    
    **WHEN TO USE**: 
    - **Cluster Architecture Discovery**: Understand what Ray components are present and active
    - **Health Triage**: Quickly identify which components have high error rates needing investigation
    - **Missing Component Detection**: Spot components that should be present but aren't (e.g., missing workers)
    - **Investigation Prioritization**: See which components have the most errors before deep diving
    - **Multi-Component Issues**: Understand if problems are isolated to specific components or cluster-wide
    
    **WHAT IT REVEALS**: 
    - **Complete Component Inventory**: All Ray components (raylet, gcs_server, dashboard, python-core-driver, python-core-worker, etc.)
    - **Activity Status**: File counts and recent activity levels for each component
    - **Error Density**: High-signal event counts to prioritize investigation efforts  
    - **System Completeness**: Missing expected components indicate cluster problems
    
    **TYPICAL RAY COMPONENTS YOU'LL SEE**:
    - **raylet**: Core Ray scheduling and object management
    - **gcs_server**: Global Control Store - cluster coordination  
    - **python-core-worker**: Where your Ray tasks actually execute
    - **python-core-driver**: Your main Ray script/application
    - **dashboard**: Ray dashboard and monitoring components
    - **worker/worker_err**: Task execution logs (often contain user code issues)
    
    **INTERPRETATION TIPS**:
    - **high_signal_chunks > 0**: Component likely has issues - investigate with find_errors() or get_high_signal_logs()
    - **recent latest_activity**: Component is actively running 
    - **Missing expected components**: Indicates cluster startup/configuration problems
    - **Many worker_err files**: Suggests user code issues vs infrastructure problems
    
    
    **RETURNS**: Structured component inventory with:
    - Component names and types discovered
    - File counts and log chunk counts per component  
    - High-signal event counts (error/warning density)
    - Latest activity timestamps for each component
    
    **PRO TIP**: Use this early in investigation to understand cluster topology, then focus on 
    components with high_signal_chunks > 0 for detailed error analysis.
    """
    def _impl():
        conn = _connect_db()
        try:
            _maybe_index(conn)
            
            sql = """
                SELECT component, 
                       COUNT(DISTINCT file_path) as file_count,
                       COUNT(*) as chunk_count,
                       MAX(end_ts) as latest_activity,
                       SUM(CASE WHEN signal_priority >= 2 THEN 1 ELSE 0 END) as high_signal_chunks
                FROM chunks 
                GROUP BY component 
                ORDER BY latest_activity DESC NULLS LAST, component
            """
            rows = conn.execute(sql).fetchall()
            
            components = []
            for row in rows:
                comp, file_count, chunk_count, latest_ts, signal_count = row
                latest_str = ""
                if latest_ts:
                    try:
                        latest_str = datetime.fromtimestamp(latest_ts).isoformat()
                    except (ValueError, OSError):
                        latest_str = "unknown"
                
                components.append({
                    "component": comp,
                    "file_count": file_count,
                    "chunk_count": chunk_count,
                    "high_signal_chunks": signal_count,
                    "latest_activity": latest_str
                })
            
            return {
                "total_components": len(components),
                "components": components
            }
        finally:
            conn.close()
    
    try:
        return _run_with_timeout(_impl)
    except FuturesTimeout:
        return {"error": f"list_components timed out after {TOOL_TIMEOUT_SEC}s"}


@mcp.tool()
def reindex(force_clean: bool = False) -> Dict[str, Any]:
    """
    **PURPOSE**: Rebuild the searchable index of Ray logs for analysis - FOUNDATION for all other tools.
    
    **WHEN TO USE**:
    - **🔧 CRITICAL FIRST STEP**: Always run this FIRST when analyzing logs from a new Ray cluster/job
    - **Tool Dependencies**: ALL other tools require this - without indexing, you get no results  
    - **Fresh Log Analysis**: After Ray cluster restarts or when investigating fresh issues
    - **Log Directory Changes**: When investigating different Ray sessions or log directories
    - **Force Clean Scenarios**: Use force_clean=True when switching between different Ray runs
    
    **AUTOMATIC FEATURES**:
    - **Smart Incremental Updates**: Only re-indexes changed files (very fast for repeat runs)
    - **Signal Priority Classification**: Automatically categorizes logs as high/medium/low priority
    - **Cross-Component Discovery**: Finds all Ray components (raylet, workers, GCS, dashboard, etc.)
    - **Timestamp Extraction**: Parses timestamps for timeline analysis capabilities
    
    **PARAMETERS**:
    - force_clean=False: **RECOMMENDED** - Incrementally update index, remove deleted files (fast)
    - force_clean=True: Complete rebuild - use when switching between different Ray clusters/sessions
    
    **PERFORMANCE**: 
    - **Incremental Mode**: Usually completes in 1-2 seconds for existing indexes
    - **Clean Rebuild**: May take 5-10 seconds for large log sets but enables all analysis features
    - **Required Foundation**: Must complete successfully for all other tools to work
    
    **RETURNS**: Comprehensive statistics about:
    - Files indexed and processing progress  
    - Signal priority breakdown (high/medium/low priority events detected)
    - Component discovery (which Ray components found logs for)
    - Index health and readiness for analysis tools
    
    **PRO TIP**: Run this first with default settings (force_clean=False), then use get_cluster_status() 
    to get an overview and investigation guidance.
    """
    def _impl():
        conn = _connect_db()
        try:
            if force_clean:
                # Clean slate - useful when Ray job changes and old logs are gone
                conn.execute("DELETE FROM chunks")
                conn.execute("DELETE FROM chunks_meta") 
                conn.execute("DELETE FROM files")
                conn.commit()
            else:
                # Clean up files that no longer exist
                file_rows = conn.execute("SELECT id, path FROM files").fetchall()
                for file_id, path in file_rows:
                    if not Path(path).exists():
                        conn.execute("DELETE FROM chunks WHERE file_path = ?", (path,))
                        conn.execute("DELETE FROM chunks_meta WHERE file_path = ?", (path,))
                        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
                conn.commit()
            
            result = _index_logs(conn, LOG_DIR)
            
            # Add some stats about the final index
            stats = conn.execute("""
                SELECT 
                    COUNT(DISTINCT file_path) as total_files,
                    COUNT(*) as total_chunks,
                    SUM(CASE WHEN signal_priority >= 3 THEN 1 ELSE 0 END) as high_signal_chunks,
                    SUM(CASE WHEN signal_priority >= 2 THEN 1 ELSE 0 END) as medium_plus_high_chunks,
                    COUNT(DISTINCT component) as components
                FROM chunks
            """).fetchone()
            
            result.update({
                "total_files_in_index": stats[0],
                "total_chunks_in_index": stats[1], 
                "high_signal_chunks": stats[2],
                "medium_plus_high_chunks": stats[3],
                "total_components": stats[4],
                "cleaned_first": force_clean
            })
            
            return result
        finally:
            conn.close()
    
    try:
        return _run_with_timeout(_impl)
    except FuturesTimeout:
        return {"error": f"reindex timed out after {TOOL_TIMEOUT_SEC}s"}


@mcp.tool()
def find_errors(query: str, time_range: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    **PURPOSE**: Search for critical errors and exceptions with timeline filtering - focuses ONLY on high-priority issues.
    
    **WHEN TO USE**:
    - **Following up on get_cluster_status() recommendations**: When it suggests specific error patterns to investigate
    - **Targeted Error Investigation**: When you know specific error patterns to look for (RayTaskError, OutOfMemoryError, etc.)
    - **Infrastructure Issue Debugging**: Find errors related to specific functionality (serialization, actor creation, task execution)  
    - **Timeline-focused Error Analysis**: Combine with time_range to see errors during specific incidents
    
    **🎯 FOCUS FEATURE**: 
    - **High-Priority Only**: Searches ONLY medium/high priority logs (filters out normal info/debug noise)
    - **Error-First Ranking**: Results sorted by signal priority (critical errors first, then warnings)
    
    **VS search_logs()**: 
    - find_errors(): Only searches high/medium priority logs - great for cutting through noise
    - search_logs(): Searches ALL logs including info/debug
    
    **POWERFUL COMBINATIONS**:
    - find_errors("SIGTERM", time_range="2025-08-21T17:01:58.670..2025-08-21T17:01:58.680") - Errors during specific incident  
    - find_errors("OutOfMemoryError") - System-wide memory issues
    - find_errors("Exception") - All user code exceptions across cluster
    
    **TARGETED ERROR EXAMPLES**:
    - find_errors("RayTaskError") - Task execution failures
    - find_errors("OutOfMemoryError") - Memory-related crashes  
    - find_errors("actor") - Actor-related issues
    - find_errors("serialization") - Serialization problems
    - find_errors("ConnectionError") - Network/connectivity issues
    - find_errors("SIGTERM") - Process termination issues
    
    **PARAMETERS**:
    - query: Search terms for specific error patterns (simple terms work best)
    - time_range: **POWERFUL**: 'start_iso..end_iso' format for incident-focused analysis (e.g., '2025-08-21T10:00:00..2025-08-21T11:00:00')
    
    **RETURNS**: High-priority error chunks with priority labels, timestamps, and context.
    
    **PRO TIP**: Use this after get_cluster_status() points you to specific error patterns, or when you need to cut through 
    log noise to focus only on actual problems.
    """
    def _impl():
        conn = _connect_db()
        try:
            _maybe_index(conn)
            # Parse time_range
            start_ts, end_ts = None, None
            if time_range:
                s, _, e = time_range.partition("..")
                s = s.strip() or None
                e = e.strip() or None
                if s:
                    start_ts = datetime.fromisoformat(s).timestamp()
                if e:
                    end_ts = datetime.fromisoformat(e).timestamp()

            where = ["signal_priority >= 2"]  # medium and high priority signals
            params: List[Any] = []
            # FTS query; use bm25 to rank
            fts_query = query if query.strip() else "*"
            where.append("chunks MATCH ?")
            params.append(fts_query)

            if start_ts is not None:
                where.append("(start_ts IS NOT NULL AND end_ts IS NOT NULL AND end_ts >= ?)")
                params.append(start_ts)
            if end_ts is not None:
                where.append("(start_ts IS NOT NULL AND start_ts <= ?)")
                params.append(end_ts)

            sql = f"""
                SELECT rowid, content, file_path, component, start_offset, end_offset, start_ts, end_ts, signal_priority,
                       bm25(chunks, 1.0, 1.0) AS score
                FROM chunks
                WHERE {' AND '.join(where)}
                ORDER BY signal_priority DESC, score LIMIT ?
            """
            params.append(MAX_RESULTS)
            rows = conn.execute(sql, params).fetchall()

            results = []
            for r in rows:
                priority_label = "high" if r[8] >= 3 else "medium" if r[8] >= 2 else "low"
                results.append({
                    "file": r[2],
                    "component": r[3],
                    "start_offset": r[4],
                    "end_offset": r[5],
                    "start_ts": r[6],
                    "end_ts": r[7],
                    "signal_priority": r[8],
                    "priority_label": priority_label,
                    "score": r[9],
                    "summary": _summarize_chunk(r[1]),
                    "content": r[1],
                })
            return _limit_output(results)
        finally:
            conn.close()

    try:
        return _run_with_timeout(_impl)
    except FuturesTimeout:
        return [{"error": f"find_errors timed out after {TOOL_TIMEOUT_SEC}s"}]


@mcp.tool()
def tail_logs(component: Optional[str] = None, N: int = 200, time_range: Optional[str] = None) -> Dict[str, Any]:
    """
    **PURPOSE**: View chronologically-ordered log activity with powerful timeline filtering
    
    **WHEN TO USE**:
    - **Timeline Analysis**: Use time_range to focus on specific windows (seconds or milliseconds precision)
    - **Cross-component Correlation**: Understand how events in one component trigger events in others
    - **Final Moments Analysis**: See what was happening at the end of a Ray cluster's life
    - **Component-specific Investigation**: Focus on specific component behavior during issues
    
    **🔥 KEY POWER FEATURES**:
    - **Chronological Interleaving**: Combines logs from ALL components in true time order with [component] prefixes
    - **Millisecond-precision Timeline**: Use time_range for precise race condition analysis
    - **Cross-component Event Correlation**: See how raylet events trigger worker events trigger GCS events
    - **Historical Analysis**: Works with logs from stopped/crashed clusters, not just active ones
    
    **TWO MODES**:
    1. **Multi-component Timeline** (component=None): Shows chronologically interleaved logs from all 
       components with [component] prefixes for clarity - PERFECT for understanding event sequences
    2. **Single component focus** (component="raylet"): Shows recent logs from matching components only
    
    **TIMELINE DEBUGGING EXAMPLES** (Most Powerful Use Cases):
    - tail_logs(time_range="2025-08-21T17:01:58.670..2025-08-21T17:01:58.680") - Analyze exact 10-second window
    - tail_logs(time_range="2025-08-21T17:01:58.675..2025-08-21T17:01:58.677") - 2-millisecond race condition window
    - tail_logs(N=100, time_range="2025-08-21T17:01:58.500..2025-08-21T17:01:59.000") - Worker lifecycle during 500ms
    
    **STANDARD EXAMPLES**:
    - tail_logs() - Last 5 minutes from entire cluster, chronological (DEFAULT: very useful starting point)
    - tail_logs(component="raylet") - Recent raylet-specific activity
    - tail_logs(component="python-core-worker") - Recent worker activity  
    - tail_logs(component="dashboard") - Recent dashboard activity
    - tail_logs(N=500) - More lines for deeper investigation
    
    **PARAMETERS**:
    - component: Partial component name (matches substrings: "worker", "dashboard", "gcs", "raylet")
    - N: Number of lines to return (default 200, max 5000) - increase for deeper investigation
    - time_range: **🔥 MOST POWERFUL**: 'start_iso..end_iso' for precise timeline windows (e.g., '2025-08-21T17:01:58.670..2025-08-21T17:01:58.680')
    
    **RETURNS**: Chronologically-ordered log lines with metadata about timespan and components involved.

    """
    N = max(1, min(N, 5000))  # cap
    def _impl():
        conn = _connect_db()
        try:
            _maybe_index(conn)

            start_ts, end_ts = None, None
            if time_range:
                s, _, e = time_range.partition("..")
                s = s.strip() or None
                e = e.strip() or None
                if s:
                    start_ts = datetime.fromisoformat(s).timestamp()
                if e:
                    end_ts = datetime.fromisoformat(e).timestamp()

            where = []
            params: List[Any] = []
            
            # If no component specified and no time_range, default to last 5 minutes
            if not component and not time_range:
                import time
                five_min_ago = time.time() - 300  # 5 minutes
                where.append("(end_ts IS NULL OR end_ts >= ?)")
                params.append(five_min_ago)
                
            if component:
                where.append("component LIKE ?")
                params.append(f"%{component.lower()}%")
            if start_ts is not None:
                where.append("(end_ts IS NULL OR end_ts >= ?)")
                params.append(start_ts)
            if end_ts is not None:
                where.append("(start_ts IS NULL OR start_ts <= ?)")
                params.append(end_ts)

            if not component:
                # Multi-component view: get chunks with timestamps for interleaving
                sql = f"""
                    SELECT content, file_path, component, start_offset, end_offset, end_ts, start_ts
                    FROM chunks
                    {"WHERE " + " AND ".join(where) if where else ""}
                    ORDER BY COALESCE(end_ts, start_ts, 0) DESC, rowid DESC
                    LIMIT ?
                """
                params.append(400)  # get more chunks for multi-component
                rows = conn.execute(sql, params).fetchall()

                # Create timestamped lines with component info
                timestamped_lines: List[Tuple[float, str, str]] = []  # (timestamp, line, component)
                for content, file_path, comp, _s, _e, end_ts, start_ts in rows:
                    ts = end_ts or start_ts or 0
                    lines = content.splitlines()
                    for line in lines:
                        if line.strip():
                            # Add component prefix to make it clear which component each line is from
                            prefixed_line = f"[{comp}] {line}"
                            timestamped_lines.append((ts, prefixed_line, comp))
                    if len(timestamped_lines) >= N * 3:  # get plenty, we'll trim later
                        break
                
                # Sort by timestamp (newest first) and take N lines
                timestamped_lines.sort(key=lambda x: x[0], reverse=True)
                lines = [line for _, line, _ in timestamped_lines[:N]]
                
                components_involved = list(set(comp for _, _, comp in timestamped_lines[:N]))
                note = f"Returned last {min(N, len(lines))} lines from {len(components_involved)} components: {', '.join(sorted(components_involved))}"
            else:
                # Single component view (original logic)
                sql = f"""
                    SELECT content, file_path, component, start_offset, end_offset, end_ts
                    FROM chunks
                    {"WHERE " + " AND ".join(where) if where else ""}
                    ORDER BY COALESCE(end_ts, 0) DESC, rowid DESC
                    LIMIT ?
                """
                params.append(200)  # get a few chunks, then trim to N lines
                rows = conn.execute(sql, params).fetchall()

                # stitch last N lines
                lines: List[str] = []
                for content, file_path, comp, _s, _e, _et in rows:
                    seg = content.splitlines()
                    lines.extend(seg)
                    if len(lines) >= N * 2:
                        break
                lines = lines[-N:]  # take last N
                note = f"Returned last {min(N, len(lines))} lines from recent chunks."
            
            tail = "\n".join(lines)
            return {
                "component": component or "all_components",
                "lines": tail,
                "note": note,
            }
        finally:
            conn.close()

    try:
        return _run_with_timeout(_impl)
    except FuturesTimeout:
        return {"error": f"tail_logs timed out after {TOOL_TIMEOUT_SEC}s"}


@mcp.tool()
def get_high_signal_logs(component: Optional[str] = None, time_range: Optional[str] = None) -> Dict[str, Any]:
    """
    **PURPOSE**: Get systematic error pattern analysis by grouping similar issues - PERFECT for root cause analysis.
    
    **WHEN TO USE**:
    - **After list_components() shows high error counts** - Use this to understand what types of errors occurred
    - **Root Cause Analysis**: See which error patterns are most common to focus investigation efforts  
    - **Cross-Component Error Correlation**: Identify if similar issues affect multiple components
    - **Error Impact Assessment**: Understand which error patterns are systemic vs isolated incidents
    - **Investigation Prioritization**: Focus on high-frequency error patterns first
    
    **🔍 PATTERN ANALYSIS FEATURES**: 
    - **Smart Error Grouping**: Groups similar error messages together (normalizes hashes, paths, line numbers)
    - **Frequency Analysis**: Shows counts for each error pattern to identify systemic vs isolated issues
    - **Cross-Component View**: See if error patterns appear across multiple Ray components
    - **Representative Examples**: Provides actual log examples for each error pattern
    - **Priority-Based Sorting**: Most frequent errors shown first for efficient triage
    
    **INTELLIGENT NORMALIZATION**:
    - **Hash/ID Removal**: "worker_id_abc123" becomes "worker_id_ID" to group similar errors
    - **Path Generalization**: "/path/to/file.py:123" becomes "/path/to/file.py:N" 
    - **Number Normalization**: Error counts, PIDs, line numbers become "N" for pattern matching
    - **Timestamp Stripping**: Focuses on error content, not when it occurred
    
    **POWERFUL ANALYSIS EXAMPLES**:
    - **Systemic Issues**: "OutOfMemoryError" appearing 15 times across multiple workers = resource problem
    - **Infrastructure Issues**: "Connection failed" appearing 8 times in raylet = network problem  
    - **User Code Issues**: "ValueError in user_function" appearing 20 times = code bug
    
    **INVESTIGATION PATTERNS**:
    - **High count + single component** = Component-specific issue (focus there)
    - **High count + multiple components** = Systemic infrastructure problem (broader investigation needed)
    - **Many different low-count patterns** = Multiple unrelated issues or widespread instability
    
    **USAGE EXAMPLES**:
    - get_high_signal_logs() - **RECOMMENDED START** - All error patterns across all components
    - get_high_signal_logs(component="raylet") - Focus on raylet infrastructure issues
    - get_high_signal_logs(component="python-core-worker") - Focus on task execution problems
    - get_high_signal_logs(time_range="2025-08-21T17:01:58.500..2025-08-21T17:02:00.000") - Errors during specific incident
    
    **PARAMETERS**:
    - component: Optional filter (e.g., "raylet", "python-core-worker", "dashboard") for focused analysis
    - time_range: **POWERFUL**: 'start_iso..end_iso' to analyze error patterns during specific incidents
    
    **RETURNS**: Intelligent error clustering with:
    - Error pattern signatures grouped by component
    - Frequency counts for impact assessment
    - Representative examples for each pattern  
    - Cross-component correlation insights
    
    **PRO TIP**: Use this after list_components() identifies problematic components, or when get_cluster_status() 
    suggests pattern analysis. Focus on high-count patterns first for maximum investigation impact.
    """
    def _impl():
        conn = _connect_db()
        try:
            _maybe_index(conn)

            start_ts, end_ts = None, None
            if time_range:
                s, _, e = time_range.partition("..")
                s = s.strip() or None
                e = e.strip() or None
                if s:
                    start_ts = datetime.fromisoformat(s).timestamp()
                if e:
                    end_ts = datetime.fromisoformat(e).timestamp()

            where = ["signal_priority >= 2"]  # medium and high priority signals
            params: List[Any] = []
            
            if component:  # This references the outer function parameter
                where.append("component LIKE ?")
                params.append(f"%{component.lower()}%")
            if start_ts is not None:
                where.append("(end_ts IS NULL OR end_ts >= ?)")
                params.append(start_ts)
            if end_ts is not None:
                where.append("(start_ts IS NULL OR start_ts <= ?)")
                params.append(end_ts)

            sql = f"""
                SELECT content, component, signal_priority
                FROM chunks
                WHERE {' AND '.join(where)}
                ORDER BY signal_priority DESC, rowid DESC
                LIMIT ?
            """
            params.append(2000)  # analyze up to 2000 signal chunks
            rows = conn.execute(sql, params).fetchall()

            # Group by component and signature
            component_sigs: Dict[str, Dict[str, int]] = {}
            examples: Dict[str, Dict[str, str]] = {}

            for content, comp_name, signal_priority in rows:
                norm = _normalize_signature(content)
                if not norm:
                    continue
                    
                if comp_name not in component_sigs:
                    component_sigs[comp_name] = {}
                    examples[comp_name] = {}
                    
                component_sigs[comp_name][norm] = component_sigs[comp_name].get(norm, 0) + 1
                
                if norm not in examples[comp_name]:
                    examples[comp_name][norm] = _grab_first_signal_line(content)

            # Build results grouped by component
            component_clusters = {}
            total_signals = 0
            
            for comp_name, sig_counts in component_sigs.items():
                items = sorted(sig_counts.items(), key=lambda kv: kv[1], reverse=True)[:20]  # top 20 per component
                clusters = [{"signature": k, "count": v, "example": examples[comp_name].get(k, "")} for k, v in items]
                component_total = sum(sig_counts.values())
                total_signals += component_total
                
                component_clusters[comp_name] = {
                    "total_errors": component_total,
                    "distinct_patterns": len(sig_counts),
                    "top_patterns": clusters
                }
            
            return {
                "total_signal_chunks": total_signals,
                "components_with_errors": len(component_clusters),
                "by_component": component_clusters,
            }
        finally:
            conn.close()

    try:
        return _run_with_timeout(_impl)
    except FuturesTimeout:
        return {"error": f"get_high_signal_logs timed out after {TOOL_TIMEOUT_SEC}s"}


@mcp.tool()
def search_logs(query: str, component: Optional[str] = None, time_range: Optional[str] = None, include_context: bool = False) -> List[Dict[str, Any]]:
    """
    **PURPOSE**: Flexible text search across ALL log levels with powerful timeline filtering for investigating specific issues.
    
    **WHEN TO USE**:
    - Tracing specific operations, user code, or Ray API calls through the system
    - Finding mentions of specific object IDs, task names, or user identifiers
    - General debugging when you know what to look for but not where
    - Following the lifecycle of specific operations across components
    - **TIMELINE DEBUGGING**: Investigating race conditions or event sequences
    
    **KEY FEATURES**:
    - **Timeline Filtering**: Use time_range to focus on specific time windows for race condition analysis
    - **Cross-component Search**: Find related events across raylet, workers, GCS, etc.
    - **Full-text Search**: Searches ALL logs (info, debug, warnings, errors) across all priority levels
    
    **VS find_errors()**: 
    - search_logs(): Searches ALL logs (info, debug, warnings, errors) across all priority levels
    - find_errors(): Only searches high/medium priority logs (errors and warnings)
    
    **SEARCH SYNTAX TIPS** (Important for query parameter):
    - **Simple terms work best**: "graceful shutdown", "123291", "SIGTERM" 
    - **Avoid special FTS characters**: . ( ) [ ] { } + * ? ^ $ | \ cause syntax errors
    - **For phrases with special chars**: Use separate searches or escape/quote
    - **Examples that work**: 
      * search_logs("ray") - finds ray.get, ray.put, etc.
      * search_logs("graceful shutdown") - phrase search
      * search_logs("worker_id") - underscores are fine
    - **Examples that break**:
      * search_logs("ray.get") - FTS syntax error on "." 
      * search_logs("(error)") - FTS syntax error on parentheses
    - **Workarounds**: Use search_logs("ray") + search_logs("get") separately
    
    **TIMELINE DEBUGGING EXAMPLES**:
    - search_logs("SIGTERM", time_range="2025-08-21T17:01:58.670..2025-08-21T17:01:58.680") - Race condition analysis
    - search_logs("123291", time_range="2025-08-21T17:01:58.500..2025-08-21T17:01:59.000") - Worker lifecycle
    - search_logs("graceful shutdown", component="python-core-worker") - Component-specific investigation
    
    **STANDARD EXAMPLES**:
    - search_logs("my_function_name") - Find user code execution
    - search_logs("01000000", component="raylet") - Track specific object in raylet
    - search_logs("serialization", include_context=True) - Deep dive into serialization issues
    
    **PARAMETERS**:
    - query: Text to search for (avoid FTS special characters: . ( ) [ ] { } + * ? ^ $ | \)
    - component: Filter to specific component type (e.g., "raylet", "python-core-worker")
    - time_range: **POWERFUL**: 'start_iso..end_iso' format for timeline analysis (e.g., '2025-08-21T17:01:58.670..2025-08-21T17:01:58.680')
    - include_context: True=full chunks, False=matching lines only
    
    **RETURNS**: Search results sorted by signal priority with relevance scores and timestamps.
    """
    def _impl():
        conn = _connect_db()
        try:
            _maybe_index(conn)
            
            start_ts, end_ts = None, None
            if time_range:
                s, _, e = time_range.partition("..")
                s = s.strip() or None
                e = e.strip() or None
                if s:
                    start_ts = datetime.fromisoformat(s).timestamp()
                if e:
                    end_ts = datetime.fromisoformat(e).timestamp()

            where = []
            params: List[Any] = []
            
            # FTS query
            fts_query = query if query.strip() else "*"
            where.append("chunks MATCH ?")
            params.append(fts_query)
            
            if component:
                where.append("component LIKE ?")
                params.append(f"%{component.lower()}%")
            if start_ts is not None:
                where.append("(start_ts IS NOT NULL AND end_ts IS NOT NULL AND end_ts >= ?)")
                params.append(start_ts)
            if end_ts is not None:
                where.append("(start_ts IS NOT NULL AND start_ts <= ?)")
                params.append(end_ts)

            sql = f"""
                SELECT rowid, content, file_path, component, start_offset, end_offset, start_ts, end_ts, signal_priority,
                       bm25(chunks, 1.0, 1.0) AS score
                FROM chunks
                WHERE {' AND '.join(where)}
                ORDER BY signal_priority DESC, score LIMIT ?
            """
            params.append(MAX_RESULTS)
            rows = conn.execute(sql, params).fetchall()

            results = []
            for r in rows:
                content = r[1]
                if not include_context:
                    # Just show lines containing the query terms
                    matching_lines = []
                    for line in content.splitlines():
                        if any(term.lower() in line.lower() for term in query.split()):
                            matching_lines.append(line.strip())
                    content = "\n".join(matching_lines[:10])  # limit to 10 matching lines
                
                priority_label = "high" if r[8] >= 3 else "medium" if r[8] >= 2 else "low"
                results.append({
                    "file": r[2],
                    "component": r[3],
                    "start_offset": r[4],
                    "end_offset": r[5],
                    "start_ts": r[6],
                    "end_ts": r[7],
                    "signal_priority": r[8],
                    "priority_label": priority_label,
                    "score": r[9],
                    "content": content,
                })
            return _limit_output(results)
        finally:
            conn.close()

    try:
        return _run_with_timeout(_impl)
    except FuturesTimeout:
        return [{"error": f"search_logs timed out after {TOOL_TIMEOUT_SEC}s"}]


@mcp.tool()
def get_cluster_status() -> Dict[str, Any]:
    """
    **PURPOSE**: Get an intelligent health assessment and timeline overview - PERFECT starting point for any Ray investigation.
    
    **WHEN TO USE**:
    - **🥇 EXCELLENT STARTING POINT** - Always run this FIRST to get AI-powered analysis and investigation guidance
    - **Triage Decision Making**: Understand if you're looking at task failures vs infrastructure issues vs clean shutdown
    - **Investigation Roadmap**: Get specific tool recommendations for next steps (e.g., "Try find_errors('SIGTERM')")
    - **Historical vs Active Analysis**: Understand if logs are from active cluster or post-mortem analysis
    - **Component Priority Ranking**: See which components had the most issues and should be investigated first
    
    **🧠 INTELLIGENT FEATURES**:
    - **Smart Timeline Analysis**: Analyzes final 5min/1hour of cluster activity (not current time - works with old logs)
    - **Automatic Issue Classification**: "task_failure", "resource_exhaustion", "infrastructure_failure", "clean_shutdown"
    - **AI-Powered Recommendations**: Suggests specific tools and queries for next investigation steps
    - **Critical Pattern Detection**: Automatically scans for OOM, node failures, network issues, user code exceptions
    - **Component Health Ranking**: Shows which components had the most high-priority signals
    
    **WORKS WITH EVERYTHING**:
    - **Active clusters**: Real-time monitoring and health checks
    - **Historical logs**: Post-mortem analysis of completed/crashed clusters from hours/days ago
    - **Partial logs**: Even works with incomplete log sets
    
    **EXAMPLE AI ANALYSIS OUTPUTS**:
    - "🚨 TASK FAILURES DETECTED - Job failed due to user code exceptions. Try find_errors('Exception') or search_logs('Traceback')"
    - "💾 MEMORY ISSUES - Cluster failed due to out-of-memory conditions. Use find_errors('OutOfMemory')"
    - "✅ CLEAN SHUTDOWN - No major issues detected, appears to be normal completion. Use tail_logs() to see final activity"
    
    **INTERPRETATION GUIDE**:
    - cluster_state="active" → Cluster likely still running (logs < 6min old)
    - cluster_state="stopped_today" → Recent failure, logs are fresh for analysis  
    - primary_issue="task_failure" → Focus on user code debugging
    - primary_issue="infrastructure_failure" → Focus on Ray component issues
    - high_signals_final_5min > 0 → Critical issues in final moments
    - Component status="critical" → Focus investigation here first
    
    **RETURNS**: Multi-layered intelligent assessment with:
    - Timing context and cluster state classification
    - AI analysis with specific next-step recommendations  
    - Error trend analysis across different time windows
    - Critical issue detection with counts and categories
    - Per-component health status with priority ranking
    
    **PRO TIP**: This tool's AI analysis will guide you to the right debugging approach and save significant time.
    """
    def _impl():
        conn = _connect_db()
        try:
            _maybe_index(conn)
            
            # Find the most recent log timestamp to use as our reference point
            # This handles cases where we're analyzing logs from old/stopped clusters
            latest_log_ts = conn.execute("""
                SELECT MAX(COALESCE(end_ts, start_ts)) 
                FROM chunks 
                WHERE end_ts IS NOT NULL OR start_ts IS NOT NULL
            """).fetchone()[0]
            
            if latest_log_ts is None:
                return {
                    "error": "No timestamped logs found in index",
                    "suggestion": "Try running reindex() first"
                }
            
            # Calculate time windows relative to the latest log, not current time
            five_min_before_latest = latest_log_ts - 300  # 5 minutes before latest log
            one_hour_before_latest = latest_log_ts - 3600  # 1 hour before latest log
            
            # Also get current time to show how old these logs are
            import time
            current_time = time.time()
            log_age_hours = (current_time - latest_log_ts) / 3600
            
            # Get recent activity by component (relative to latest log time)
            recent_activity = conn.execute("""
                SELECT component,
                       COUNT(*) as recent_chunks,
                       SUM(CASE WHEN signal_priority >= 2 THEN 1 ELSE 0 END) as recent_signals,
                       SUM(CASE WHEN signal_priority >= 3 THEN 1 ELSE 0 END) as recent_high_signals,
                       MAX(COALESCE(end_ts, start_ts)) as last_activity
                FROM chunks 
                WHERE COALESCE(end_ts, start_ts) >= ?
                GROUP BY component
                ORDER BY recent_high_signals DESC, recent_signals DESC, recent_chunks DESC
            """, (five_min_before_latest,)).fetchall()
            
            # Get overall error trend (relative to latest log time)
            error_trend = conn.execute("""
                SELECT 
                    SUM(CASE WHEN COALESCE(end_ts, start_ts) >= ? AND signal_priority >= 3 THEN 1 ELSE 0 END) as high_signals_final_5min,
                    SUM(CASE WHEN COALESCE(end_ts, start_ts) >= ? AND signal_priority >= 2 THEN 1 ELSE 0 END) as medium_plus_high_final_5min,
                    SUM(CASE WHEN COALESCE(end_ts, start_ts) >= ? AND signal_priority >= 3 THEN 1 ELSE 0 END) as high_signals_final_hour,
                    SUM(CASE WHEN COALESCE(end_ts, start_ts) >= ? AND signal_priority >= 2 THEN 1 ELSE 0 END) as medium_plus_high_final_hour,
                    COUNT(CASE WHEN COALESCE(end_ts, start_ts) >= ? THEN 1 END) as chunks_in_final_5min
                FROM chunks
            """, (five_min_before_latest, five_min_before_latest, one_hour_before_latest, one_hour_before_latest, five_min_before_latest)).fetchone()
            
            # Look for specific critical patterns in recent logs
            # Enhanced to distinguish between task failures and infrastructure issues
            critical_patterns = [
                ("task_failures", "RuntimeError OR ValueError OR TypeError OR \"Task failed\" OR \"💥\" OR \"demo crash\" OR \"raised\""),
                ("user_code_errors", "Exception OR Error OR Traceback"),
                ("cluster_shutdown", "shutdown OR \"shutting down\" OR terminated"),
                ("out_of_memory", "\"out of memory\" OR oom OR \"memory error\""),
                ("node_failure", "(node* AND failed) OR (worker* AND died) OR (raylet* AND died)"),
                ("network_issues", "(connection* AND failed) OR timeout OR unreachable"),
            ]
            
            critical_issues = {}
            task_failure_detected = False
            
            for pattern_name, pattern in critical_patterns:
                try:
                    count = conn.execute("""
                        SELECT COUNT(*) FROM chunks 
                        WHERE COALESCE(end_ts, start_ts) >= ? AND signal_priority >= 2 AND chunks MATCH ?
                    """, (one_hour_before_latest, pattern)).fetchone()[0]
                    if count > 0:
                        critical_issues[pattern_name] = count
                        if pattern_name in ["task_failures", "user_code_errors"]:
                            task_failure_detected = True
                except sqlite3.OperationalError:
                    # Skip patterns that cause FTS5 syntax errors
                    pass
            
            activity_summary = []
            for comp, chunks, medium_signals, high_signals, last_ts in recent_activity:
                last_str = "unknown"
                if last_ts:
                    try:
                        last_str = datetime.fromtimestamp(last_ts).isoformat()
                    except (ValueError, OSError):
                        pass
                
                activity_summary.append({
                    "component": comp,
                    "recent_activity": chunks,
                    "recent_medium_signals": medium_signals,
                    "recent_high_signals": high_signals,
                    "last_seen": last_str,
                    "status": "critical" if high_signals > 3 else "error" if high_signals > 0 else "warning" if medium_signals > 0 else "active"
                })
            
            # Determine cluster state based on log age
            if log_age_hours < 0.1:  # less than 6 minutes old
                cluster_state = "active"
            elif log_age_hours < 1:  # less than 1 hour old  
                cluster_state = "recently_stopped"
            elif log_age_hours < 24:  # less than 1 day old
                cluster_state = "stopped_today"
            else:
                cluster_state = "historical"
            
            # Smart analysis recommendations with specific tool suggestions
            if task_failure_detected:
                analysis_note = f"🚨 TASK FAILURES DETECTED - Job failed due to user code exceptions. Try find_errors('Exception') or search_logs('Traceback')"
                primary_issue = "task_failure"
            elif critical_issues.get("out_of_memory", 0) > 0:
                analysis_note = f"💾 MEMORY ISSUES - Cluster failed due to out-of-memory conditions. Use find_errors('OutOfMemory')"
                primary_issue = "resource_exhaustion"
            elif critical_issues.get("node_failure", 0) > 0:
                analysis_note = f"🖥️ INFRASTRUCTURE FAILURE - Node or component failures detected. Use find_errors() to investigate infrastructure issues."
                primary_issue = "infrastructure_failure"  
            elif error_trend[0] > 0:  # high signals in final 5 min
                analysis_note = f"⚠️ CLUSTER ISSUES - Multiple high-priority issues in final moments. Try get_high_signal_logs() for error patterns or find_errors() for specific issues."
                primary_issue = "multiple_issues"
            else:
                analysis_note = f"✅ CLEAN SHUTDOWN - No major issues detected, appears to be normal completion. Use tail_logs() to see final activity."
                primary_issue = "clean_shutdown"
            
            return {
                "log_timing": {
                    "latest_log_time": datetime.fromtimestamp(latest_log_ts).isoformat(),
                    "log_age_hours": round(log_age_hours, 2),
                    "cluster_state": cluster_state,
                    "analysis_note": analysis_note,
                    "primary_issue": primary_issue
                },
                "cluster_health": {
                    "high_signals_final_5min": error_trend[0],
                    "medium_plus_high_final_5min": error_trend[1],
                    "high_signals_final_hour": error_trend[2], 
                    "medium_plus_high_final_hour": error_trend[3],
                    "activity_in_final_5min": error_trend[4],
                    "critical_issues_in_final_hour": critical_issues,
                    "task_failure_detected": task_failure_detected
                },
                "component_status": activity_summary,
                "analyzed_at": datetime.now().isoformat()
            }
        finally:
            conn.close()
    
    try:
        return _run_with_timeout(_impl)
    except FuturesTimeout:
        return {"error": f"get_cluster_status timed out after {TOOL_TIMEOUT_SEC}s"}


# ------------- Helpers for summarization -------------

def _summarize_chunk(text: str) -> str:
    # Grab first matching high or medium signal line as a short summary
    for ln in text.splitlines():
        if HIGH_SIGNAL_PAT.search(ln):
            return ln.strip()[:240]
    for ln in text.splitlines():
        if MEDIUM_SIGNAL_PAT.search(ln):
            return ln.strip()[:240]
    # Fallback: first line
    return text.strip().splitlines()[0][:240] if text.strip() else ""


def _grab_first_signal_line(text: str) -> str:
    for ln in text.splitlines():
        if HIGH_SIGNAL_PAT.search(ln):
            return ln.strip()[:400]
    for ln in text.splitlines():
        if MEDIUM_SIGNAL_PAT.search(ln):
            return ln.strip()[:400]
    return text.strip().splitlines()[0][:400] if text.strip() else ""


_ID_PAT = re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{8,}\b")
_NUM_PAT = re.compile(r"\b\d+\b")
_PATH_PAT = re.compile(r"(/[^/ \t\n]+)+")
_FILELINE_PAT = re.compile(r'File ".*?", line \d+')

def _normalize_signature(text: str) -> str:
    """
    Very simple signature: take lines around the first signal,
    replace numbers/hex/paths/line nos, trim timestamps.
    """
    lines = text.splitlines()
    win: List[str] = []
    found = False
    for i, ln in enumerate(lines):
        if HIGH_SIGNAL_PAT.search(ln) or MEDIUM_SIGNAL_PAT.search(ln):
            # take a small window
            start = max(0, i - 2)
            end = min(len(lines), i + 5)
            win = lines[start:end]
            found = True
            break
    if not found and lines:
        win = lines[:5]

    norm_lines = []
    for ln in win:
        # strip leading timestamps
        ln = TS_PAT.sub("", ln)
        ln = _PATH_PAT.sub("/…", ln)
        ln = _FILELINE_PAT.sub('File "…", line N', ln)
        ln = _ID_PAT.sub("ID", ln)
        ln = _NUM_PAT.sub("N", ln)
        norm_lines.append(ln.strip())
    sig = " | ".join([l for l in norm_lines if l])
    sig = re.sub(r"\s+", " ", sig)
    return sig[:400]


# ------------- Entry point -------------

if __name__ == "__main__":
    # Ensure DB exists & do a quick initial index
    try:
        conn = _connect_db()
        _index_logs(conn, LOG_DIR)
    except Exception as e:
        print(f"[{APP_NAME}] Startup index warning: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # stdio transport for local integration (Cursor, etc.)
    mcp.run()
