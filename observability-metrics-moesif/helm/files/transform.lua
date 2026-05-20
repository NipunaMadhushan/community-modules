-- Parse key="value" and key=value pairs from a Ballerina logfmt line.
-- Field names may contain dots and hyphens (e.g. http.status_code_group).
--
-- A character-by-character parser is used instead of gmatch patterns because
-- Ballerina's logfmt encoder escapes special characters inside quoted values
-- (e.g. \" for a literal double-quote, \\ for a literal backslash). The
-- previous regex pattern [^"]* stopped at the first " regardless of whether
-- it was preceded by a backslash, silently truncating any value that contained
-- an escaped quote.
local function parse_logfmt(line)
    local fields = {}
    local pos    = 1
    local len    = #line

    while pos <= len do
        -- Skip whitespace between pairs.
        while pos <= len and line:sub(pos, pos) == " " do
            pos = pos + 1
        end
        if pos > len then break end

        -- Read key name (up to '=' or whitespace).
        local key_start = pos
        while pos <= len and line:sub(pos, pos) ~= "=" and line:sub(pos, pos) ~= " " do
            pos = pos + 1
        end
        local key = line:sub(key_start, pos - 1)
        if key == "" then break end

        if pos > len or line:sub(pos, pos) ~= "=" then
            fields[key] = ""
        else
            pos = pos + 1  -- consume '='
            if pos <= len and line:sub(pos, pos) == '"' then
                -- Quoted value: walk character by character so that escape
                -- sequences (\" and \\) inside the value are handled correctly.
                pos = pos + 1  -- consume opening '"'
                local parts = {}
                while pos <= len do
                    local c = line:sub(pos, pos)
                    if c == "\\" and pos < len then
                        local nc = line:sub(pos + 1, pos + 1)
                        -- Unescape \" -> " and \\ -> \; keep other sequences as-is.
                        parts[#parts + 1] = (nc == '"' or nc == "\\") and nc or (c .. nc)
                        pos = pos + 2
                    elseif c == '"' then
                        pos = pos + 1  -- consume closing '"'
                        break
                    else
                        parts[#parts + 1] = c
                        pos = pos + 1
                    end
                end
                fields[key] = table.concat(parts)
            else
                -- Unquoted value: read until the next whitespace.
                local val_start = pos
                while pos <= len and line:sub(pos, pos) ~= " " do
                    pos = pos + 1
                end
                fields[key] = line:sub(val_start, pos - 1)
            end
        end
    end

    return fields
end

-- Structural logfmt fields that exist on every line but carry no metric
-- signal — excluded from the metadata payload sent to Moesif.
local EXCLUDE = {
    time=true, level=true, module=true, message=true, logger=true
}

function transform(tag, timestamp, record)
    local log_line = record["log"]
    if not log_line then
        return -1, 0, 0
    end

    -- Trim trailing newline added by Docker JSON log format.
    log_line = log_line:gsub("%s+$", "")

    local f = parse_logfmt(log_line)

    -- Safety check: only process metric log lines.
    if f["logger"] ~= "metrics" then
        return -1, 0, 0
    end

    -- Read app ID from pod annotation for rewrite_tag routing.
    local k8s         = record["kubernetes"] or {}
    local annotations = k8s["annotations"] or {}
    local app_id      = annotations["moesif-app-id"] or ""

    local method = f["http.method"]
    local url    = f["http.url"]

    -- action_name: "METHOD /path" for HTTP services; function name for others
    -- (e.g. FTP listener emits src.function.name="onFileChange").
    local action_name
    if method and method ~= "" and url and url ~= "" then
        action_name = method .. " " .. url
    else
        action_name = f["src.function.name"] or f["entrypoint.function.name"] or "unknown"
    end

    -- request.uri / request.verb: fall back to function-level identifiers when
    -- HTTP fields are absent (e.g. FTP client calls, event handler invocations).
    -- Use the protocol field from the log line (e.g. "http") rather than
    -- hardcoding "https", and apply it consistently to both URI forms.
    local protocol = f["protocol"] or "http"
    local req_uri
    if url and url ~= "" then
        req_uri = protocol .. "://" .. (f["src.object.name"] or "service") .. url
    else
        local svc = f["entrypoint.service.name"] or f["src.object.name"] or "service"
        local fn  = f["src.function.name"] or "invoke"
        req_uri   = protocol .. "://" .. svc .. "/" .. fn
    end

    local req_verb = method or f["src.function.name"] or "INVOKE"

    -- Build metadata dynamically: include every parsed logfmt field whose
    -- value is non-empty. Dots and hyphens in key names are normalised to
    -- underscores for consistent JSON output across HTTP and FTP metrics.
    local metadata = {}
    for k, v in pairs(f) do
        if not EXCLUDE[k] and v ~= "" then
            local norm = k:gsub("[%.%-]", "_")
            if k == "response_time_seconds" then
                metadata[norm] = tonumber(v) or 0
            else
                metadata[norm] = v
            end
        end
    end

    -- moesif_app_id must be at the top level so rewrite_tag can read it
    -- via $moesif_app_id and use it as the new Fluent Bit tag. The tag is
    -- then copied into X-Moesif-Application-Id by header_tag in the output.
    -- record_modifier removes it from the top level before the record is sent.
    local new_record = {
        action_name   = action_name,
        moesif_app_id = app_id,
        request       = {
            time = f["time"],
            uri  = req_uri,
            verb = req_verb,
        },
        metadata = metadata,
    }

    return 1, timestamp, new_record
end
