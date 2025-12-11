@load base/protocols/conn
@load base/protocols/mqtt/main
@load base/frameworks/logging

module C2;

export {
    # Custom log record for suspected MQTT C2 flows.
    type C2Record: record {
        ts: time        &log;  # timestamp
        uid: string     &log;  # Zeek connection UID
        id: conn_id     &log;  # 4-tuple (orig/resp IP/port)
        sensor_id: string &log &optional;  # which sensor VM this came from
        reason: string  &log;  # why we flagged it (heuristic description)
    };

    # Custom log stream ID
    redef enum Log::ID += { LOG_C2_MQTT_CANDIDATES };

    # Per-VM sensor identifier (override in local.zeek)
    const c2_sensor_id: string &redef = "unknown-sensor";

    # MQTT ports (plaintext)
    const mqtt_ports: set[port] = { 1883/tcp } &redef;

    # Heuristic 1: long-lived, low-volume MQTT "beacon" flow
    const mqtt_min_beacon_duration: interval = 60secs &redef;
    const mqtt_max_beacon_bytes: count = 20000 &redef; # ~20 KB total bytes

    # Heuristic 2: high-frequency MQTT connects from same origin
    const mqtt_connect_window: interval = 60secs &redef;
    const mqtt_connect_threshold: count = 20 &redef;
}

# Per-origin counter of MQTT connects within a sliding window
global mqtt_connect_counter: table[addr] of count
    &write_expire = C2::mqtt_connect_window;

# Create the custom log stream at startup
event zeek_init()
    {
    Log::create_stream(C2::LOG_C2_MQTT_CANDIDATES,
        [$columns = C2::C2Record,
         $path    = "c2_mqtt_candidates"]);
    }

# Write one C2 candidate entry to c2_mqtt_candidates.log
function log_c2_candidate(c: connection, reason: string)
    {
    local rec: C2::C2Record = [
        $ts        = network_time(),
        $uid       = c$uid,
        $id        = c$id,
        $sensor_id = C2::c2_sensor_id,
        $reason    = reason
    ];

    Log::write(C2::LOG_C2_MQTT_CANDIDATES, rec);
    }

##########################
# Heuristic 2: high-frequency connects
##########################

event connection_established(c: connection)
    {
    # Only care about MQTT flows (standard port or recognized by analyzer)
    if ( !(c$id$resp_p in C2::mqtt_ports || c?$mqtt) )
        return;

    local orig = c$id$orig_h;

    if ( orig !in mqtt_connect_counter )
        mqtt_connect_counter[orig] = 0;

    mqtt_connect_counter[orig] += 1;

    if ( mqtt_connect_counter[orig] > C2::mqtt_connect_threshold )
        {
        local reason = fmt("High-frequency MQTT connects from %s to %s:%d "
                           "(count in %s window: %d)",
                           orig, c$id$resp_h, c$id$resp_p,
                           C2::mqtt_connect_window, mqtt_connect_counter[orig]);

        log_c2_candidate(c, reason);
        }
    }

##########################
# Heuristic 1: long-lived, low-volume MQTT flows
##########################

event connection_state_remove(c: connection)
    {
    # Only care about MQTT flows
    if ( !(c$id$resp_p in C2::mqtt_ports || c?$mqtt) )
        return;

    local ci = c$conn;

    if ( ci?$orig_bytes && ci?$resp_bytes && ci?$duration )
        {
        local total: count = ci$orig_bytes + ci$resp_bytes;

        if ( ci$duration >= C2::mqtt_min_beacon_duration &&
             total       <= C2::mqtt_max_beacon_bytes )
            {
            local reason = fmt("MQTT beacon-like flow %s:%d -> %s:%d "
                               "(dur=%.1fs, bytes=%d)",
                               c$id$orig_h, c$id$orig_p,
                               c$id$resp_h, c$id$resp_p,
                               ci$duration, total);

            log_c2_candidate(c, reason);
            }
        }
    }
  
