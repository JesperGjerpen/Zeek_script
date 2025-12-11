@load base/protocols/conn
@load base/protocols/mqtt/main
@load base/frameworks/logging
@load base/frameworks/weird

module C2;

export {
    # Enriched C2 candidate log record
    type C2Record: record {
        ts: time         &log;  # timestamp
        uid: string      &log;  # Zeek connection UID
        id: conn_id      &log;  # 4-tuple (orig/resp IP/port)
        sensor_id: string &log &optional;  # set per VM via redef
        anomaly_type: string &log;         # timing-irregularity / header-inconsistency / protocol-misuse
        reason: string   &log;             # human-readable explanation
    };

    # Custom log stream ID
    redef enum Log::ID += { LOG_C2_MQTT_CANDIDATES };

    # Per-VM sensor identifier (override in local.zeek)
    const c2_sensor_id: string &redef = "unknown-sensor";

    # MQTT ports (plaintext)
    const mqtt_ports: set[port] = { 1883/tcp } &redef;

    # Heuristic 1: long-lived, low-volume MQTT "beacon" flow (timing irregularity)
    const mqtt_min_beacon_duration: interval = 60secs &redef;
    const mqtt_max_beacon_bytes: count = 20000 &redef; # ~20 KB total bytes

    # Heuristic 2: high-frequency MQTT connects from same origin (timing irregularity)
    const mqtt_connect_window: interval = 60secs &redef;
    const mqtt_connect_threshold: count = 20 &redef;
}

# Per-origin counter of MQTT connects within a window
global mqtt_connect_counter: table[addr] of count
    &write_expire = C2::mqtt_connect_window;

# Create the custom log stream at startup
event zeek_init()
    {
    Log::create_stream(C2::LOG_C2_MQTT_CANDIDATES,
        [$columns = C2::C2Record,
         $path    = "c2_mqtt_candidates"]);
    }

##########################
# Logging helpers
##########################

# From a connection object
function log_c2_candidate_conn(c: connection, anomaly_type: string, reason: string)
    {
    local rec: C2::C2Record = [
        $ts           = network_time(),
        $uid          = c$uid,
        $id           = c$id,
        $sensor_id    = C2::c2_sensor_id,
        $anomaly_type = anomaly_type,
        $reason       = reason
    ];

    Log::write(C2::LOG_C2_MQTT_CANDIDATES, rec);
    }

# From a conn_id/uid pair (e.g. from weirds)
function log_c2_candidate_uid(uid: string, id: conn_id, anomaly_type: string, reason: string)
    {
    local rec: C2::C2Record = [
        $ts           = network_time(),
        $uid          = uid,
        $id           = id,
        $sensor_id    = C2::c2_sensor_id,
        $anomaly_type = anomaly_type,
        $reason       = reason
    ];

    Log::write(C2::LOG_C2_MQTT_CANDIDATES, rec);
    }

##########################
# TIMING IRREGULARITIES
#  - high-frequency connects
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

        log_c2_candidate_conn(c, "timing-irregularity", reason);
        }
    }

##########################
# TIMING IRREGULARITIES
#  - long-lived, low-volume MQTT beacon flows
#  + HEADER INCONSISTENCIES
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

        # Long-lived, low-volume -> beacon-like
        if ( ci$duration >= C2::mqtt_min_beacon_duration &&
             total       <= C2::mqtt_max_beacon_bytes )
            {
            local reason = fmt("MQTT beacon-like flow %s:%d -> %s:%d "
                               "(dur=%.1fs, bytes=%d)",
                               c$id$orig_h, c$id$orig_p,
                               c$id$resp_h, c$id$resp_p,
                               ci$duration, total);

            log_c2_candidate_conn(c, "timing-irregularity", reason);
            }
        }

    # Header inconsistencies on MQTT CONNECT etc.
    if ( c?$mqtt )
        {
        local mi = c$mqtt;  # MQTT::ConnectInfo

        # Example checks – tune as needed:
        local bad_proto = F;
        if ( mi?$proto_version && mi$proto_version != "" &&
             mi$proto_version != "4" && mi$proto_version != "5" )
            bad_proto = T;

        local bad_client_id = F;
        if ( mi?$client_id && mi$client_id == "" )
            bad_client_id = T;

        if ( bad_proto || bad_client_id )
            {
            local reason = fmt("MQTT header inconsistency on %s:%d -> %s:%d "
                               "(proto_version=%s, client_id='%s')",
                               c$id$orig_h, c$id$orig_p,
                               c$id$resp_h, c$id$resp_p,
                               mi?$proto_version ? mi$proto_version : "<none>",
                               mi?$client_id ? mi$client_id : "<none>");

            log_c2_candidate_conn(c, "header-inconsistency", reason);
            }
        }
    }

##########################
# PROTOCOL MISUSE
#  - MQTT-related weirds
##########################

event weird(w: Weird::Info)
    {
    # Only target MQTT-related weirds (name contains 'mqtt')
    if ( /mqtt/ in w$name )
        {
        local reason = fmt("MQTT protocol misuse/weird '%s'%s",
                           w$name,
                           w?$addl ? fmt(" addl='%s'", w$addl) : "");

        log_c2_candidate_uid(w$uid, w$id, "protocol-misuse", reason);
        }
    }
