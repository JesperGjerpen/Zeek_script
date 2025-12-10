## layer1_anomaly_detection.zeek
##
## Purpose:
##   - Use standard Zeek protocol analyzers (conn/http/dns/ssl) to log:
##       * conn.log
##       * http.log  (via http_request)
##       * dns.log   (via dns_request)
##       * ssl.log
##   - Raise notices for:
##       * High-frequency callbacks (many connections/requests from one origin in a short window)
##       * Large data transfers (very large amount of bytes on a single connection)
##
## Usage:
##   - Place this script where Zeek can load it (e.g. /opt/zeek/share/zeek/site/).
##   - Add `@load layer1_anomaly_detection` to local.zeek.
##   - Deploy with `zeekctl deploy`.

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/frameworks/notice

############################
# Custom Notice Types
############################

redef enum Notice::Type += {
    High_Frequency_Callback,
    Large_Data_Transfer
};

############################
# Tunable Parameters
############################

# Time window for counting callbacks per origin host.
const callback_window: interval = 60secs &redef;

# Thresholds for what we treat as "high frequency" callbacks.
const http_callback_threshold: count = 20 &redef;  # HTTP requests per origin IP per window
const dns_callback_threshold:  count = 30 &redef;  # DNS queries per origin IP per window
const ssl_callback_threshold:  count = 15 &redef;  # SSL/TLS connections per origin IP per window

# Large data transfer threshold (total bytes in a connection).
# Default: 10 MB.
const large_transfer_threshold: count = 10 * 1024 * 1024 &redef;

############################
# State Tables
############################

# Count HTTP requests per origin host within 'callback_window'.
global http_callback_counter: table[addr] of count
    &write_expire = callback_window;

# Count DNS queries per origin host within 'callback_window'.
global dns_callback_counter: table[addr] of count
    &write_expire = callback_window;

# Count SSL handshakes per origin host within 'callback_window'.
global ssl_callback_counter: table[addr] of count
    &write_expire = callback_window;

############################
# Helper: Increment + Check
############################

function increment_and_check(
    tbl: table[addr] of count,
    key: addr,
    threshold: count,
    note: Notice::Type,
    msg: string,
    c: connection
    )
    {
    if ( key !in tbl )
        tbl[key] = 0;

    tbl[key] += 1;

    if ( tbl[key] > threshold )
        {
        NOTICE([$note = note,
                $msg  = msg,
                $conn = c]);
        }
    }

############################
# HTTP: High-frequency callbacks
############################

# This event fires when Zeek sees an HTTP request and will also drive http.log.
event http_request(c: connection, method: string, host: string, uri: string, version: string)
    {
    local orig = c$id$orig_h;

    local msg = fmt("High-frequency HTTP callbacks from %s: %s %s%s -> %s",
                    orig, method, host, uri, c$id$resp_h);

    increment_and_check(http_callback_counter,
                        orig,
                        http_callback_threshold,
                        High_Frequency_Callback,
                        msg,
                        c);
    }

############################
# DNS: High-frequency callbacks
############################

# This event drives dns.log entries for queries.
event dns_request(c: connection, msg: dns_msg, query: string)
    {
    local orig = c$id$orig_h;

    local msg_text = fmt("High-frequency DNS callbacks from %s: query=%s",
                         orig, query);

    increment_and_check(dns_callback_counter,
                        orig,
                        dns_callback_threshold,
                        High_Frequency_Callback,
                        msg_text,
                        c);
    }

############################
# SSL: High-frequency callbacks
############################

# Called when an SSL/TLS session is established (drives ssl.log).
event ssl_established(c: connection)
    {
    local orig = c$id$orig_h;

    local msg = fmt("High-frequency SSL/TLS callbacks from %s to %s:%d",
                    orig, c$id$resp_h, c$id$resp_p);

    increment_and_check(ssl_callback_counter,
                        orig,
                        ssl_callback_threshold,
                        High_Frequency_Callback,
                        msg,
                        c);
    }

############################
# Large Data Transfers
############################

# This event runs when Zeek finalizes state for a connection (drives conn.log).
event connection_state_remove(c: connection)
    {
    local ci = c$conn;

    if ( ci?$orig_bytes && ci?$resp_bytes )
        {
        local total: count = ci$orig_bytes + ci$resp_bytes;

        if ( total >= large_transfer_threshold )
            {
            local msg = fmt("Large data transfer on %s:%d -> %s:%d (%d bytes total)",
                            c$id$orig_h, c$id$orig_p,
                            c$id$resp_h, c$id$resp_p,
                            total);

            NOTICE([$note = Large_Data_Transfer,
                    $msg  = msg,
                    $conn = c]);
            }
        }
    }
