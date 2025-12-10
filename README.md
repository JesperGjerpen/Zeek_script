# Zeek_script
This repository contains Zeek scripts designed for use as Layer-1 detection components in a multi-sensor environment. Each sensor VM runs Zeek locally, tags its logs with a unique sensor identifier, and performs lightweight anomaly detection before logs are forwarded to a central RITA instance for Layer-2 analysis.

How this behaves in practice
Standard logs:
Just by loading base/protocols/conn/http/dns/ssl, Zeek already writes:
-	conn.log
-	http.log
-	dns.log
-	ssl.log
This script does not replace those it only adds notice.log entries based on their activity.

High-frequency callbacks:
For each origin IP:
-	Count HTTP requests, DNS queries, and SSL connections within a rolling callback_window (default 60 seconds).
-	If the count exceeds the configured thresholds, a High_Frequency_Callback notice is raised: Visible in notice.log.
Includes the origin IP, destination, and basic context (method/host/URI or query).

Large data transfers:
On connection_state_remove, it sums orig_bytes + resp_bytes. If that exceeds large_transfer_threshold (default 10 MB), a Large_Data_Transfer notice is raised.

How to use it in your Vms:
1.	On each VM, clone/pull the repo into /opt/zeek/custom
2.	Symlink into zeek’s site directory: 
cd /opt/zeek/share/zeek/site
sudo ln -s /opt/zeek/custom/scripts/layer1_anomaly_detection.zeek .
3.	In /opt/zeek/share/zeek/site/local.zeek add: 
@load sensor-id
@load layer1_anomaly_detection
4.	Redeploy:
cd /opt/zeek/bin
sudo ./zeekctl deploy
sudo ./zeekctl status
