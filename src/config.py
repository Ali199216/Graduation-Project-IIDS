from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"

DATASET_PATH = DATA_DIR / "NF-UNSW-NB15-v2.csv"
SAMPLED_PATH = DATA_DIR / "dataset_sample.csv"

FEATURES = [
    'L4_SRC_PORT','L4_DST_PORT','PROTOCOL','L7_PROTO',
    'IN_BYTES','IN_PKTS','OUT_BYTES','OUT_PKTS',
    'TCP_FLAGS','CLIENT_TCP_FLAGS','SERVER_TCP_FLAGS',
    'FLOW_DURATION_MILLISECONDS','DURATION_IN',
    'MIN_TTL','MAX_TTL','LONGEST_FLOW_PKT','SHORTEST_FLOW_PKT',
    'MIN_IP_PKT_LEN','MAX_IP_PKT_LEN',
    'SRC_TO_DST_SECOND_BYTES','DST_TO_SRC_SECOND_BYTES',
    'SRC_TO_DST_AVG_THROUGHPUT','DST_TO_SRC_AVG_THROUGHPUT',
    'NUM_PKTS_UP_TO_128_BYTES',
    'TCP_WIN_MAX_IN','TCP_WIN_MAX_OUT',
    'ICMP_TYPE','ICMP_IPV4_TYPE',
    'DNS_QUERY_ID','DNS_QUERY_TYPE','DNS_TTL_ANSWER',
    'FTP_COMMAND_RET_CODE'
]

# User-facing features (the ones shown in the form)
USER_FEATURES = [
    'IPV4_SRC_ADDR', 'IPV4_DST_ADDR',
    'L4_SRC_PORT', 'L4_DST_PORT',
    'PROTOCOL', 'L7_PROTO',
    'IN_BYTES', 'OUT_BYTES',
    'IN_PKTS', 'OUT_PKTS',
    'TCP_FLAGS',
    'FLOW_DURATION_MILLISECONDS',
]

# Anomaly detection thresholds
ANOMALY_THRESHOLD = 0.03
STAGE1_THRESHOLD = 0.5

# Attack type descriptions for the agent
ATTACK_DESCRIPTIONS = {
    "Exploits": "An Exploits attack leverages known vulnerabilities in software/OS to gain unauthorized access or escalate privileges. Common in unpatched systems.",
    "Reconnaissance": "Reconnaissance (Recon) is the information-gathering phase. The attacker scans the network to discover hosts, open ports, services, and potential entry points.",
    "DoS": "Denial of Service (DoS) floods a target with excessive traffic to exhaust resources and make services unavailable to legitimate users.",
    "Generic": "Generic attacks use common techniques that don't fit a single category — often combining multiple methods like brute force, hash collisions, or protocol-level abuse.",
    "Shellcode": "Shellcode attacks inject small executable code (shellcode) into memory to spawn a shell or execute commands on the target machine.",
    "Fuzzers": "Fuzzers send random, malformed, or unexpected data to programs to find crashes, memory leaks, or security holes.",
    "Worms": "Worms are self-replicating malware that spread across networks without user interaction, consuming bandwidth and potentially dropping payloads.",
    "Backdoor": "Backdoor attacks install persistent unauthorized access points into a system, allowing the attacker to return later bypassing authentication.",
    "Analysis": "Analysis attacks involve deeper packet inspection or traffic analysis to extract sensitive data, patterns, or credentials from network communications.",
}

# Common protocol mappings
PROTOCOL_NAMES = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    0: "HOPOPT",
    2: "IGMP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    132: "SCTP",
}

# Common L7 protocol mappings
L7_PROTO_NAMES = {
    0.0: "Unknown",
    7.0: "HTTP",
    91.0: "DNS",
    5.0: "NetBIOS",
    92.0: "HTTPS/TLS",
}