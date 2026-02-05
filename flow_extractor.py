import argparse
import logging
import os
import dotenv
dotenv.load_dotenv()

from pyflowmeter.sniffer import create_sniffer
import time
import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

CIC_IDS_2017_COLUMNS = {
    "src_ip": "Source IP",
    "dst_ip": "Destination IP",
    "src_port": "Source Port",
    "dst_port": "Destination Port",
    "protocol": "Protocol",
    "timestamp": "Timestamp",
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "cwe_flag_count": "CWE Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "fwd_seg_size_min": "min_seg_size_forward",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",
    "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
}

def flows_to_cic_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename columns to CIC-IDS-2017 names and add Flow ID if possible."""
    logging.info(f"Renaming columns: {df.columns} to {CIC_IDS_2017_COLUMNS.keys()}")
    df = df.rename(columns={k: v for k, v in CIC_IDS_2017_COLUMNS.items() if k in df.columns})
    if "Source IP" in df.columns and "Destination IP" in df.columns:
        flow_id_cols = ["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol"]
        if all(c in df.columns for c in flow_id_cols):
            df.insert(0, "Flow ID", df.apply(
                lambda r: f"{r['Source IP']}-{r['Destination IP']}-{r['Source Port']}-{r['Destination Port']}-{r['Protocol']}",
                axis=1,
            ))
    return df


class FlowFileHandler(FileSystemEventHandler):
    def __init__(self, output_dir='./output/', to_cic=False):
        self.output_dir = output_dir
        self.to_cic = to_cic

        logging.info("FlowFileHandler initialized: output_dir=%s, to_cic=%s", self.output_dir, self.to_cic)

    def on_modified(self, event):
        if event.src_path.endswith('.csv') and os.path.exists(event.src_path) and os.path.getsize(event.src_path) > 0:
            logging.info("New flows detected: %s (to_cic: %s)", event.src_path, self.to_cic)
            new_flows = pd.read_csv(event.src_path)
            if self.to_cic:
                new_flows = flows_to_cic_columns(new_flows)   
                self.to_cic = False

            new_flows.to_csv(event.src_path, index=False)
            logging.info("New flows detected: %d (CIC columns written to %s)", len(new_flows), event.src_path)

def setup_logging():
    """Configure logging to output/log.txt and stdout."""
    log_dir = "output"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "log.txt")
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    date_fmt = "%Y-%m-%d %H:%M:%S"
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in root.handlers[:]:
        root.removeHandler(h)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(fmt, datefmt=date_fmt))
    root.addHandler(file_handler)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter(fmt, datefmt=date_fmt))
    root.addHandler(stream_handler)

def main():
    setup_logging()
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--iface', default='eth0', help='Network interface to capture (default: eth0)')
    parser.add_argument('--to-cic', action='store_true', help='Convert flow CSV columns to CIC-IDS-2017 names')
    args = parser.parse_args()

    observer = Observer()
    observer.schedule(FlowFileHandler(to_cic=args.to_cic), path='./output/', recursive=False)
    observer.start()

    sniffer = create_sniffer(
        input_interface=args.iface,
        to_csv=True,
        output_file='./output/out.csv'
    )
    sniffer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        sniffer.stop()
    observer.join()

if __name__ == "__main__":
    main()