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
from flows_to_tensors import flows_to_tensors

def process_flows(flows_df):
    logging.info("Processing flows: %d", len(flows_df))
    node_tensors, adjacency_tensors, _y = flows_to_tensors(flows_df)
    logging.info("Node: %s, Adjacency: %s", node_tensors, adjacency_tensors)

class FlowFileHandler(FileSystemEventHandler):
    def __init__(self):
        self.pos = 0
        logging.info("FlowFileHandler initialized")

    def on_modified(self, event):
        if event.src_path.endswith('.csv') and os.path.exists(event.src_path) and os.path.getsize(event.src_path) > 0:
            logging.info("New flows detected: %s", event.src_path)
            new_flows_df = pd.read_csv(event.src_path)
            new_flows_df = new_flows_df.iloc[self.pos:].copy()
            self.pos += len(new_flows_df)    
            logging.info("Flow count: %d", len(new_flows_df))

            if len(new_flows_df) > 0:
               process_flows(new_flows_df)

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
    args = parser.parse_args()

    output_dir = './output/'
    observer = Observer()
    observer.schedule(FlowFileHandler(), path=output_dir, recursive=False)
    observer.start()

    sniffer = create_sniffer(
        input_interface=args.iface,
        to_csv=True,
        output_file=os.path.join(output_dir, 'out.csv')
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