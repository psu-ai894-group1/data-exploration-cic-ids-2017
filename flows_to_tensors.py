import pandas as pd
import numpy as np
import logging
from sklearn.preprocessing import StandardScaler
import tensorflow as tf


def flows_to_tensors(flows_df):
    """
    Convert flows from pyflowmeter format to tensors for use in GNNs.

    This style of graph uses flows as nodes and edges based on behaviors as is described in:
    https://link.springer.com/article/10.1186/s42400-024-00296-8
    """
    flow_count = len(flows_df)
    logging.info(f"Flow count: {flow_count}")   

    feature_names = [
        'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts',
        'totlen_fwd_pkts', 'totlen_bwd_pkts',
        'fwd_pkt_len_mean', 'bwd_pkt_len_mean',
        'flow_byts_s', 'flow_pkts_s',
        'fwd_iat_mean', 'bwd_iat_mean'
    ]

    available_feature_names = [f for f in feature_names if f in flows_df.columns]
    logging.info(f"Available feature names: {available_feature_names}")

    node_features = flows_df[available_feature_names].values
    scaler = StandardScaler()
    node_features = scaler.fit_transform(node_features)
    node_features = tf.constant(node_features, dtype=tf.float32)

    edges = create_flow_edges(flows_df)
    adjacency = create_sparse_adjacency(edges, flow_count)

    return node_features, adjacency, None

def create_flow_edges(flows_df):
    return None

def create_sparse_adjacency(edges, flow_count):
    return None