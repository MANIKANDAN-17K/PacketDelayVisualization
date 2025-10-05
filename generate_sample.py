#!/usr/bin/env python3
"""Generate sample packet data for testing"""

import pandas as pd
import numpy as np
import os

print("📊 Generating sample packet data...")

n_packets = 1000

# Realistic timestamps
timestamps = np.cumsum(np.random.exponential(0.01, n_packets))

# Protocol distribution
protocols = np.random.choice(
    ['TCP', 'UDP', 'HTTP', 'ICMP', 'DNS'], 
    n_packets, 
    p=[0.4, 0.3, 0.15, 0.1, 0.05]
)

# Packet sizes
lengths = np.random.choice(
    [64, 128, 256, 512, 1024, 1500], 
    n_packets,
    p=[0.2, 0.2, 0.2, 0.2, 0.15, 0.05]
)

# Common ports
ports = np.random.choice([80, 443, 22, 53, 3478, 5222, 8080], n_packets)

data = {
    'Timestamp': timestamps,
    'Protocol': protocols,
    'Source': ['192.168.1.' + str(np.random.randint(1, 255)) for _ in range(n_packets)],
    'Dest': ['8.8.8.' + str(np.random.randint(1, 255)) for _ in range(n_packets)],
    'Length': lengths,
    'DstPort': ports,
    'SrcPort': np.random.randint(1024, 65535, n_packets)
}

df = pd.DataFrame(data)

# Create data directory
os.makedirs('data', exist_ok=True)

# Save
df.to_csv('data/sample_packets.csv', index=False)

print(f"✅ Created: data/sample_packets.csv")
print(f"   Packets: {len(df)}")
print(f"   Duration: {timestamps[-1]:.2f} seconds")
print(f"   Protocols: {df['Protocol'].value_counts().to_dict()}")
print("\n📌 Upload this file in the dashboard!")