import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta

def generate_traffic(num_rows=1500, output_file='data/sample_ddos.csv'):
    """
    Generates synthetic traffic data simulating normal and various DDoS patterns.
    Labels:
      0: Normal
      1: SYN Flood
      2: UDP Flood
      3: HTTP Get Flood
      4: DNS Amplification
    """
    print(f"Generating {num_rows} rows of multi-class traffic data...")
    
    data = []
    base_time = datetime.now()
    
    for i in range(num_rows):
        timestamp = base_time + timedelta(seconds=i*5) # 5 second intervals
        
        # We partition the dataset to contain strong representation of all states
        if i < 800:
            # 1. Normal traffic (0)
            label = 0
            src_ip = f"192.168.1.{random.randint(2, 50)}"
            dst_ip = "10.0.0.1"
            packets_per_sec = int(np.random.normal(500, 100))
            bytes_per_sec = int(np.random.normal(20000, 5000))
            flow_count = int(np.random.normal(10, 2))
        elif i < 975:
            # 2. SYN Flood (1) - High PPS, Low packet size, High flow count
            label = 1
            src_ip = f"185.{random.randint(10,254)}.{random.randint(10,254)}.{random.randint(1,254)}"
            dst_ip = "10.0.0.1"
            packets_per_sec = int(np.random.normal(70000, 5000))
            bytes_per_sec = int(np.random.normal(4500000, 300000)) # ~64B packet
            flow_count = int(np.random.normal(2000, 200))
        elif i < 1150:
            # 3. UDP Flood (2) - High BPS, Moderate PPS, Lower flow count, Large packet size
            label = 2
            src_ip = f"45.{random.randint(10,254)}.{random.randint(10,254)}.{random.randint(1,254)}"
            dst_ip = "10.0.0.1"
            packets_per_sec = int(np.random.normal(40000, 3000))
            bytes_per_sec = int(np.random.normal(50000000, 4000000)) # ~1250B packet
            flow_count = int(np.random.normal(150, 20))
        elif i < 1325:
            # 4. HTTP Get Flood (3) - Moderate PPS/BPS, Very High flow count
            label = 3
            src_ip = f"103.{random.randint(10,254)}.{random.randint(10,254)}.{random.randint(1,254)}"
            dst_ip = "10.0.0.1"
            packets_per_sec = int(np.random.normal(10000, 1000))
            bytes_per_sec = int(np.random.normal(5000000, 500000)) # ~500B packet
            flow_count = int(np.random.normal(5000, 400))
        else:
            # 5. DNS Amplification (4) - High BPS, Moderate PPS, Very Large packet size
            label = 4
            src_ip = f"91.{random.randint(10,254)}.{random.randint(10,254)}.{random.randint(1,254)}"
            dst_ip = "10.0.0.1"
            packets_per_sec = int(np.random.normal(30000, 2500))
            bytes_per_sec = int(np.random.normal(45000000, 3000000)) # ~1500B packet
            flow_count = int(np.random.normal(60, 5))

        # Ensure values don't go negative
        packets_per_sec = max(1, packets_per_sec)
        bytes_per_sec = max(1, bytes_per_sec)
        flow_count = max(1, flow_count)

        data.append([timestamp, src_ip, dst_ip, packets_per_sec, bytes_per_sec, flow_count, label])

    df = pd.DataFrame(data, columns=['timestamp', 'src_ip', 'dst_ip', 'packets_per_sec', 'bytes_per_sec', 'flow_count', 'label'])
    
    # Save to CSV
    df.to_csv(output_file, index=False)
    print(f"Data successfully saved to {output_file}")
    return df

if __name__ == "__main__":
    generate_traffic()

