# packet_sniffing
Breaking Down Ikusa Logger to Its Core

## Context:
Ikusa Logger is a full-stack application that logs combat messages from Black Desert Online and saves the data in a file. This file can then be manually uploaded to [Ikusa](https://ikusa.site/) to visualize players' performance.

When Ikusa Logger was first released by sch-28 on GitHub, I was immediately impressed. Since Black Desert Online encrypts all its packets, extracting meaningful data is a significant challenge.

After reviewing the original Svelte-based application's source code, I uncovered a crucial Python script buried within, that makes all of this possible. I'd like to highlight the key functionality of data extraction by sharing a refactored version of that key feature, which improves efficiency—reducing the worst-case time complexity from O(n²) to O(n) for better performance.

[Refactored](refactor.py) vs. [Original Code](original.py)

Note: This part of the application doesn’t actually handle file saving; adding this feature to the Python script is trivial and beside the point.

Finally, I want to credit sch-28 for making this project open-source, allowing me to explore TCP packet decryption and refine my understanding of network analysis.

## Requirements
- Python 3.x
- Scapy (`pip install scapy`)

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/ottitsch/packet_sniffing.git
   cd packet_sniffing
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage
Record your Network Traffic via Wireshark, while playing Black Desert Online and then save it as a PCAP file.

### Analyzing the PCAP File
To analyze the PCAP file, run:
```sh
python refactor.py
```
Then, enter the path to the PCAP file when prompted.

## Output
![output](https://github.com/user-attachments/assets/982fb8cc-1060-4f3c-b7a9-aa109cf7467e)


## License
This project is licensed under the MIT License.
