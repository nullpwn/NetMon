# Real-Time Traffic Analysis Dashboard

This repository contains a Python-based network traffic sniffer and a web-based dashboard that visualizes real-time traffic data. The dashboard provides insights into various network protocols, packet lengths, system resource usage, and allows users to filter and analyze traffic data interactively.

## Table of Contents

- [Real-Time Traffic Analysis Dashboard](#real-time-traffic-analysis-dashboard)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Features](#features)
  - [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Python Package Installation](#python-package-installation)
  - [Usage](#usage)
    - [Running the Traffic Sniffer](#running-the-traffic-sniffer)
    - [Accessing the Dashboard](#accessing-the-dashboard)
    - [Using the Dashboard](#using-the-dashboard)
      - [Filtering Traffic Data](#filtering-traffic-data)
      - [Exporting Data](#exporting-data)
      - [Stopping the Sniffer](#stopping-the-sniffer)
  - [Troubleshooting](#troubleshooting)

## Overview

The Real-Time Traffic Analysis Dashboard is a tool designed to monitor and analyze network traffic in real-time. It captures packets, categorizes them by protocol, and displays the data through interactive charts and tables. Additionally, it monitors system resource usage such as CPU and RAM, providing a comprehensive view of network activity and system performance.

## Features

- **Real-Time Packet Monitoring:** Capture and display live network traffic data.
- **Interactive Dashboard:** Visualize traffic data with various filtering options.
- **Protocol Analysis:** Breakdown of traffic by protocol (e.g., HTTP, HTTPS, UDP, TCP).
- **System Resource Monitoring:** Track CPU and RAM usage in real-time.
- **Dark Mode:** Switch between light and dark modes for better readability.
- **Data Export:** Download traffic data as CSV for further analysis.

## Installation

### Prerequisites

- **Python 3.7+**: Make sure Python is installed on your system. You can download it from [python.org](https://www.python.org/).
- **pip**: Python's package installer should be available. It comes pre-installed with Python.

### Python Package Installation

To run the traffic sniffer and serve the dashboard, you'll need to install the required Python packages. Use the following command:

```bash
pip install scapy Flask psutil
```

## Usage

### Installing the Requirements

```bash
pip install -r requirements.txt
```

### Running the Traffic Sniffer

To start the traffic sniffer, run the following command:

```bash
python perimica_traffic_sniffer.py
```

### Accessing the Dashboard

After starting the sniffer, you can access the dashboard by opening `real_time_traffic_dashboard.html` in a web browser.

### Using the Dashboard

#### Filtering Traffic Data

You can filter the traffic data by protocol, IP version, source IP, and destination IP using the provided filter options on the dashboard.

#### Exporting Data

To export the traffic data as a CSV file, click the "Download CSV" button on the dashboard.

#### Stopping the Sniffer

To stop the sniffer, press `Ctrl+C` in the terminal where the sniffer is running.

## Troubleshooting

If you encounter issues, ensure that all required Python packages are installed and that your network interface is correctly specified in the sniffer script.
