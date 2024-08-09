# Real-Time Traffic Analysis Dashboard

This repository contains a Python-based network traffic sniffer and a web-based dashboard that visualizes real-time traffic data. The dashboard provides insights into various network protocols, packet lengths, system resource usage, and allows users to filter and analyze traffic data interactively.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Python Package Installation](#python-package-installation)
  - [JavaScript Libraries](#javascript-libraries)
- [Usage](#usage)
  - [Running the Traffic Sniffer](#running-the-traffic-sniffer)
  - [Accessing the Dashboard](#accessing-the-dashboard)
  - [Using the Dashboard](#using-the-dashboard)
    - [Filtering Traffic Data](#filtering-traffic-data)
    - [Exporting Data](#exporting-data)
  - [Stopping the Sniffer](#stopping-the-sniffer)
  - [Troubleshooting](#troubleshooting)
  - [Example](#example)
  - [Advanced Usage](#advanced-usage)
- [Development](#development)
  - [File Structure](#file-structure)
  - [Adding New Features](#adding-new-features)
  - [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

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
