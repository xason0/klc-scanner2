#!/bin/bash
# Install system dependencies
apt-get update
apt-get install -y libzbar0 libzbar-dev pkg-config

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt
