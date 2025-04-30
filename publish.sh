#!/bin/bash

# Exit on error
set -e

# Remove old dist directory if exists
rm -rf dist

# Build the package
python -m build

# Upload to PyPI
# 请确保已配置好 ~/.pypirc 或已设置环境变量 TWINE_USERNAME/TWINE_PASSWORD

twine upload dist/* 