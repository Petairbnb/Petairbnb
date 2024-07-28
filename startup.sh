#!/bin/bash

# Make sure the script stops on first error
set -e

# Install dependencies
pip install -r requirements.txt

# Create the database tables
python -c "from app import db; db.create_all()"

# Start Gunicorn
gunicorn --bind=0.0.0.0 --timeout 600 app:app
