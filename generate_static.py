#!/usr/bin/env python3
"""
🌟 DARK-SHADOW CTF Platform - Static Site Generator
Generates a static version of the beautiful web interface for GitHub Pages deployment
"""

import os
import shutil
from pathlib import Path
from advanced_ctf_web import app, ctf

# Configuration
OUTPUT_DIR = Path("docs")

# Clean up previous build
if OUTPUT_DIR.exists():
    shutil.rmtree(OUTPUT_DIR)
OUTPUT_DIR.mkdir()

# Copy static files
shutil.copytree("static", OUTPUT_DIR / "static")

# Create templates
TEMPLATES = {
    "index.html": "/",
    "challenges.html": "/challenges",
    "leaderboard.html": "/leaderboard",
    "profile.html": "/profile",
}

with app.test_request_context():
    for template_name, route in TEMPLATES.items():
        try:
            # Render template
            response = app.test_client().get(route)
            html_content = response.data.decode('utf-8')
            
            # Save to file
            with open(OUTPUT_DIR / template_name, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            print(f"✅ Generated: {template_name}")

        except Exception as e:
            print(f"❌ Error generating {template_name}: {e}")

print("\n✨ Static site generation complete!")

