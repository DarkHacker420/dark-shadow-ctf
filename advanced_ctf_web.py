#!/usr/bin/env python3
"""
🌟 DARK-SHADOW CTF Platform - Advanced Beautiful Web Interface
Most advanced and beautiful CTF web platform with modern design
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
import os
import json
import hashlib
import base64
import time
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

class AdvancedWebCTF:
    def __init__(self):
        self.data_dir = Path("ctf_data")
        self.data_dir.mkdir(exist_ok=True)
        self.init_database()
        self.challenges = self.load_advanced_challenges()
    
    def init_database(self):
        """Initialize SQLite database for better performance"""
        self.db_path = self.data_dir / "ctf.db"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    score INTEGER DEFAULT 0,
                    join_date TEXT,
                    last_active TEXT,
                    country TEXT,
                    avatar TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS submissions (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    challenge_id TEXT,
                    submitted_flag TEXT,
                    is_correct BOOLEAN,
                    timestamp TEXT,
                    points_earned INTEGER,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS solved_challenges (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    challenge_id TEXT,
                    solve_time TEXT,
                    points INTEGER,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
    
    def load_advanced_challenges(self):
        """Load advanced challenges with detailed information"""
        return {
            'web_sql_basic': {
                'id': 'web_sql_basic',
                'category': 'Web Security',
                'name': 'SQL Injection Master',
                'description': 'Exploit this vulnerable login form to gain admin access',
                'long_description': 'This challenge simulates a real-world SQL injection vulnerability. Your goal is to bypass the authentication system and gain administrative privileges.',
                'points': 100,
                'flag': 'CTF{sql_1nj3ct10n_m4st3r_2024}',
                'hint': 'Try using SQL comments and OR statements',
                'difficulty': 'Easy',
                'tags': ['sql', 'injection', 'authentication', 'bypass'],
                'author': 'DARK-SHADOW',
                'release_date': '2024-01-01',
                'solve_count': 0,
                'file_url': '/challenges/web/sql_injection.html',
                'writeup_url': None,
                'estimated_time': '10-15 minutes'
            },
            'web_xss_reflected': {
                'id': 'web_xss_reflected',
                'category': 'Web Security',
                'name': 'Reflected XSS Hunter',
                'description': 'Find and exploit a reflected XSS vulnerability',
                'long_description': 'This application contains a reflected XSS vulnerability. Craft a payload that executes JavaScript in the victim\'s browser.',
                'points': 120,
                'flag': 'CTF{xss_r3fl3ct3d_hunt3r}',
                'hint': 'Look for user input that gets reflected back without proper sanitization',
                'difficulty': 'Medium',
                'tags': ['xss', 'javascript', 'client-side', 'reflected'],
                'author': 'DARK-SHADOW',
                'release_date': '2024-01-02',
                'solve_count': 0,
                'file_url': '/challenges/web/xss_reflected.html',
                'writeup_url': None,
                'estimated_time': '15-20 minutes'
            },
            'crypto_aes_weak': {
                'id': 'crypto_aes_weak',
                'category': 'Cryptography',
                'name': 'Weak AES Implementation',
                'description': 'Break this poorly implemented AES encryption',
                'long_description': 'The developers made critical mistakes in their AES implementation. Can you find the weakness and decrypt the secret message?',
                'points': 150,
                'flag': 'CTF{w34k_a3s_1mpl3m3nt4t10n}',
                'hint': 'Check for weak key generation or reused IVs',
                'difficulty': 'Medium',
                'tags': ['aes', 'encryption', 'weak-crypto', 'implementation'],
                'author': 'DARK-SHADOW',
                'release_date': '2024-01-03',
                'solve_count': 0,
                'file_url': '/static/challenges/aes_weak.py',
                'writeup_url': None,
                'estimated_time': '20-30 minutes'
            },
            'crypto_rsa_small_e': {
                'id': 'crypto_rsa_small_e',
                'category': 'Cryptography',
                'name': 'RSA Small Exponent Attack',
                'description': 'Exploit RSA with a small public exponent',
                'long_description': 'This RSA implementation uses a dangerously small public exponent. Use this weakness to recover the original message.',
                'points': 200,
                'flag': 'CTF{rs4_sm4ll_3xp0n3nt_pwn3d}',
                'hint': 'When e=3 and the message is small, you might not need the private key',
                'difficulty': 'Hard',
                'tags': ['rsa', 'small-exponent', 'cube-root', 'number-theory'],
                'author': 'DARK-SHADOW',
                'release_date': '2024-01-04',
                'solve_count': 0,
                'file_url': '/static/challenges/rsa_small_e.txt',
                'writeup_url': None,
                'estimated_time': '30-45 minutes'
            },
            'forensics_steganography': {
                'id': 'forensics_steganography',
                'category': 'Digital Forensics',
                'name': 'Hidden in Plain Sight',
                'description': 'Extract the secret hidden in this image',
                'long_description': 'A secret message has been hidden in this seemingly innocent image using steganography techniques.',
                'points': 130,
                'flag': 'CTF{st3g4n0gr4phy_m4st3r}',
                'hint': 'Try different steganography tools and techniques',
                'difficulty': 'Medium',
                'tags': ['steganography', 'image', 'hidden-data', 'extraction'],
                'author': 'DARK-SHADOW',
                'release_date': '2024-01-05',
                'solve_count': 0,
                'file_url': '/static/challenges/hidden_message.png',
                'writeup_url': None,
                'estimated_time': '15-25 minutes'
            },
            'reverse_crackme': {
                'id': 'reverse_crackme',
                'category': 'Reverse Engineering',
                'name': 'Advanced CrackMe',
                'description': 'Reverse engineer this binary to find the flag',
                'long_description': 'This is a sophisticated crackme challenge that requires advanced reverse engineering skills to solve.',
                'points': 180,
                'flag': 'CTF{r3v3rs3_3ng1n33r1ng_pr0}',
                'hint': 'Use dynamic analysis tools like GDB or static analysis with IDA/Ghidra',
                'difficulty': 'Hard',
                'tags': ['reverse-engineering', 'binary', 'crackme', 'assembly'],
                'author': 'DARK-SHADOW',
                'release_date': '2024-01-06',
                'solve_count': 0,
                'file_url': '/static/challenges/crackme.exe',
                'writeup_url': None,
                'estimated_time': '45-60 minutes'
            },
            'pwn_buffer_overflow': {
                'id': 'pwn_buffer_overflow',
                'category': 'Binary Exploitation',
                'name': 'Stack Overflow Mastery',
                'description': 'Exploit this buffer overflow to gain shell access',
                'long_description': 'This vulnerable C program contains a classic buffer overflow. Craft a payload to control execution flow and spawn a shell.',
                'points': 250,
                'flag': 'CTF{buff3r_0v3rfl0w_pwn3d}',
                'hint': 'You\'ll need to find the offset and control the return address',
                'difficulty': 'Hard',
                'tags': ['buffer-overflow', 'exploitation', 'shellcode', 'stack'],
                'author': 'DARK-SHADOW',
                'release_date': '2024-01-07',
                'solve_count': 0,
                'file_url': '/static/challenges/vuln_program',
                'writeup_url': None,
                'estimated_time': '60-90 minutes'
            },
            'osint_social_media': {
                'id': 'osint_social_media',
                'category': 'OSINT',
                'name': 'Social Media Investigation',
                'description': 'Find the target\'s location using social media',
                'long_description': 'Use open source intelligence techniques to track down the target\'s current location based on their social media activity.',
                'points': 110,
                'flag': 'CTF{051nt_s0c14l_m3d14_pwn}',
                'hint': 'Check timestamps, metadata, and background details in photos',
                'difficulty': 'Medium',
                'tags': ['osint', 'social-media', 'geolocation', 'investigation'],
                'author': 'DARK-SHADOW',
                'release_date': '2024-01-08',
                'solve_count': 0,
                'file_url': '/challenges/osint/social_investigation.html',
                'writeup_url': None,
                'estimated_time': '20-30 minutes'
            },
            'misc_qr_advanced': {
                'id': 'misc_qr_advanced',
                'category': 'Miscellaneous',
                'name': 'QR Code Puzzle Master',
                'description': 'Solve this multi-layered QR code puzzle',
                'long_description': 'This challenge involves multiple QR codes with different encoding schemes and puzzle elements.',
                'points': 90,
                'flag': 'CTF{qr_c0d3_puzzl3_m4st3r}',
                'hint': 'Some QR codes might be damaged or need reconstruction',
                'difficulty': 'Easy',
                'tags': ['qr-code', 'puzzle', 'encoding', 'reconstruction'],
                'author': 'DARK-SHADOW',
                'release_date': '2024-01-09',
                'solve_count': 0,
                'file_url': '/static/challenges/qr_puzzle.png',
                'writeup_url': None,
                'estimated_time': '10-15 minutes'
            }
        }
    
    def get_user_by_username(self, username):
        """Get user from database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0], 'username': row[1], 'score': row[2],
                    'join_date': row[3], 'last_active': row[4],
                    'country': row[5], 'avatar': row[6]
                }
            return None
    
    def create_user(self, username, country='Unknown'):
        """Create new user"""
        with sqlite3.connect(self.db_path) as conn:
            try:
                cursor = conn.execute('''
                    INSERT INTO users (username, score, join_date, last_active, country, avatar)
                    VALUES (?, 0, ?, ?, ?, ?)
                ''', (username, datetime.now().isoformat(), datetime.now().isoformat(), 
                     country, f'https://robohash.org/{username}?set=set4'))
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                return None
    
    def get_leaderboard(self, limit=50):
        """Get leaderboard"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT username, score, 
                       (SELECT COUNT(*) FROM solved_challenges WHERE user_id = users.id) as solved_count,
                       country, avatar
                FROM users 
                ORDER BY score DESC, username ASC 
                LIMIT ?
            ''', (limit,))
            return [{'username': row[0], 'score': row[1], 'solved_count': row[2], 
                    'country': row[3], 'avatar': row[4]} for row in cursor.fetchall()]
    
    def submit_flag(self, user_id, challenge_id, flag):
        """Submit flag with detailed tracking"""
        if challenge_id not in self.challenges:
            return False, "Challenge not found!"
        
        challenge = self.challenges[challenge_id]
        
        with sqlite3.connect(self.db_path) as conn:
            # Check if already solved
            cursor = conn.execute('''
                SELECT id FROM solved_challenges 
                WHERE user_id = ? AND challenge_id = ?
            ''', (user_id, challenge_id))
            
            if cursor.fetchone():
                return False, "Already solved!"
            
            # Record submission
            conn.execute('''
                INSERT INTO submissions (user_id, challenge_id, submitted_flag, is_correct, timestamp, points_earned)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, challenge_id, flag, flag.strip() == challenge['flag'], 
                  datetime.now().isoformat(), challenge['points'] if flag.strip() == challenge['flag'] else 0))
            
            if flag.strip() == challenge['flag']:
                # Mark as solved
                conn.execute('''
                    INSERT INTO solved_challenges (user_id, challenge_id, solve_time, points)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, challenge_id, datetime.now().isoformat(), challenge['points']))
                
                # Update user score
                conn.execute('''
                    UPDATE users SET score = score + ?, last_active = ?
                    WHERE id = ?
                ''', (challenge['points'], datetime.now().isoformat(), user_id))
                
                # Update solve count
                self.challenges[challenge_id]['solve_count'] += 1
                
                return True, f"🎉 Correct! +{challenge['points']} points"
            else:
                return False, "❌ Incorrect flag!"

ctf = AdvancedWebCTF()

@app.route('/')
def index():
    """Advanced home page - Dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = ctf.get_user_by_username(session['username'])
    
    # Get user stats
    with sqlite3.connect(ctf.db_path) as conn:
        cursor = conn.execute('SELECT COUNT(*) FROM solved_challenges WHERE user_id = ?', (user['id'],))
        solved_count = cursor.fetchone()[0]
        
        cursor = conn.execute('''
            SELECT challenge_id, solve_time FROM solved_challenges 
            WHERE user_id = ? ORDER BY solve_time DESC LIMIT 5
        ''', (user['id'],))
        recent_solves = cursor.fetchall()
        
        # Get recent submissions
        cursor = conn.execute('''
            SELECT challenge_id, is_correct, timestamp, points_earned FROM submissions 
            WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10
        ''', (user['id'],))
        recent_submissions = cursor.fetchall()
    
    total_challenges = len(ctf.challenges)
    progress_percentage = int((solved_count / total_challenges) * 100) if total_challenges > 0 else 0
    
    # Calculate rank
    leaderboard = ctf.get_leaderboard()
    user_rank = next((i+1 for i, u in enumerate(leaderboard) if u['username'] == user['username']), 'Unranked')
    
    # Calculate dynamic category progress
    category_progress = {}
    solved_challenge_ids = [solve[0] for solve in recent_solves]  # Get solved challenge IDs
    
    # Get all solved challenges for this user
    with sqlite3.connect(ctf.db_path) as conn:
        cursor = conn.execute('SELECT challenge_id FROM solved_challenges WHERE user_id = ?', (user['id'],))
        all_solved_ids = {row[0] for row in cursor.fetchall()}
    
    for challenge_id, challenge in ctf.challenges.items():
        category = challenge['category']
        if category not in category_progress:
            category_progress[category] = {'solved': 0, 'total': 0, 'percentage': 0}
        category_progress[category]['total'] += 1
        if challenge_id in all_solved_ids:
            category_progress[category]['solved'] += 1
    
    # Calculate percentages
    for category in category_progress:
        if category_progress[category]['total'] > 0:
            category_progress[category]['percentage'] = int(
                (category_progress[category]['solved'] / category_progress[category]['total']) * 100
            )
    
    # Create user object with all needed data
    user_data = {
        'username': user['username'],
        'avatar': user['avatar'],
        'country': user['country'],
        'total_score': user['score'],
        'challenges_solved': solved_count,
        'rank': user_rank,
        'time_spent': '2h 30m',  # Mock data
        'category_progress': category_progress,
        'recent_submissions': [{
            'challenge_name': ctf.challenges.get(sub[0], {'name': 'Unknown'})['name'],
            'correct': sub[1],
            'points': sub[3],
            'timestamp': sub[2]
        } for sub in recent_submissions]
    }
    
    # Prepare challenges data
    challenges_data = []
    for challenge_id, challenge in ctf.challenges.items():
        challenges_data.append({
            'id': challenge_id,
            'name': challenge['name'],
            'description': challenge['description'],
            'category': challenge['category'],
            'points': challenge['points'],
            'difficulty': challenge['difficulty']
        })
    
    return render_template('advanced_dashboard.html',
                         user=user_data,
                         challenges=challenges_data,
                         total_challenges=total_challenges,
                         solved_count=solved_count,
                         progress_percentage=progress_percentage,
                         total_users=len(leaderboard))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Advanced login page"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        country = request.form.get('country', 'Unknown')
        
        if username:
            user = ctf.get_user_by_username(username)
            if not user:
                user_id = ctf.create_user(username, country)
                if user_id:
                    user = ctf.get_user_by_username(username)
                    flash(f'Welcome to DARK-SHADOW CTF, {username}! 🎉', 'success')
                else:
                    flash('Error creating account', 'error')
                    return redirect(url_for('login'))
            else:
                flash(f'Welcome back, {username}! 🚀', 'info')
            
            session['user_id'] = user['id']
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Please enter a valid username', 'error')
    
    return render_template('advanced_login.html')

@app.route('/challenges')
def challenges():
    """Advanced challenges page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Get solved challenges
    with sqlite3.connect(ctf.db_path) as conn:
        cursor = conn.execute('SELECT challenge_id FROM solved_challenges WHERE user_id = ?', (user_id,))
        solved_ids = {row[0] for row in cursor.fetchall()}
    
    solved_count = len(solved_ids)
    total_challenges = len(ctf.challenges)
    progress_percentage = int((solved_count / total_challenges) * 100) if total_challenges > 0 else 0
    total_points = sum(challenge['points'] for challenge in ctf.challenges.values() if challenge['id'] in solved_ids)
    
    # Group challenges by category
    categories = {}
    for challenge_id, challenge in ctf.challenges.items():
        category = challenge['category']
        if category not in categories:
            categories[category] = []
        
        challenge_copy = challenge.copy()
        challenge_copy['solved'] = challenge_id in solved_ids
        challenge_copy['id'] = challenge_id  # Ensure ID is set
        categories[category].append(challenge_copy)
    
    # Sort challenges by difficulty and points
    difficulty_order = {'Easy': 1, 'Medium': 2, 'Hard': 3}
    for category in categories:
        categories[category].sort(key=lambda x: (difficulty_order.get(x['difficulty'], 4), x['points']))
    
    return render_template('advanced_challenges.html', 
                         categories=categories,
                         solved_count=solved_count,
                         total_challenges=total_challenges,
                         progress_percentage=progress_percentage,
                         total_points=total_points)

@app.route('/challenge/<challenge_id>')
def challenge_detail(challenge_id):
    """Advanced challenge detail page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if challenge_id not in ctf.challenges:
        flash('Challenge not found!', 'error')
        return redirect(url_for('challenges'))
    
    user_id = session['user_id']
    challenge = ctf.challenges[challenge_id]
    
    # Check if solved
    with sqlite3.connect(ctf.db_path) as conn:
        cursor = conn.execute('''
            SELECT solve_time FROM solved_challenges 
            WHERE user_id = ? AND challenge_id = ?
        ''', (user_id, challenge_id))
        solve_info = cursor.fetchone()
        
        # Get submission history
        cursor = conn.execute('''
            SELECT submitted_flag, is_correct, timestamp FROM submissions
            WHERE user_id = ? AND challenge_id = ?
            ORDER BY timestamp DESC LIMIT 10
        ''', (user_id, challenge_id))
        submissions = cursor.fetchall()
    
    solved = solve_info is not None
    solve_time = solve_info[0] if solve_info else None
    
    return render_template('advanced_challenge_detail.html',
                         challenge=challenge,
                         solved=solved,
                         solve_time=solve_time,
                         submissions=submissions)

@app.route('/submit_flag', methods=['POST'])
def submit_flag():
    """Advanced flag submission with detailed response"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    user_id = session['user_id']
    challenge_id = request.form['challenge_id']
    flag = request.form['flag']
    
    success, message = ctf.submit_flag(user_id, challenge_id, flag)
    
    response = {'success': success, 'message': message}
    
    if success:
        # Add celebration data
        user = ctf.get_user_by_username(session['username'])
        response['new_score'] = user['score']
        response['celebration'] = True
    
    return jsonify(response)

@app.route('/leaderboard')
def leaderboard():
    """Advanced leaderboard with detailed stats"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    leaderboard_data = ctf.get_leaderboard()
    current_username = session.get('username', '')
    
    # Add additional stats
    with sqlite3.connect(ctf.db_path) as conn:
        # Get total submissions count
        cursor = conn.execute('SELECT COUNT(*) FROM submissions')
        total_submissions = cursor.fetchone()[0]
        
        # Get unique countries count
        cursor = conn.execute('SELECT COUNT(DISTINCT country) FROM users WHERE country IS NOT NULL AND country != "Unknown"')
        total_countries = cursor.fetchone()[0]
        
        # Calculate total hours played (mock data)
        hours_played = len(leaderboard_data) * 2.5  # Average 2.5 hours per user
        
        # Get country statistics
        cursor = conn.execute('''
            SELECT country, COUNT(*) as user_count, SUM(score) as total_points
            FROM users 
            WHERE country IS NOT NULL AND country != "Unknown"
            GROUP BY country
            ORDER BY total_points DESC
            LIMIT 10
        ''')
        country_stats = [{
            'name': row[0],
            'users': row[1],
            'total_points': row[2]
        } for row in cursor.fetchall()]
        
        # Add additional stats for each user
        for user_data in leaderboard_data:
            cursor = conn.execute('''
                SELECT users.username, COUNT(*) as total_solves,
                       AVG(solved_challenges.points) as avg_points
                FROM users 
                LEFT JOIN solved_challenges ON users.id = solved_challenges.user_id
                WHERE users.username = ?
                GROUP BY users.username
            ''', (user_data['username'],))
            stats = cursor.fetchone()
            user_data['avg_points'] = round(stats[2], 1) if stats and stats[2] else 0
            user_data['total_score'] = user_data['score']  # Map for template compatibility
            user_data['challenges_solved'] = user_data['solved_count']
    
    return render_template('advanced_leaderboard.html', 
                         leaderboard=leaderboard_data,
                         all_users=leaderboard_data,
                         current_user=current_username,
                         total_users=len(leaderboard_data),
                         total_countries=total_countries,
                         total_submissions=total_submissions,
                         hours_played=int(hours_played),
                         country_stats=country_stats,
                         total_challenges=len(ctf.challenges))

@app.route('/profile')
def profile():
    """Advanced user profile"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = ctf.get_user_by_username(session['username'])
    user_id = session['user_id']
    
    # Calculate rank
    leaderboard = ctf.get_leaderboard()
    user_rank = next((i+1 for i, u in enumerate(leaderboard) if u['username'] == user['username']), 'Unranked')
    user['rank'] = user_rank
    
    with sqlite3.connect(ctf.db_path) as conn:
        # Get solved challenges with details
        cursor = conn.execute('''
            SELECT sc.challenge_id, sc.solve_time, sc.points
            FROM solved_challenges sc
            WHERE sc.user_id = ?
            ORDER BY sc.solve_time DESC
        ''', (user_id,))
        solved_challenges = cursor.fetchall()
        
        # Get submission stats
        cursor = conn.execute('''
            SELECT COUNT(*) as total_submissions,
                   SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) as correct_submissions
            FROM submissions WHERE user_id = ?
        ''', (user_id,))
        submission_stats = cursor.fetchone()
    
    # Calculate dynamic category progress
    category_progress = {}
    solved_challenge_ids = {sc[0] for sc in solved_challenges}  # Get solved challenge IDs
    
    for challenge_id, challenge in ctf.challenges.items():
        category = challenge['category']
        if category not in category_progress:
            category_progress[category] = {'total': 0, 'solved': 0, 'points': 0}
        category_progress[category]['total'] += 1
        category_progress[category]['points'] += challenge['points']
        
        if challenge_id in solved_challenge_ids:
            category_progress[category]['solved'] += 1
    
    return render_template('advanced_profile.html',
                         user=user,
                         solved_challenges=solved_challenges,
                         submission_stats=submission_stats,
                         category_progress=category_progress,
                         ctf_challenges=ctf.challenges)

def create_advanced_templates():
    """Create beautiful advanced templates"""
    templates_dir = Path("templates")
    templates_dir.mkdir(exist_ok=True)
    
    # Advanced base template with modern design
    base_template = '''<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}🏴‍☠️ DARK-SHADOW CTF{% endblock %}</title>
    
    <!-- Bootstrap 5.3 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome 6 -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <!-- Particles.js -->
    <script src="https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js"></script>
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- Animate.css -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    
    <style>
        :root {
            --primary-color: #00ff88;
            --secondary-color: #ff0080;
            --accent-color: #0080ff;
            --dark-bg: #0a0a0a;
            --card-bg: rgba(20, 20, 20, 0.8);
            --text-primary: #ffffff;
            --text-secondary: #cccccc;
            --success-color: #00ff88;
            --danger-color: #ff4757;
            --warning-color: #ffa502;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Roboto', sans-serif;
            background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 25%, #16213e 50%, #0f3460 100%);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        #particles-js {
            position: fixed;
            width: 100%;
            height: 100%;
            top: 0;
            left: 0;
            z-index: -1;
        }
        
        .navbar {
            background: rgba(0, 0, 0, 0.9) !important;
            backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--primary-color);
            padding: 1rem 0;
        }
        
        .navbar-brand {
            font-family: 'Orbitron', monospace;
            font-weight: 900;
            font-size: 1.8rem;
            background: linear-gradient(45deg, var(--primary-color), var(--accent-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 30px var(--primary-color);
        }
        
        .nav-link {
            color: var(--text-secondary) !important;
            font-weight: 500;
            transition: all 0.3s ease;
            position: relative;
        }
        
        .nav-link:hover {
            color: var(--primary-color) !important;
            text-shadow: 0 0 10px var(--primary-color);
        }
        
        .nav-link::after {
            content: '';
            position: absolute;
            width: 0;
            height: 2px;
            bottom: 0;
            left: 50%;
            background: var(--primary-color);
            transition: all 0.3s ease;
        }
        
        .nav-link:hover::after {
            width: 100%;
            left: 0;
        }
        
        .card {
            background: var(--card-bg);
            border: 1px solid rgba(0, 255, 136, 0.2);
            border-radius: 15px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
            overflow: hidden;
        }
        
        .card:hover {
            transform: translateY(-5px);
            border-color: var(--primary-color);
            box-shadow: 0 15px 40px rgba(0, 255, 136, 0.2);
        }
        
        .challenge-card {
            position: relative;
            cursor: pointer;
        }
        
        .challenge-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-color), var(--accent-color));
        }
        
        .difficulty-easy { border-left: 4px solid var(--success-color); }
        .difficulty-medium { border-left: 4px solid var(--warning-color); }
        .difficulty-hard { border-left: 4px solid var(--danger-color); }
        
        .solved-badge {
            position: absolute;
            top: 10px;
            right: 10px;
            background: var(--success-color);
            color: var(--dark-bg);
            border-radius: 50%;
            width: 30px;
            height: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        
        .btn-primary {
            background: linear-gradient(45deg, var(--primary-color), var(--accent-color));
            border: none;
            border-radius: 25px;
            padding: 10px 25px;
            font-weight: 500;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .btn-primary:hover {
            transform: scale(1.05);
            box-shadow: 0 10px 25px rgba(0, 255, 136, 0.3);
        }
        
        .stats-card {
            text-align: center;
            padding: 2rem;
        }
        
        .stats-number {
            font-family: 'Orbitron', monospace;
            font-size: 3rem;
            font-weight: 900;
            background: linear-gradient(45deg, var(--primary-color), var(--accent-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .progress {
            height: 8px;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.1);
        }
        
        .progress-bar {
            background: linear-gradient(90deg, var(--primary-color), var(--accent-color));
            border-radius: 10px;
        }
        
        .alert {
            border: none;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }
        
        .alert-success {
            background: rgba(0, 255, 136, 0.2);
            color: var(--success-color);
            border: 1px solid var(--success-color);
        }
        
        .alert-danger {
            background: rgba(255, 71, 87, 0.2);
            color: var(--danger-color);
            border: 1px solid var(--danger-color);
        }
        
        .category-header {
            font-family: 'Orbitron', monospace;
            font-weight: 700;
            text-align: center;
            padding: 1rem;
            margin: 2rem 0 1rem 0;
            background: rgba(0, 255, 136, 0.1);
            border-radius: 10px;
            border: 1px solid var(--primary-color);
        }
        
        .leaderboard-item {
            display: flex;
            align-items: center;
            padding: 1rem;
            margin: 0.5rem 0;
            background: var(--card-bg);
            border-radius: 10px;
            transition: all 0.3s ease;
        }
        
        .leaderboard-item:hover {
            background: rgba(0, 255, 136, 0.1);
        }
        
        .rank-badge {
            background: linear-gradient(45deg, var(--primary-color), var(--accent-color));
            color: var(--dark-bg);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            margin-right: 1rem;
        }
        
        .flag-input {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(0, 255, 136, 0.3);
            border-radius: 10px;
            color: var(--text-primary);
            padding: 12px 20px;
            font-family: 'Courier New', monospace;
        }
        
        .flag-input:focus {
            background: rgba(255, 255, 255, 0.15);
            border-color: var(--primary-color);
            box-shadow: 0 0 15px rgba(0, 255, 136, 0.3);
            color: var(--text-primary);
        }
        
        .typing-effect {
            overflow: hidden;
            border-right: 3px solid var(--primary-color);
            white-space: nowrap;
            animation: typing 3.5s steps(40, end), blink-caret 0.75s step-end infinite;
        }
        
        @keyframes typing {
            from { width: 0; }
            to { width: 100%; }
        }
        
        @keyframes blink-caret {
            from, to { border-color: transparent; }
            50% { border-color: var(--primary-color); }
        }
        
        .glow {
            text-shadow: 0 0 10px var(--primary-color);
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -2;
            opacity: 0.1;
        }
        
        .challenge-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 1rem;
        }
        
        .tag {
            background: rgba(0, 255, 136, 0.2);
            color: var(--primary-color);
            border: 1px solid var(--primary-color);
            border-radius: 15px;
            padding: 0.25rem 0.75rem;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .celebration {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            z-index: 9999;
            text-align: center;
            background: rgba(0, 0, 0, 0.9);
            padding: 2rem;
            border-radius: 20px;
            border: 2px solid var(--primary-color);
        }
        
        @media (max-width: 768px) {
            .stats-number { font-size: 2rem; }
            .navbar-brand { font-size: 1.4rem; }
        }
    </style>
</head>
<body>
    <div id="particles-js"></div>
    
    <nav class="navbar navbar-expand-lg fixed-top">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('index') }}">
                <i class="fas fa-skull-crossbones"></i> DARK-SHADOW CTF
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                {% if session.username %}
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('index') }}">
                            <i class="fas fa-home"></i> Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('challenges') }}">
                            <i class="fas fa-flag"></i> Challenges
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('leaderboard') }}">
                            <i class="fas fa-trophy"></i> Leaderboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('profile') }}">
                            <i class="fas fa-user"></i> Profile
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#" onclick="logout()">
                            <i class="fas fa-sign-out-alt"></i> Logout
                        </a>
                    </li>
                </ul>
                {% endif %}
            </div>
        </div>
    </nav>
    
    <div class="container-fluid" style="margin-top: 100px;">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="container">
                    {% for category, message in messages %}
                        <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-dismissible fade show animate__animated animate__bounceInDown">
                            {{ message }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
    
    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Particles.js configuration
        particlesJS('particles-js', {
            particles: {
                number: { value: 80, density: { enable: true, value_area: 800 } },
                color: { value: '#00ff88' },
                shape: { type: 'circle' },
                opacity: { value: 0.5, random: false },
                size: { value: 3, random: true },
                line_linked: { enable: true, distance: 150, color: '#00ff88', opacity: 0.4, width: 1 },
                move: { enable: true, speed: 6, direction: 'none', random: false, straight: false, out_mode: 'out', bounce: false }
            },
            interactivity: {
                detect_on: 'canvas',
                events: { onhover: { enable: true, mode: 'repulse' }, onclick: { enable: true, mode: 'push' }, resize: true },
                modes: { grab: { distance: 400, line_linked: { opacity: 1 } }, bubble: { distance: 400, size: 40, duration: 2, opacity: 8, speed: 3 }, repulse: { distance: 200, duration: 0.4 }, push: { particles_nb: 4 }, remove: { particles_nb: 2 } }
            },
            retina_detect: true
        });
        
        function logout() {
            if (confirm('Are you sure you want to logout?')) {
                window.location.href = '/logout';
            }
        }
        
        // Auto-hide alerts
        setTimeout(() => {
            document.querySelectorAll('.alert').forEach(alert => {
                if (alert.classList.contains('show')) {
                    alert.classList.remove('show');
                }
            });
        }, 5000);
    </script>
    
    {% block scripts %}{% endblock %}
</body>
</html>'''
    
    with open(templates_dir / "advanced_base.html", 'w', encoding='utf-8') as f:
        f.write(base_template)
    
    # Advanced login template
    login_template = '''{% extends "advanced_base.html" %}

{% block title %}Login - DARK-SHADOW CTF{% endblock %}

{% block content %}
<div class="container">
    <div class="row justify-content-center align-items-center min-vh-100">
        <div class="col-lg-6 col-md-8">
            <div class="card animate__animated animate__fadeInUp">
                <div class="card-body p-5">
                    <div class="text-center mb-4">
                        <h1 class="typing-effect" style="font-family: 'Orbitron', monospace;">
                            <i class="fas fa-skull-crossbones glow"></i> DARK-SHADOW CTF
                        </h1>
                        <p class="text-secondary mt-3">Enter the cybersecurity battleground</p>
                    </div>
                    
                    <form method="POST" class="needs-validation" novalidate>
                        <div class="mb-4">
                            <label for="username" class="form-label">
                                <i class="fas fa-user"></i> Hacker Alias
                            </label>
                            <input type="text" class="form-control flag-input" id="username" name="username" 
                                   placeholder="Enter your hacker name..." required>
                            <div class="invalid-feedback">Please choose a username.</div>
                        </div>
                        
                        <div class="mb-4">
                            <label for="country" class="form-label">
                                <i class="fas fa-globe"></i> Country (Optional)
                            </label>
                            <select class="form-select flag-input" id="country" name="country">
                                <option value="Unknown">Select Country</option>
                                <option value="Pakistan">🇵🇰 Pakistan</option>
                                <option value="United States">🇺🇸 United States</option>
                                <option value="United Kingdom">🇬🇧 United Kingdom</option>
                                <option value="Germany">🇩🇪 Germany</option>
                                <option value="France">🇫🇷 France</option>
                                <option value="Japan">🇯🇵 Japan</option>
                                <option value="China">🇨🇳 China</option>
                                <option value="India">🇮🇳 India</option>
                                <option value="Russia">🇷🇺 Russia</option>
                                <option value="Canada">🇨🇦 Canada</option>
                                <option value="Australia">🇦🇺 Australia</option>
                                <option value="Brazil">🇧🇷 Brazil</option>
                                <option value="Other">🌍 Other</option>
                            </select>
                        </div>
                        
                        <button type="submit" class="btn btn-primary w-100 btn-lg">
                            <i class="fas fa-rocket"></i> INITIATE HACK
                        </button>
                    </form>
                    
                    <div class="text-center mt-4">
                        <small class="text-secondary">
                            🏴‍☠️ Join the elite hackers • Solve challenges • Claim the throne
                        </small>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    // Form validation
    (function() {
        'use strict';
        window.addEventListener('load', function() {
            var forms = document.getElementsByClassName('needs-validation');
            var validation = Array.prototype.filter.call(forms, function(form) {
                form.addEventListener('submit', function(event) {
                    if (form.checkValidity() === false) {
                        event.preventDefault();
                        event.stopPropagation();
                    }
                    form.classList.add('was-validated');
                }, false);
            });
        }, false);
    })();
</script>
{% endblock %}'''
    
    with open(templates_dir / "advanced_login.html", 'w', encoding='utf-8') as f:
        f.write(login_template)
    
    print("✨ Advanced beautiful templates created!")

# Challenge file download routes
@app.route('/challenges/web/<filename>')
def download_web_challenge(filename):
    """Serve web challenge files"""
    try:
        challenges_dir = Path("challenges/web")
        challenges_dir.mkdir(parents=True, exist_ok=True)
        file_path = challenges_dir / filename
        if file_path.exists():
            return send_file(file_path)
        else:
            flash('Challenge file not found!', 'error')
            return redirect(url_for('challenges'))
    except Exception as e:
        flash(f'Error accessing file: {str(e)}', 'error')
        return redirect(url_for('challenges'))

@app.route('/challenges/osint/<filename>')
def download_osint_challenge(filename):
    """Serve OSINT challenge files"""
    try:
        challenges_dir = Path("challenges/osint")
        challenges_dir.mkdir(parents=True, exist_ok=True)
        file_path = challenges_dir / filename
        if file_path.exists():
            return send_file(file_path)
        else:
            flash('Challenge file not found!', 'error')
            return redirect(url_for('challenges'))
    except Exception as e:
        flash(f'Error accessing file: {str(e)}', 'error')
        return redirect(url_for('challenges'))

@app.route('/static/challenges/<filename>')
def download_static_challenge(filename):
    """Serve static challenge files"""
    try:
        static_dir = Path("static/challenges")
        static_dir.mkdir(parents=True, exist_ok=True)
        file_path = static_dir / filename
        if file_path.exists():
            return send_file(file_path)
        else:
            flash('Challenge file not found!', 'error')
            return redirect(url_for('challenges'))
    except Exception as e:
        flash(f'Error accessing file: {str(e)}', 'error')
        return redirect(url_for('challenges'))

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out successfully! 👋', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_advanced_templates()
    
    print("🌟 Starting DARK-SHADOW Advanced CTF Web Platform...")
    print("🎯 URL: http://localhost:5000")
    print("🚀 Advanced features: Particles.js, Beautiful UI, Real-time stats")
    print("🇵🇰 Pakistan country support added!")
    
    # Get port from environment variable for deployment
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    app.run(debug=debug, host='0.0.0.0', port=port)
