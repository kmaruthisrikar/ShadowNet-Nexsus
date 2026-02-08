"""
SHADOWNET v4.0 - COMPREHENSIVE REAL-TIME STRESS TEST
This script simulates multiple attack vectors to verify the system's
Real-Time Detection (WMI), AI Analysis, and Forensic Preservation layers.

INSTRUCTIONS:
1. Ensure 'python shadownet_realtime.py' is running in another Administrator terminal.
2. Run this script: 'python shadownet_v4_stress_test.py'
"""

import subprocess
import time
import os
import sys

def print_banner():
    print("="*70)
    print("🛡️  SHADOWNET v4.0 - FULL SYSTEM CAPABILITY TEST")
    print("="*70)
    print("This will trigger multiple suspicious activities to verify detection.")
    print("Watch your ShadowNet terminal for real-time alerts!")
    print("="*70 + "\n")

def run_test(name, command, description):
    print(f"👉 TESTING: {name}")
    print(f"   Description: {description}")
    print(f"   Command: {command}")
    
    try:
        # We use subprocess.Popen to ensure it's a real process creation event for WMI
        # and shell=True to allow command strings to execute.
        # We don't care if the command fails (access denied), detection happens at spawn.
        subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("   ✅ [SENT] Waiting for system response...")
    except Exception as e:
        print(f"   ❌ [FAILED TO DISPATCH]: {e}")
    
    time.sleep(3) # Space out tests to see individual alerts
    print("-" * 50)

def main():
    if sys.platform != "win32":
        print("❌ Error: ShadowNet is currently optimized for Windows environments.")
        return

    print_banner()

    # CATEGORY 1: ANTI-FORENSICS (The Core Target)
    run_test(
        "Log Clearing (wevtutil)", 
        "wevtutil cl Application", 
        "Attempting to wipe System logs to hide tracks."
    )

    run_test(
        "Secure File Deletion (sdelete)", 
        "sdelete.exe -p 3 sensitive_data.txt", 
        "Using forensic wipes to destroy evidence irrecoverably."
    )

    # CATEGORY 2: RANSOMWARE PREPARATION
    run_test(
        "Shadow Copy Deletion", 
        "vssadmin delete shadows /all /quiet", 
        "Classic ransomware move to prevent data recovery."
    )

    run_test(
        "Backup Disabling (bcdedit)", 
        "bcdedit /set {default} recoveryenabled No", 
        "Disabling Windows Recovery environment."
    )

    # CATEGORY 3: CREDENTIAL ACCESS
    run_test(
        "Credential Dumping (Mimikatz)", 
        "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", 
        "Attempting to dump system passwords from memory."
    )

    # CATEGORY 4: OBFUSCATION & STEALTH
    run_test(
        "Encoded PowerShell", 
        "powershell -EncodedCommand JABhID0gMSArIDE=", 
        "Running base64 encoded payload to bypass simple filters."
    )

    # CATEGORY 5: SYSTEM TAMPERING
    run_test(
        "Registry Persistence", 
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Malicious /t REG_SZ /d \"C:\\temp\\evil.exe\"", 
        "Modifying registry for persistence."
    )

    # CATEGORY 6: KEYLOGGER & BEHAVIORAL DETECTION
    print("👉 TESTING: Keylogger Detection (Mechanical Pattern)")
    print("   Description: Simulating bot-driven keystroke injection vs Human typing.")
    
    try:
        import statistics
        from core.gemini_behavior_analyzer import GeminiBehaviorAnalyzer
        from dotenv import load_dotenv
        load_dotenv()
        
        # Scenario A: Mechanical Bot (Low Jitter)
        bot_data = [10, 10, 10, 11, 10, 10, 10, 9, 10, 10]
        # Scenario B: Human (High Jitter)
        human_data = [120, 250, 80, 400, 150, 90, 220, 110]
        
        # 1. Local Statistical Check (Offline Defense)
        print("   [STEP 1] Running Local Jitter Analysis (Offline)...")
        bot_std = statistics.stdev(bot_data)
        if bot_std < 10:
            print(f"   ✅ [LOCAL VERDICT] 🚨 KEYLOGGER DETECTED (StdDev: {bot_std:.2f}ms)")
        else:
            print(f"   ❌ [LOCAL VERDICT] Failed to detect (StdDev: {bot_std:.2f}ms)")
            
        # 2. AI Behavioral Check (Deep Intelligence)
        print("   [STEP 2] Running AI Behavioral Analysis (Gemini)...")
        analyzer = GeminiBehaviorAnalyzer(os.getenv('GEMINI_API_KEY'))
        res = analyzer.analyze_keystroke_pattern(bot_data)
        
        if 'error' in res:
             print(f"   ⚠️  AI Analysis delayed (Quota/Network): {res['error']}")
        else:
            verdict = "🚨 BOT/KEYLOGGER" if not res.get('is_human') else "Human"
            print(f"   ✅ [AI VERDICT] {verdict} (Confidence: {res.get('confidence', 0):.2%})")
            print(f"   Reasoning: {res.get('assessment', 'N/A')[:60]}...")

    except Exception as e:
        print(f"   ⚠️  Behavioral Test Error: {e}")

    print("\n" + "="*70)
    print("🏁 COMPREHENSIVE TEST COMPLETE")
    print("Check the 'evidence/incidents' folder for generated forensic reports.")
    print("="*70)

if __name__ == "__main__":
    main()
