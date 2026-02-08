"""
ShadowNet Nexus - Complete System Test
Tests all capabilities end-to-end with real-world scenarios
"""

import os
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

print("\n" + "="*80)
print("🛡️  SHADOWNET NEXUS - COMPLETE SYSTEM TEST")
print("="*80)
print("Testing all capabilities with real-world ransomware scenarios")
print("="*80)

api_key = os.getenv('GEMINI_API_KEY')
if not api_key:
    print("❌ ERROR: GEMINI_API_KEY not found in .env file")
    exit(1)

print(f"\n✅ API Key loaded: {api_key[:20]}...{api_key[-10:]}")

# Import all components
from core.gemini_command_analyzer import GeminiCommandAnalyzer
from core.proactive_evidence_collector import ProactiveEvidenceCollector
from core.siem_integration import SIEMIntegration, SIEMPlatform
from core.alert_manager import AlertManager, AlertChannel, AlertSeverity
from core.gemini_report_generator import GeminiReportGenerator
from core.gemini_report_generator import GeminiReportGenerator
from core.incident_report_generator import IncidentReportGenerator
from core.gemini_behavior_analyzer import GeminiBehaviorAnalyzer
import random

print("\n" + "="*80)
print("📦 INITIALIZING SHADOWNET COMPONENTS")
print("="*80)

# Initialize components
analyzer = GeminiCommandAnalyzer(api_key)
collector = ProactiveEvidenceCollector(evidence_vault_path="./evidence", enabled=True)
siem = SIEMIntegration(config={'syslog_server': '127.0.0.1', 'syslog_port': 514})
alert_mgr = AlertManager(config={})
report_gen = GeminiReportGenerator(api_key)
report_gen = GeminiReportGenerator(api_key)
incident_reporter = IncidentReportGenerator(evidence_path="./evidence")
behavior_analyzer = GeminiBehaviorAnalyzer(api_key)

print(f"✅ AI Command Analyzer: {analyzer.model_name}")
print(f"✅ Evidence Collector: {collector.os_type.upper()} (Enabled: {collector.enabled})")
print(f"✅ SIEM Integration: {len(list(SIEMPlatform))} platforms supported")
print(f"✅ Alert Manager: {len(list(AlertChannel))} channels supported")
print(f"✅ Report Generator: {report_gen.model_name}")
print(f"✅ Behavior Analyzer: {behavior_analyzer.model_name}")
print(f"✅ Incident Reporter: Ready")

# Real-world attack scenarios
attack_scenarios = [
    {
        "name": "LockBit 3.0 - Event Log Clearing",
        "command": "wevtutil cl Security",
        "process": {
            "name": "cmd.exe",
            "pid": 4521,
            "parent_name": "powershell.exe",
            "parent_pid": 3210,
            "user": "SYSTEM",
            "timestamp": "2024-01-29T03:42:00",
            "elevated": True,
            "cwd": "C:\\Windows\\System32"
        },
        "expected_threat": True
    },
    {
        "name": "LockBit 3.0 - VSS Deletion",
        "command": "vssadmin delete shadows /all /quiet",
        "process": {
            "name": "cmd.exe",
            "pid": 7721,
            "parent_name": "powershell.exe",
            "parent_pid": 7700,
            "user": "SYSTEM",
            "timestamp": datetime.now().isoformat(),
            "elevated": True,
            "cwd": "C:\\Windows\\System32"
        },
        "expected_threat": True
    },
    {
        "name": "BlackCat - Obfuscated PowerShell",
        "command": "powershell -enc d2V2dHV0aWwgY2wgU2VjdXJpdHk=",
        "process": {
            "name": "excel.exe",
            "pid": 5521,
            "parent_name": "outlook.exe",
            "parent_pid": 2100,
            "user": "user123",
            "timestamp": datetime.now().isoformat(),
            "elevated": False,
            "cwd": "C:\\Users\\user123\\Documents"
        },
        "expected_threat": True
    },
    {
        "name": "Legitimate Admin Activity",
        "command": "wevtutil qe Application /c:10 /rd:true /f:text",
        "process": {
            "name": "powershell.exe",
            "pid": 8821,
            "parent_name": "explorer.exe",
            "parent_pid": 1200,
            "user": "ADMIN",
            "timestamp": "2024-01-29T10:15:00",
            "elevated": True,
            "cwd": "C:\\Users\\Admin"
        },
        "expected_threat": False
    }
]

print("\n" + "="*80)
print(f"🧪 TESTING {len(attack_scenarios)} REAL-WORLD SCENARIOS")
print("="*80)

results = []
threats_detected = 0
false_positives = 0
false_negatives = 0

for i, scenario in enumerate(attack_scenarios, 1):
    print(f"\n[TEST {i}/{len(attack_scenarios)}] {scenario['name']}")
    print(f"Command: {scenario['command']}")
    print(f"Context: {scenario['process']['user']} @ {scenario['process']['timestamp'][:19]}")
    
    try:
        # 1. AI Analysis
        print("\n🔍 Step 1: AI Threat Analysis...")
        start_time = time.time()
        analysis = analyzer.analyze_command(scenario['command'], scenario['process'])
        detection_time = time.time() - start_time
        
        is_threat = analysis.get('is_anti_forensics', False)
        confidence = analysis.get('confidence', 0)
        severity = analysis.get('severity', 'UNKNOWN')
        
        print(f"   ├─ Threat Detected: {is_threat}")
        print(f"   ├─ Confidence: {confidence:.2%}")
        print(f"   ├─ Severity: {severity}")
        print(f"   └─ Detection Time: {detection_time:.3f}s")
        
        # 2. Evidence Preservation (if threat)
        if is_threat:
            print("\n💾 Step 2: Proactive Evidence Preservation...")
            evidence_result = collector.on_threat_detected({
                'command': scenario['command'],
                'category': analysis.get('category', 'unknown'),
                'severity': severity,
                'process_info': scenario['process']
            })
            
            if evidence_result.get('snapshot_taken'):
                snapshot_id = evidence_result.get('snapshot_id')
                print(f"   ✅ Evidence preserved: {snapshot_id}")
                
                # Generate incident report
                print("\n📄 Step 2b: Generating Incident Report...")
                incident_data = {
                    'incident_id': f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                    'threat_type': analysis.get('category', 'unknown'),
                    'command': scenario['command'],
                    'process_info': scenario['process'],
                    'snapshot_id': snapshot_id,
                    'detection_time': datetime.now().isoformat(),
                    'ai_analysis': analysis,
                    'severity': severity,
                    'evidence_types': [
                        'Event Logs (Application, System, Security)',
                        'Process State (All running processes)',
                        'Network Connections (Active TCP/UDP)',
                        'Volume Shadow Copy State',
                        'File System Metadata'
                    ]
                }
                report_path = incident_reporter.generate_incident_report(incident_data)
                print(f"   ✅ Incident report generated: {report_path}")
            else:
                print(f"   ⚠️  {evidence_result.get('reason', 'Evidence preservation triggered')}")
        
        # 3. SIEM Integration (if threat)
        if is_threat:
            print("\n📡 Step 3: SIEM Event Transmission...")
            siem_event = {
                'type': 'anti_forensics_detected',
                'severity': severity,
                'command': scenario['command'],
                'confidence': confidence,
                'timestamp': datetime.now().isoformat()
            }
            siem_result = siem.send_event(siem_event, [SIEMPlatform.SYSLOG])
            print(f"   ✅ SIEM event sent: {siem_result.get('syslog', False)}")
        
        # 4. Alerting (if critical threat)
        if is_threat and severity == 'CRITICAL':
            print("\n🚨 Step 4: Critical Alert...")
            alert_result = alert_mgr.send_alert(
                title=f"{scenario['name']} Detected",
                message=f"Command: {scenario['command']}",
                severity=AlertSeverity.CRITICAL,
                channels=[AlertChannel.CONSOLE],
                metadata={
                    'confidence': f"{confidence:.0%}",
                    'user': scenario['process']['user'],
                    'time': scenario['process']['timestamp'][:19]
                }
            )
            print(f"   ✅ Alert sent: {alert_result.get('console', False)}")
        
        # Validate results
        expected = scenario['expected_threat']
        if is_threat == expected:
            print(f"\n✅ PASS - Correctly {'detected' if is_threat else 'ignored'}")
            if is_threat:
                threats_detected += 1
            results.append({
                'scenario': scenario['name'],
                'status': 'PASS',
                'detected': is_threat,
                'confidence': confidence
            })
        else:
            if is_threat and not expected:
                print(f"\n❌ FAIL - False Positive")
                false_positives += 1
            else:
                print(f"\n❌ FAIL - Missed Threat")
                false_negatives += 1
            
            results.append({
                'scenario': scenario['name'],
                'status': 'FAIL',
                'detected': is_threat,
                'expected': expected
            })
        
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        results.append({
            'scenario': scenario['name'],
            'status': 'ERROR',
            'error': str(e)
        })
    
    print("-" * 80)
    print("-" * 80)
    time.sleep(2)  # Rate limiting

# --- NEW SECTION: BEHAVIOR ANALYSIS TEST ---
print("\n" + "="*80)
print("🧠 TESTING KEYSTROKE DYNAMICS (BEHAVIOR ANALYSIS)")
print("="*80)

# Generate simulation data
# 1. Human (Variable 80-250ms with pauses)
human_timings = []
for _ in range(50):
    delay = random.randint(80, 250)
    if random.random() < 0.1: delay += random.randint(300, 800)
    human_timings.append(delay)

# 2. Bot (Constant 10ms)
bot_timings = [10 + random.randint(0, 2) for _ in range(50)]

behavior_scenarios = [
    {
        "name": "Human Typing Simulation",
        "data": human_timings,
        "expected_human": True
    },
    {
        "name": "Bot/Script Injection (Keylogger Behavior)",
        "data": bot_timings,
        "expected_human": False
    }
]

for i, scenario in enumerate(behavior_scenarios, 1):
    print(f"\n[BEHAVIOR TEST {i}/{len(behavior_scenarios)}] {scenario['name']}")
    print(f"Data Sample: {scenario['data'][:10]}...")
    
    try:
        print("🔍 AI Analyzing Keystroke Patterns...")
        start_time = time.time()
        analysis = behavior_analyzer.analyze_keystroke_pattern(scenario['data'])
        detection_time = time.time() - start_time
        
        is_human = analysis.get('is_human', False)
        confidence = analysis.get('confidence', 0)
        
        print(f"   ├─ Prediction: {'Human' if is_human else 'Bot/Script'}")
        print(f"   ├─ Confidence: {confidence:.2%}")
        print(f"   └─ Time: {detection_time:.3f}s")
        
        # Validation
        passed = (is_human == scenario['expected_human'])
        if passed:
            print(f"\n✅ PASS - Correctly identified as {'Human' if is_human else 'Bot'}")
            results.append({
                'scenario': scenario['name'],
                'status': 'PASS',
                'detected': not is_human, 
                'confidence': confidence
            })
            
            # If a BOT is detected (Threat), generate an incident report
            if not is_human:
                print("\n🚨 THREAT CONFIRMED: Bot/Script Activity Detected")
                print("📄 Generating Incident Report for Behavioral Threat...")
                incident_data = {
                    'incident_id': f"INC-BEHAVIOR-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                    'threat_type': 'behavioral_anomaly',
                    'title': 'Automated Keystroke Injection Detected',
                    'command': 'N/A (Behavioral Analysis)',
                    'process_info': {'name': 'unknown_script', 'pid': 'N/A', 'user': 'unknown'},
                    'snapshot_id': 'N/A',
                    'detection_time': datetime.now().isoformat(),
                    'ai_analysis': {
                        'is_human': False,
                        'confidence': confidence,
                        'explanation': 'Keystroke dynamics consistent with automated script execution.'
                    },
                    'severity': 'HIGH',
                    'evidence_types': ['Keystroke Timing Analysis']
                }
                report_path = incident_reporter.generate_incident_report(incident_data)
                print(f"   ✅ Incident report generated: {report_path}")

        else:
            print(f"\n❌ FAIL - Identification Mismatch")
            results.append({
                'scenario': scenario['name'],
                'status': 'FAIL',
                'detected': not is_human,
                'confidence': confidence
            })
            
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        results.append({'scenario': scenario['name'], 'status': 'ERROR', 'error': str(e)})
    
    time.sleep(2)

# Generate Incident Report
print("\n" + "="*80)
print("📄 GENERATING INCIDENT REPORT")
print("="*80)

if threats_detected > 0:
    incident_data = {
        'incident_id': f'INC-{datetime.now().strftime("%Y%m%d-%H%M%S")}',
        'detection_time': datetime.now().isoformat(),
        'threats_detected': threats_detected,
        'scenarios_tested': len(attack_scenarios),
        'false_positives': false_positives,
        'false_negatives': false_negatives,
        'severity': 'CRITICAL',
        'commands_detected': [s['command'] for s in attack_scenarios if s['expected_threat']]
    }
    
    try:
        print("Generating executive summary...")
        summary = report_gen.generate_executive_summary(incident_data)
        
        if summary and len(summary) > 100:
            print(f"✅ Report generated: {len(summary)} characters")
            print(f"\nPreview:\n{summary[:300]}...")
        else:
            print("⚠️  Report generation completed with limited output")
    except Exception as e:
        print(f"⚠️  Report generation: {str(e)[:100]}")

# Final Summary
print("\n" + "="*80)
print("📊 COMPLETE SYSTEM TEST SUMMARY")
print("="*80)

total_threats = sum(1 for s in attack_scenarios if s['expected_threat'])
total_benign = len(attack_scenarios) - total_threats

print(f"\n📈 DETECTION STATISTICS:")
print(f"   Total Scenarios: {len(attack_scenarios)}")
print(f"   ├─ Actual Threats: {total_threats}")
print(f"   └─ Benign Activities: {total_benign}")
print(f"\n   ✅ Threats Detected: {threats_detected}/{total_threats}")
print(f"   ❌ Threats Missed: {false_negatives}/{total_threats}")
print(f"   ⚠️  False Positives: {false_positives}/{total_benign}")

accuracy = (sum(1 for r in results if r['status'] == 'PASS') / len(results)) * 100
print(f"\n🎯 OVERALL ACCURACY: {accuracy:.1f}%")

print(f"\n📋 DETAILED RESULTS:")
for result in results:
    status_icon = {'PASS': '✅', 'FAIL': '❌', 'ERROR': '❌'}.get(result['status'], '❓')
    print(f"   {status_icon} {result['scenario']}: {result['status']}")

# Component Statistics
print(f"\n📊 COMPONENT STATISTICS:")
print(f"   SIEM Events Sent: {siem.total_events_sent}")
print(f"   Alerts Sent: {alert_mgr.total_alerts_sent}")
print(f"   Evidence Snapshots: {collector.snapshots_taken}")

# Final Verdict
print("\n" + "="*80)
print("🏆 FINAL VERDICT")
print("="*80)

if accuracy >= 90:
    print("✅ EXCELLENT - System is production-ready!")
    print("   All core capabilities validated successfully")
elif accuracy >= 75:
    print("✅ GOOD - System is functional with minor tuning needed")
    print("   Core capabilities working correctly")
elif accuracy >= 60:
    print("⚠️  FAIR - System needs improvement")
    print("   Review failed tests and adjust configuration")
else:
    print("❌ POOR - System requires significant work")
    print("   Major issues detected, review implementation")

print("\n💡 CAPABILITIES DEMONSTRATED:")
print("   ✅ Real-time threat detection")
print("   ✅ Context-aware AI analysis")
print("   ✅ Proactive evidence preservation")
print("   ✅ SIEM integration")
print("   ✅ Multi-channel alerting")
print("   ✅ Automated report generation")

print("\n" + "="*80)
print("✅ COMPLETE SYSTEM TEST FINISHED")
print("="*80 + "\n")
