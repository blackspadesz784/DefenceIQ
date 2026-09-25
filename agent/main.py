"""DefenceIQ Laptop Security Agent - Main Service Entry Point."""

import argparse
import asyncio
import logging
import os
import sys

# Ensure repository root is in sys.path
_cur_dir = os.path.dirname(os.path.abspath(__file__))
for _p in [_cur_dir, os.path.dirname(_cur_dir), os.path.dirname(os.path.dirname(_cur_dir))]:
    if os.path.isdir(os.path.join(_p, "sentinellayer")) and _p not in sys.path:
        sys.path.insert(0, _p)

from sentinellayer.agent.config.settings import default_settings
from sentinellayer.agent.monitors.process_monitor import ProcessEvent, ProcessMonitor
from sentinellayer.agent.monitors.file_monitor import FileEvent, FileMonitor
from sentinellayer.agent.monitors.network_monitor import NetworkEvent, NetworkMonitor
from sentinellayer.agent.monitors.usb_monitor import USBEvent, USBMonitor

from sentinellayer.agent.detection.static_analysis import StaticAnalyzer
from sentinellayer.agent.detection.yara_engine import YaraEngine
from sentinellayer.agent.detection.reputation_engine import ReputationEngine
from sentinellayer.agent.detection.signature_engine import SignatureEngine
from sentinellayer.agent.ai_engine import RiskScoringEngine, EventCorrelator, Incident, MLAnomalyDetector
from sentinellayer.agent.comms import LocalServer, USBBridge, CloudRelay, BluetoothBridge
from sentinellayer.agent.tamper_protection import SelfMonitor, TamperEvent
from sentinellayer.agent.response import ResponseEngine
from sentinellayer.agent.storage import LocalDatabase

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("DefenceIQ")


async def main():
    parser = argparse.ArgumentParser(description="DefenceIQ Laptop Security Agent")
    parser.add_argument(
        "--demo", action="store_true", help="Run combined monitoring demo mode"
    )
    parser.add_argument(
        "--demo-file", action="store_true", help="Run file monitoring demo mode only"
    )
    parser.add_argument(
        "--demo-net", action="store_true", help="Run network monitoring demo mode only"
    )
    parser.add_argument(
        "--scan", type=str, default=None, help="Run layered detection scan on a target file"
    )
    parser.add_argument(
        "--incidents", action="store_true", help="Display recent stored incidents from SQLite"
    )
    parser.add_argument(
        "--duration", type=int, default=30, help="Duration in seconds for demo mode"
    )
    parser.add_argument(
        "--no-server", action="store_true", help="Disable the local Wi-Fi communications server"
    )
    parser.add_argument(
        "--port", type=int, default=None, help="Port for local Wi-Fi API server (default: 8765)"
    )
    parser.add_argument(
        "--pair", type=str, default=None, help="Pair laptop with mobile app using token (e.g. DIQ-XXXX-XXXX)"
    )
    args = parser.parse_args()

    loop = asyncio.get_running_loop()
    event_queue: asyncio.Queue = asyncio.Queue()

    # Local SQLite Storage
    db = LocalDatabase(db_path=default_settings.db_path)

    if args.incidents:
        print("=" * 70)
        print("  DEFENCEIQ - STORED INCIDENTS (SQLite)")
        print("=" * 70)
        recent = db.get_recent_incidents(limit=20)
        if not recent:
            print("No incidents currently recorded in database.")
        for inc in recent:
            print(f"\n[INCIDENT] {inc['incident_id'][:8]} | Root: {inc['root_process_name']} (PID {inc['root_pid']})")
            print(f"  Score: {inc['risk_score']}/100 [{inc['risk_band']}] | Status: {inc['status']}")
            print(f"  Signals: {inc['signals']}")
            print(f"  Explanation: {inc['explanation']}")
        print("=" * 70)
        return

    logger.info("Starting DefenceIQ Security Agent...")
    logger.info(f"Protection Level: {default_settings.protection_level.value.upper()}")

    # Detection Engines
    static_analyzer = StaticAnalyzer()
    yara_engine = YaraEngine()
    reputation_engine = ReputationEngine()
    signature_engine = SignatureEngine()

    if args.scan:
        logger.info(f"Scanning target file: {args.scan}")
        print("=" * 70)
        print("  DEFENCEIQ - LAYERED DETECTION SCAN")
        print("=" * 70)
        rep = reputation_engine.check_file(args.scan)
        print("\n[1] Hash Reputation Check:")
        print(f"    Verdict: {rep.get('verdict')} | Signals: {rep.get('signals')}")

        yara_res = yara_engine.scan_file(args.scan)
        print("\n[2] YARA Rules Matching:")
        print(f"    Matches: {yara_res.get('has_matches')} | Rules: {[r['rule'] for r in yara_res.get('matched_rules', [])]}")

        static_res = static_analyzer.analyze_file(args.scan)
        print("\n[3] Static Analysis:")
        print(f"    MIME: {static_res.get('mime_type')} | Entropy: {static_res.get('overall_entropy')} | Signals: {static_res.get('signals')}")

        sig_res = signature_engine.scan_file(args.scan)
        print("\n[4] ClamAV Signature Scan:")
        print(f"    Status: {sig_res.get('status')} | Virus: {sig_res.get('virus_name')}")
        print("=" * 70)
        return

    # 1. Process Monitor
    proc_monitor = ProcessMonitor(
        event_bus=event_queue,
        config=default_settings.process_monitor,
    )

    # 2. File Monitor (with integrated Detection Engines)
    file_monitor = FileMonitor(
        event_bus=event_queue,
        config=default_settings.file_monitor,
        loop=loop,
        static_analyzer=static_analyzer,
        yara_engine=yara_engine,
        reputation_engine=reputation_engine,
    )

    # 3. Network Monitor
    net_monitor = NetworkMonitor(
        event_bus=event_queue,
        config=default_settings.network_monitor,
    )

    # 4. USB Monitor (Milestone 2 - Phase 11)
    usb_monitor = USBMonitor(
        event_bus=event_queue,
        config=default_settings.usb_monitor,
        static_analyzer=static_analyzer,
        yara_engine=yara_engine,
        reputation_engine=reputation_engine,
    )

    # Cross-layer telemetry link: if a process spawns with suspicious signals,
    # notify the network monitor so subsequent outbound connections from it are tagged!
    def on_process_event(proc_ev: ProcessEvent):
        if proc_ev.signals and proc_ev.pid:
            net_monitor.record_suspicious_process(proc_ev.pid)

    proc_monitor.register_callback(on_process_event)

    # AI & Scoring Engine
    scoring_engine = RiskScoringEngine(settings=default_settings)
    ml_anomaly_detector = MLAnomalyDetector(auto_train=True)
    correlator = EventCorrelator(scoring_engine=scoring_engine, ml_anomaly_detector=ml_anomaly_detector)

    # Tamper Protection & Agent Self-Monitoring (Milestone 2 - Phase 14)
    self_monitor = SelfMonitor(
        monitored_files=[default_settings.db_path, default_settings.pairing_token_file],
        callback=lambda tamper_ev: correlator.process_event(tamper_ev),
    )

    # Response Engine
    response_engine = ResponseEngine(settings=default_settings)

    # Local Wi-Fi API & WebSocket Alerts Server
    server = None
    if not args.no_server:
        usb_bridge = USBBridge(local_port=args.port or default_settings.port)
        bluetooth_bridge = BluetoothBridge()

        server = LocalServer(
            host=default_settings.host,
            port=args.port or default_settings.port,
            settings=default_settings,
            db=db,
            response_engine=response_engine,
            usb_bridge=usb_bridge,
            bluetooth_bridge=bluetooth_bridge,
        )
        def on_mobile_command(envelope: dict):
            cmd_type = envelope.get("type")
            data = envelope.get("data", {})
            logger.info(f"[MOBILE COMMAND] Received {cmd_type}: {data}")
            if cmd_type == "ROLLBACK":
                inc_id = data.get("incident_id")
                if inc_id:
                    results = response_engine.rollback_incident(inc_id)
                    db.update_incident_status(inc_id, "ROLLED_BACK")
                    logger.info(f"[MOBILE COMMAND] Rollback executed for {inc_id}: {results}")
            elif cmd_type == "SET_PROTECTION_LEVEL":
                level = data.get("level")
                if level:
                    try:
                        from sentinellayer.agent.config.settings import ProtectionLevel
                        new_lvl = ProtectionLevel(level.lower())
                        default_settings.protection_level = new_lvl
                        logger.info(f"[MOBILE COMMAND] Protection level updated to {new_lvl}")
                    except ValueError:
                        pass

        cloud_token = args.pair.strip().upper() if args.pair else server.pairing_token
        cloud_relay = CloudRelay(
            pairing_token=cloud_token,
            enabled=True,
            on_command_callback=on_mobile_command,
        )
        server.cloud_relay = cloud_relay
        cloud_relay.publish_handshake()
        cloud_relay.start_listener()
        server.process_monitor = proc_monitor
        server.network_monitor = net_monitor

    def on_incident_update(inc: Incident):
        db.save_incident(inc)
        if server:
            try:
                running_loop = asyncio.get_running_loop()
                running_loop.create_task(server.broadcast_incident(inc))
            except RuntimeError:
                asyncio.run_coroutine_threadsafe(server.broadcast_incident(inc), loop)

        if inc.score_result and inc.score_result.score > 0:
            logger.warning(
                f"[INCIDENT] ID: {inc.incident_id[:8]} | Root: {inc.root_process_name} (PID {inc.root_pid}) | "
                f"Score: {inc.score_result.score}/100 [{inc.score_result.band}] | Signals: {inc.signals}"
            )
            if inc.score_result.band in ("ORANGE", "RED"):
                actions = response_engine.handle_incident(inc)
                for act in actions:
                    db.save_action(act)
                    if server:
                        try:
                            running_loop = asyncio.get_running_loop()
                            running_loop.create_task(server.broadcast_action(act))
                        except RuntimeError:
                            asyncio.run_coroutine_threadsafe(server.broadcast_action(act), loop)
                logger.error(
                    f"[CONTAINMENT] Executed {len(actions)} containment action(s) for Incident {inc.incident_id[:8]}: "
                    f"{[a.action_type for a in actions]}"
                )

    correlator.register_incident_callback(on_incident_update)

    if args.demo_file:
        logger.info(f"Running File Monitor DEMO for {args.duration} seconds...")
        await file_monitor.run_demo(duration_seconds=args.duration)
        return

    if args.demo_net:
        logger.info(f"Running Network Monitor DEMO for {args.duration} seconds...")
        await net_monitor.run_demo(duration_seconds=args.duration)
        return

    if args.demo:
        logger.info(f"Running Combined Telemetry & Correlator DEMO for {args.duration} seconds...")
        print("=" * 70)
        print("  DEFENCEIQ - LIVE TELEMETRY & RISK SCORING DEMO")
        print("=" * 70)
        print("Listening for events across all monitors and calculating live risk scores...")
        print("=" * 70)

        def print_event(event):
            incident = correlator.process_event(event)
            print(f"\n[+] LIVE EVENT: {type(event).__name__}")
            if incident and incident.score_result and incident.score_result.score > 0:
                print(f"    >>> CORRELATED INCIDENT SCORE: {incident.score_result.score}/100 [{incident.score_result.band}]")
                print(f"    >>> Contributing Signals: {incident.signals}")
            else:
                print(f"    Status: Processed (Score: 0/100 [GREEN])")

        proc_monitor.register_callback(print_event)
        file_monitor.register_callback(print_event)
        net_monitor.register_callback(print_event)
        usb_monitor.register_callback(print_event)

        proc_task = asyncio.create_task(proc_monitor.start())
        net_task = asyncio.create_task(net_monitor.start())
        usb_task = asyncio.create_task(usb_monitor.start())
        file_monitor.start()
        self_monitor.start()

        if server:
            server.start_in_thread()

        try:
            await asyncio.sleep(args.duration)
        finally:
            if server:
                server.stop()
            self_monitor.stop()
            proc_monitor.stop()
            file_monitor.stop()
            net_monitor.stop()
            usb_monitor.stop()
            proc_task.cancel()
            net_task.cancel()
            usb_task.cancel()
            print("\n" + "=" * 70)
            print("  DEMO COMPLETE")
            print("=" * 70)
        return

    # Production background service loop
    logger.info("Starting Process, File, Network, and USB Monitors, and Event Correlator...")
    proc_task = asyncio.create_task(proc_monitor.start())
    net_task = asyncio.create_task(net_monitor.start())
    usb_task = asyncio.create_task(usb_monitor.start())
    file_monitor.start()
    self_monitor.start()

    if server:
        server.start_in_thread()

    try:
        while True:
            event = await event_queue.get()
            db.save_event(event)
            correlator.process_event(event)
            if isinstance(event, ProcessEvent):
                logger.info(
                    f"[BUS:PROCESS] {event.event_type} | PID: {event.pid} | {event.name} | Signals: {event.signals}"
                )
            elif isinstance(event, FileEvent):
                logger.info(
                    f"[BUS:FILE] {event.event_type} | {event.file_name} | Ext: {event.extension} | Entropy: {event.entropy} | Signals: {event.signals}"
                )
            elif isinstance(event, NetworkEvent):
                logger.info(
                    f"[BUS:NETWORK] {event.event_type} | PID: {event.pid} ({event.process_name}) -> {event.remote_address} | Signals: {event.signals}"
                )
            elif isinstance(event, USBEvent):
                logger.warning(
                    f"[BUS:USB] {event.event_type} | Drive: {event.drive_path} | Signals: {event.signals}"
                )
            event_queue.task_done()
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutting down DefenceIQ agent...")
        if server:
            server.stop()
        self_monitor.stop()
        proc_monitor.stop()
        file_monitor.stop()
        net_monitor.stop()
        usb_monitor.stop()
        proc_task.cancel()
        net_task.cancel()
        usb_task.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nDefenceIQ stopped by user.")
