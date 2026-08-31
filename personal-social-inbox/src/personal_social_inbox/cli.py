from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from .database import connect, initialize
from .dingtalk_835_adapter import DingTalkAdapterError, export_dingtalk_snapshot
from .dingtalk_generation import (
    DingTalkGenerationError,
    ingest_generation as ingest_dingtalk_generation,
)
from .importer import ImportValidationError, import_manifest
from .monitoring import MonitoringError, scan_signup_deadline
from .paths import database_path, default_data_home
from .qq_doctor import (
    DEFAULT_DEPLOYMENT_ROOT,
    DEFAULT_DOCKER_APP_PATH,
    diagnose_qq_docker,
)
from .qq_generation import (
    QQGenerationError,
    capture_qce_generation,
    ingest_qce_generation,
)
from .qq_qce_adapter import QQAdapterError, export_qce_groups
from .service import InboxService
from .wechat_4_adapter import WechatAdapterError, export_wechat_snapshot
from .wechat_doctor import DEFAULT_APP_PATH, DEFAULT_CONTAINER_PATH, diagnose_wechat
from .wechat_generation import WechatGenerationError, ingest_generation


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="personal-social-inbox",
        description="Explicitly import and inspect local personal message exports.",
    )
    parser.add_argument(
        "--data-home",
        type=Path,
        help="Override the private data directory for this invocation.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init", help="Initialize the local normalized store.")
    import_parser = subparsers.add_parser("import", help="Import one v1 manifest.")
    import_parser.add_argument("manifest", type=Path)
    subparsers.add_parser("stats", help="Show normalized store counts.")
    monitor_parser = subparsers.add_parser(
        "monitor-scan",
        help="Incrementally derive review-required event candidates from imported messages.",
    )
    monitor_parser.add_argument(
        "--profile",
        choices=("signup-deadline-v1",),
        default="signup-deadline-v1",
    )
    monitor_parser.add_argument("--max-messages", type=int, default=50000)
    doctor_parser = subparsers.add_parser(
        "wechat-doctor",
        help="Inspect local WeChat acquisition readiness without reading messages or keys.",
    )
    doctor_parser.add_argument("--app-path", type=Path, default=DEFAULT_APP_PATH)
    doctor_parser.add_argument(
        "--container-path", type=Path, default=DEFAULT_CONTAINER_PATH
    )
    export_parser = subparsers.add_parser(
        "wechat-export",
        help="Export a bounded v1 manifest from separately decrypted WeChat 4.x copies.",
    )
    export_parser.add_argument("snapshot_root", type=Path)
    export_parser.add_argument("output_directory", type=Path)
    export_parser.add_argument("--account-id", required=True)
    export_parser.add_argument("--display-name", default="Personal WeChat")
    export_parser.add_argument("--max-conversations", type=int, default=20)
    export_parser.add_argument("--max-messages", type=int, default=200)
    export_parser.add_argument(
        "--wechat-profile-root",
        type=Path,
        help="Read-only WeChat profile root used to resolve local attachments.",
    )
    export_parser.add_argument(
        "--include-all-groups",
        action="store_true",
        help="Include metadata-only group records outside the bounded session window.",
    )
    ingest_parser = subparsers.add_parser(
        "wechat-ingest-generation",
        help="Verify, export and import one completed incremental WeChat generation.",
    )
    ingest_parser.add_argument("generation_root", type=Path)
    ingest_parser.add_argument("output_directory", type=Path)
    ingest_parser.add_argument("--account-id", required=True)
    ingest_parser.add_argument("--display-name", default="Personal WeChat")
    ingest_parser.add_argument("--max-conversations", type=int, default=20)
    ingest_parser.add_argument("--max-messages", type=int, default=200)
    ingest_parser.add_argument("--wechat-profile-root", type=Path)
    ingest_parser.add_argument("--include-all-groups", action="store_true")
    dingtalk_export_parser = subparsers.add_parser(
        "dingtalk-export",
        help="Export a bounded v1 manifest from a decrypted DingTalk 8.3.5 copy.",
    )
    dingtalk_export_parser.add_argument("snapshot_root", type=Path)
    dingtalk_export_parser.add_argument("output_directory", type=Path)
    dingtalk_export_parser.add_argument("--account-id", required=True)
    dingtalk_export_parser.add_argument("--self-uid", required=True)
    dingtalk_export_parser.add_argument("--display-name", default="Personal DingTalk")
    dingtalk_export_parser.add_argument("--max-conversations", type=int, default=20)
    dingtalk_export_parser.add_argument("--max-messages", type=int, default=200)
    dingtalk_export_parser.add_argument(
        "--media-root",
        type=Path,
        action="append",
        default=[],
        help="Allow exact recorded local attachment paths beneath this read-only root; repeatable.",
    )
    dingtalk_ingest_parser = subparsers.add_parser(
        "dingtalk-ingest-generation",
        help="Verify, export and import one personal DingTalk 8.3.5 generation.",
    )
    dingtalk_ingest_parser.add_argument("generation_root", type=Path)
    dingtalk_ingest_parser.add_argument("output_directory", type=Path)
    dingtalk_ingest_parser.add_argument("--account-id", required=True)
    dingtalk_ingest_parser.add_argument(
        "--self-uid",
        help="Optional explicit UID; otherwise resolve it against the generation account binding.",
    )
    dingtalk_ingest_parser.add_argument("--display-name", default="Personal DingTalk")
    dingtalk_ingest_parser.add_argument("--max-conversations", type=int, default=20)
    dingtalk_ingest_parser.add_argument("--max-messages", type=int, default=200)
    dingtalk_ingest_parser.add_argument(
        "--media-root",
        type=Path,
        action="append",
        default=[],
        help="Allow exact recorded local attachment paths beneath this read-only root; repeatable.",
    )
    qq_parser = subparsers.add_parser(
        "qq-qce-export",
        help="Convert explicitly allowlisted QCE group JSON exports into one v1 manifest.",
    )
    qq_parser.add_argument("output_directory", type=Path)
    qq_parser.add_argument("qce_json", type=Path, nargs="+")
    qq_parser.add_argument("--account-id", required=True)
    qq_parser.add_argument("--display-name", default="Personal QQ")
    qq_parser.add_argument(
        "--group-id",
        action="append",
        required=True,
        help="Allowed QQ group peerUid or peerUin; repeat for multiple groups.",
    )
    qq_parser.add_argument(
        "--since", help="Inclusive ISO 8601 lower bound with timezone."
    )
    qq_parser.add_argument(
        "--until", help="Exclusive ISO 8601 upper bound with timezone."
    )
    qq_doctor_parser = subparsers.add_parser(
        "qq-doctor",
        help="Inspect Docker QCE readiness without reading messages, tokens or QQ session data.",
    )
    qq_doctor_parser.add_argument(
        "--deployment-root", type=Path, default=DEFAULT_DEPLOYMENT_ROOT
    )
    qq_doctor_parser.add_argument(
        "--docker-app-path", type=Path, default=DEFAULT_DOCKER_APP_PATH
    )
    qq_capture_parser = subparsers.add_parser(
        "qq-capture-generation",
        help="Copy allowlisted QCE group JSON and local resources into an immutable generation.",
    )
    qq_capture_parser.add_argument("generation_root", type=Path)
    qq_capture_parser.add_argument("qce_json", type=Path, nargs="+")
    qq_capture_parser.add_argument(
        "--group-id",
        action="append",
        required=True,
        help="Allowed QQ group peerUid or peerUin; repeat for multiple groups.",
    )
    qq_ingest_parser = subparsers.add_parser(
        "qq-ingest-generation",
        help="Verify, normalize and import one completed QCE generation.",
    )
    qq_ingest_parser.add_argument("generation_root", type=Path)
    qq_ingest_parser.add_argument("output_directory", type=Path)
    qq_ingest_parser.add_argument("--account-id", required=True)
    qq_ingest_parser.add_argument("--display-name", default="Personal QQ")
    qq_ingest_parser.add_argument(
        "--group-id",
        action="append",
        required=True,
        help="The same explicit group scope used for capture.",
    )
    qq_ingest_parser.add_argument(
        "--since", help="Inclusive ISO 8601 lower bound with timezone."
    )
    qq_ingest_parser.add_argument(
        "--until", help="Exclusive ISO 8601 upper bound with timezone."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "wechat-doctor":
        result = diagnose_wechat(args.app_path, args.container_path)
    elif args.command == "qq-doctor":
        result = diagnose_qq_docker(args.deployment_root, args.docker_app_path)
    elif args.command == "wechat-export":
        try:
            result = export_wechat_snapshot(
                args.snapshot_root,
                args.output_directory,
                account_id=args.account_id,
                display_name=args.display_name,
                max_conversations=args.max_conversations,
                max_messages_per_conversation=args.max_messages,
                wechat_profile_root=args.wechat_profile_root,
                include_all_groups=args.include_all_groups,
            )
        except (WechatAdapterError, OSError, sqlite3.Error) as exc:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
            return 2
    elif args.command == "dingtalk-export":
        try:
            result = export_dingtalk_snapshot(
                args.snapshot_root,
                args.output_directory,
                account_id=args.account_id,
                self_uid=args.self_uid,
                display_name=args.display_name,
                max_conversations=args.max_conversations,
                max_messages_per_conversation=args.max_messages,
                media_roots=args.media_root,
            )
        except (DingTalkAdapterError, OSError, sqlite3.Error) as exc:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
            return 2
    elif args.command == "qq-qce-export":
        try:
            result = export_qce_groups(
                args.qce_json,
                args.output_directory,
                account_id=args.account_id,
                display_name=args.display_name,
                allowed_group_ids=set(args.group_id),
                since=args.since,
                until=args.until,
            )
        except (QQAdapterError, OSError) as exc:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
            return 2
    elif args.command == "qq-capture-generation":
        try:
            result = capture_qce_generation(
                args.qce_json,
                args.generation_root,
                allowed_group_ids=set(args.group_id),
            )
        except (QQGenerationError, OSError) as exc:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
            return 2
    elif args.command == "qq-ingest-generation":
        home = (args.data_home or default_data_home()).resolve()
        try:
            result = ingest_qce_generation(
                args.generation_root,
                args.output_directory,
                home,
                account_id=args.account_id,
                display_name=args.display_name,
                allowed_group_ids=set(args.group_id),
                since=args.since,
                until=args.until,
            )
        except (
            QQGenerationError,
            QQAdapterError,
            ImportValidationError,
            OSError,
        ) as exc:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
            return 2
    elif args.command == "wechat-ingest-generation":
        home = (args.data_home or default_data_home()).resolve()
        try:
            result = ingest_generation(
                args.generation_root,
                args.output_directory,
                home,
                account_id=args.account_id,
                display_name=args.display_name,
                max_conversations=args.max_conversations,
                max_messages_per_conversation=args.max_messages,
                wechat_profile_root=args.wechat_profile_root,
                include_all_groups=args.include_all_groups,
            )
        except (
            WechatGenerationError,
            WechatAdapterError,
            ImportValidationError,
            OSError,
            sqlite3.Error,
        ) as exc:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
            return 2
    elif args.command == "dingtalk-ingest-generation":
        home = (args.data_home or default_data_home()).resolve()
        try:
            result = ingest_dingtalk_generation(
                args.generation_root,
                args.output_directory,
                home,
                account_id=args.account_id,
                self_uid=args.self_uid,
                display_name=args.display_name,
                max_conversations=args.max_conversations,
                max_messages_per_conversation=args.max_messages,
                media_roots=args.media_root,
            )
        except (
            DingTalkGenerationError,
            DingTalkAdapterError,
            ImportValidationError,
            OSError,
            sqlite3.Error,
        ) as exc:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
            return 2
    else:
        home = (args.data_home or default_data_home()).resolve()
    if args.command == "init":
        connection = connect(database_path(home))
        initialize(connection)
        connection.close()
        result = {"status": "initialized", "data_home": str(home)}
    elif args.command == "import":
        try:
            result = import_manifest(args.manifest, home)
        except (ImportValidationError, OSError) as exc:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
            return 2
    elif args.command == "stats":
        with InboxService(home) as service:
            result = service.stats()
    elif args.command == "monitor-scan":
        try:
            result = scan_signup_deadline(home, max_messages=args.max_messages)
        except (MonitoringError, OSError, sqlite3.Error) as exc:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
            return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0
