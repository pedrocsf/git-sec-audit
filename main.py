import argparse
import os
import sys
from datetime import datetime, timezone

from composition_root import AppConfig, build_controllers
from domain.errors import GitSecAuditError
from presentation.controllers.run_options import RunOptions
from presentation.views.console_view import ConsoleView

CACHE_ROOT = os.path.join("~", ".cache", "git-sec-audit")
DEFAULT_BRANCH = "HEAD"
SUBCOMMANDS = ("history", "patch-lag", "secrets", "patterns", "report", "all")
ALL_SEQUENCE = ("patch-lag", "secrets", "patterns", "report")
FAILURE_EXIT_CODE = 1
SUCCESS_EXIT_CODE = 0
GIT_DIRECTORY_NAME = ".git"


def build_parser():
    parser = argparse.ArgumentParser(prog="git-sec-audit")
    parser.add_argument("command", choices=SUBCOMMANDS)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument("--all-parents", action="store_true")
    parser.add_argument("--db")
    parser.add_argument("--output-dir")
    parser.add_argument("--as-of", type=datetime.fromisoformat)
    parser.add_argument("--ignore-revs-file")
    parser.add_argument("--include-authors", action="store_true")
    parser.add_argument("--anonymize-authors", action="store_true")
    parser.add_argument("--gitleaks-bin", default="gitleaks")
    parser.add_argument("--semgrep-bin", default="semgrep")
    return parser


def is_git_repository(path):
    return os.path.isdir(path) and os.path.exists(os.path.join(path, GIT_DIRECTORY_NAME))


def resolve_as_of(as_of):
    if as_of is None:
        return datetime.now(timezone.utc)
    if as_of.tzinfo is None:
        return as_of.replace(tzinfo=timezone.utc)
    return as_of.astimezone(timezone.utc)


def build_config(arguments, repo_path):
    name = os.path.basename(repo_path)
    cache_root = os.path.expanduser(CACHE_ROOT)
    db_path = arguments.db or os.path.join(cache_root, f"{name}.sqlite")
    return AppConfig(
        repo_path=repo_path,
        db_path=os.path.abspath(os.path.expanduser(db_path)),
        gitleaks_binary=arguments.gitleaks_bin,
        semgrep_binary=arguments.semgrep_bin,
    )


def build_options(arguments, repo_path):
    name = os.path.basename(repo_path)
    output_dir = arguments.output_dir or os.path.join(
        os.path.expanduser(CACHE_ROOT), "reports", name
    )
    return RunOptions(
        repository_name=name,
        branch=arguments.branch,
        first_parent=not arguments.all_parents,
        as_of=resolve_as_of(arguments.as_of),
        head_revision=arguments.branch,
        ignore_revs_file=arguments.ignore_revs_file,
        output_dir=os.path.abspath(os.path.expanduser(output_dir)),
        include_authors=arguments.include_authors,
        anonymize_authors=arguments.anonymize_authors,
    )


def run_command(command, controllers, options):
    if command == "history":
        controllers.history.run(
            options.repository_name, options.branch, options.first_parent
        )
    elif command == "patch-lag":
        controllers.patch_lag.run(options)
    elif command == "secrets":
        controllers.secrets.run(options)
    elif command == "patterns":
        controllers.patterns.run(options)
    elif command == "report":
        controllers.report.run(
            options.output_dir,
            options.as_of,
            options.include_authors,
            options.anonymize_authors,
        )


def main(argv=None, overrides=None):
    arguments = build_parser().parse_args(argv)
    repo_path = os.path.abspath(os.path.expanduser(arguments.repo))
    console_view = ConsoleView(sys.stdout)
    if not is_git_repository(repo_path):
        console_view.render_error(f"Não é um repositório git: {repo_path}")
        return FAILURE_EXIT_CODE
    config = build_config(arguments, repo_path)
    options = build_options(arguments, repo_path)
    os.makedirs(os.path.dirname(config.db_path), exist_ok=True)
    controllers = build_controllers(config, overrides, console_view)
    try:
        commands = ALL_SEQUENCE if arguments.command == "all" else (arguments.command,)
        for command in commands:
            run_command(command, controllers, options)
    except GitSecAuditError as error:
        console_view.render_error(str(error))
        return FAILURE_EXIT_CODE
    finally:
        controllers.close()
    return SUCCESS_EXIT_CODE


if __name__ == "__main__":
    raise SystemExit(main())
