#!/usr/bin/env python3
import queue
import sys
import time
import argparse
import threading
from multiprocessing import cpu_count
from pathlib import Path
from subprocess import Popen, PIPE
from threading import Thread, Lock
from typing import Dict, List, Tuple, Iterator, Set, Optional, NamedTuple, TextIO

SCAN_COMMAND = Tuple[str, Path]


class AlreadyScannedCache(NamedTuple):
    cache: Set[Path]
    lock: Lock


def generate_scan_commands(path: Path, already_scanned: Optional[AlreadyScannedCache] = None) -> Iterator[SCAN_COMMAND]:
    try:
        resolved = path.resolve(strict=True)
        if already_scanned is not None:
            with already_scanned.lock:
                if resolved in already_scanned.cache:
                    return
                already_scanned.cache.add(resolved)
    except (FileNotFoundError, RuntimeError):
        return

    if path.is_file():
        yield ["FILE_SCAN", path]
        return

    yield ["DIR_OPEN", path]

    try:
        for child in path.iterdir():
            if not child.is_dir():
                continue
            for sub in generate_scan_commands(child, already_scanned):
                yield sub
        for child in path.iterdir():
            if not child.is_file():
                continue
            for sub in generate_scan_commands(child, already_scanned):
                yield sub
    except (PermissionError, OSError):
        pass

    yield ["DIR_DONE", path]


def scan(path: Path, log_file: Optional[TextIO]) -> None:
    already_scanned_cache = AlreadyScannedCache(cache=set(), lock=Lock())
    commands: queue.Queue[Tuple[int, SCAN_COMMAND]] = queue.Queue(maxsize=cpu_count() * 20)
    commands_unfinished = Lock()
    commands_unfinished.acquire(blocking=False)
    processed_command_ids: Set[int] = set()
    opened_directories: Dict[Path, Dict[str, Set[Path]]] = {}
    dirs_to_close: queue.Queue[Tuple[int, SCAN_COMMAND]] = queue.Queue(maxsize=cpu_count() * 20)
    log_lines_to_write: queue.Queue[Tuple[TextIO, str]] = queue.Queue(maxsize=cpu_count() * 100)

    counter = {
        'scanned-files': 0,
        'infected-files': 0,
        'time-start': time.time()
    }

    def close_finished_directories() -> Iterator[None]:
        while True:
            try:
                command_id, (_, target) = dirs_to_close.get(block=False)
                while True:
                    if not processed_command_ids or min(processed_command_ids) >= command_id:
                        del opened_directories[target]
                        if target.parent in opened_directories:
                            opened_directories[target.parent]["open"].remove(target)
                            opened_directories[target.parent]["done"].add(target)
                        break
                    yield
            except queue.Empty:
                pass
            yield

    finished_directories_closer = close_finished_directories()

    def thread_commands_generator():
        for i, cmd in enumerate(generate_scan_commands(path, already_scanned_cache)):
            commands.put((i, cmd))
        if commands_unfinished.locked():
            commands_unfinished.release()

    def thread_write_log():
        last_line_length = 0

        while True:
            if not commands_unfinished.locked() and log_lines_to_write.empty():
                alive_threads = sum(map(lambda _: 1, filter(lambda x: x.is_alive(), threading.enumerate())))
                if alive_threads <= 2:
                    break
            try:
                console, line = log_lines_to_write.get(timeout=1)
                is_infected = not line.endswith(': OK')
                spaces = " " * (last_line_length - len(line))
                print(line + spaces, end='\n' if is_infected else '\r', file=console, flush=True)

                if log_file is not None:
                    log_file.write(line + '\n')

                last_line_length = len(line)
            except queue.Empty:
                pass

    def thread_scanning():
        while True:
            if not commands_unfinished.locked():
                break

            try:
                command_id, (command, target) = commands.get(timeout=1)
                processed_command_ids.add(command_id)
                try:
                    if command == "DIR_DONE":
                        dirs_to_close.put((command_id, (command, target)))

                    if command == "DIR_OPEN":
                        if target.parent in opened_directories:
                            opened_directories[target.parent]["open"].add(target)
                        opened_directories[target] = {"open": set(), "done": set()}

                    if command == "FILE_SCAN":
                        p = Popen(["clamdscan", "--fdpass", "--no-summary", target.absolute()],
                                  stdin=PIPE,
                                  stderr=PIPE,
                                  stdout=PIPE
                                  )
                        p.stdin.close()
                        p.wait()
                        stdout = p.stdout.read().decode('utf8').strip()
                        stderr = p.stderr.read().decode('utf8').strip()
                        if stdout:
                            counter['scanned-files'] += 1
                            if not stdout.endswith(': OK'):
                                counter['infected-files'] += 1
                            log_lines_to_write.put((sys.stdout, stdout))
                        if stderr:
                            log_lines_to_write.put((sys.stderr, stderr))

                finally:
                    processed_command_ids.remove(command_id)
                    try:
                        next(finished_directories_closer)
                    except ValueError:
                        pass
            except queue.Empty:
                pass

    threads: List[Thread] = []
    for f in (thread_commands_generator, thread_write_log):
        t = Thread(target=f)
        t.setDaemon(True)
        t.start()
        threads.append(t)

    for _ in range(cpu_count()):
        t = Thread(target=thread_scanning)
        threads.append(t)
        t.start()

    try:
        for t in threads:
            t.join()
        print()
        print('=========================================')
        print(f'Scan competed in {int(time.time() - counter["time-start"])} s')
        print(f'Scanned files: {counter["scanned-files"]}')
        print(f'Infected files: {counter["infected-files"]}')
    except KeyboardInterrupt:
        if commands_unfinished.locked():
            commands_unfinished.release()
        for t in threads:
            t.join()

        while True:
            try:
                next(finished_directories_closer)
                break
            except ValueError:
                time.sleep(0.5)

        def get_closed_directories() -> List[str]:
            r: List[str] = []
            for d, v in opened_directories.items():
                for c in v.get('done', []):
                    r.append(f"{c.absolute()}")
            return r

        print(get_closed_directories())


def main() -> None:
    parser = argparse.ArgumentParser(description='Recursive and fast scan')
    parser.add_argument('path', metavar='path', type=str,
                        help='a path to scan')
    parser.add_argument('--log', dest='log', type=str, help='log file to write information to', default=None)
    args = parser.parse_args()

    log_file: Optional[TextIO] = None
    if args.log is not None:
        log_file = open(args.log, 'w')

    scan(Path(args.path), log_file)

    if log_file is not None:
        log_file.flush()
        log_file.close()


if __name__ == '__main__':
    main()
