#!/usr/bin/env python3
import json
import queue
import sys
import time
import argparse
import threading
from multiprocessing import cpu_count
from pathlib import Path
from subprocess import Popen, PIPE, TimeoutExpired
from threading import Thread, Lock, Event
from typing import List, Tuple, Iterator, Set, Optional, NamedTuple, TextIO

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
                    print(f"{path}: SKIP")
                    return
                already_scanned.cache.add(resolved)
    except (FileNotFoundError, RuntimeError):
        return

    if path.is_file():
        yield ["FILE_SCAN", path]
        return

    yield ["DIR_OPEN", path]

    try:
        for child in sorted(path.iterdir(), key=lambda x: 0 if x.is_dir() else 1):
            for sub in generate_scan_commands(child, already_scanned):
                yield sub
    except (PermissionError, OSError):
        pass

    yield ["DIR_DONE", path]


def scan(path: Path, log_file: Optional[TextIO], file_cache: Optional[Path] = None) -> None:
    skip_files: Set[Path] = set()
    if file_cache is not None and file_cache.exists():
        with file_cache.open('r') as f:
            skip_files = set(filter(
                lambda x: x.is_file(),
                map(lambda x: Path(x), json.load(f))
            ))
        print(f'Loaded {len(skip_files)} entries from cache')

    already_scanned_cache = AlreadyScannedCache(cache=skip_files, lock=Lock())
    commands: queue.Queue[Tuple[int, SCAN_COMMAND]] = queue.Queue(maxsize=cpu_count() * 20)
    commands_unfinished = Event()
    commands_unfinished.set()
    log_lines_to_write: queue.Queue[Tuple[TextIO, str]] = queue.Queue(maxsize=cpu_count() * 100)

    counter = {
        'scanned-files': 0,
        'infected-files': 0,
        'time-start': time.time()
    }

    def thread_commands_generator():
        for i, cmd in enumerate(generate_scan_commands(path, already_scanned_cache)):
            while True:
                if not commands_unfinished.is_set():
                    return
                try:
                    commands.put((i, cmd), timeout=5)
                    break
                except queue.Full:
                    pass
        print("[SCANNER] Command generation finished")
        commands_unfinished.clear()

    def thread_write_log():
        last_line_length = 0

        while True:
            if not commands_unfinished.is_set() and log_lines_to_write.empty():
                alive_threads = sum(map(lambda _: 1, filter(lambda x: x.is_alive(), threading.enumerate())))
                if alive_threads <= 2:
                    break
                print(f'Waiting for log to finish, threads alive: {alive_threads}')
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
            if not commands_unfinished.is_set():
                print("[SCANNER] Thread finished")
                break

            try:
                command_id, (command, target) = commands.get(timeout=1)
                try:

                    if command == "FILE_SCAN":
                        p = Popen(["clamdscan", "--fdpass", "--no-summary", target.absolute()],
                                  stdin=PIPE,
                                  stderr=PIPE,
                                  stdout=PIPE,
                                  text=True
                                  )
                        time_start = time.time()
                        while True:
                            try:
                                stdout, stderr = p.communicate(input=None, timeout=30)
                                break
                            except TimeoutExpired:
                                print(f"[SCANNER] {target} taking longer than it should (f{int(time.time() - time_start)}s)")
                        stdout, stderr = stdout.strip(), stderr.strip()
                        if stdout:
                            counter['scanned-files'] += 1
                            if not stdout.endswith(': OK'):
                                counter['infected-files'] += 1
                            log_lines_to_write.put((sys.stdout, stdout))
                        if stderr:
                            log_lines_to_write.put((sys.stderr, stderr))
                finally:
                    pass
            except queue.Empty:
                print("[SCANNER]  ... nothing to do")
                pass

    threads: List[Thread] = []
    for f in (thread_commands_generator, thread_write_log):
        t = Thread(target=f)
        t.setDaemon(True)
        t.start()
        threads.append(t)

    print(f"[SCANNER] Starting {cpu_count()} scanning threads")
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
        print("^C received, ending")

        if file_cache is not None:
            print(f'Saving cache to {file_cache}')
            with already_scanned_cache.lock:
                with file_cache.open('w') as f:
                    json.dump(
                        list(
                            map(lambda x: str(x),
                                filter(
                                    lambda x: x.is_file(),
                                    already_scanned_cache.cache
                                )
                                )
                        ),
                        f
                    )
            print('Cache saved')

        commands_unfinished.clear()
        print('Waiting for other thread to terminate')
        for t in threads:
            t.join()

        print('Finishing')


def main() -> None:
    parser = argparse.ArgumentParser(description='Recursive and fast scan')
    parser.add_argument('path', metavar='path', type=str,
                        help='a path to scan')
    parser.add_argument('--log', dest='log', type=str, help='log file to write information to', default=None)
    parser.add_argument('--cache', dest='cache', type=str, help='where to store scanned cache info', default=None)
    args = parser.parse_args()

    log_file: Optional[TextIO] = None
    if args.log is not None:
        log_file = open(args.log, 'w')

    scan(Path(args.path), log_file, Path(args.cache) if args.cache is not None else None)

    if log_file is not None:
        log_file.flush()
        log_file.close()


if __name__ == '__main__':
    main()
