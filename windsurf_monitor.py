#!/usr/bin/env python3
import sys
import os
import time
import json
import logging
import threading
import requests
from datetime import datetime
from pathlib import Path
import click
from rich.live import Live
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.logging import RichHandler
from rich import box
from rich.text import Text
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

console = Console()

WINDDECRYPT_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║  ██╗    ██╗██╗███╗   ██╗██████╗ ███████╗██╗   ██╗██████╗ ███████╗         ║
║  ██║    ██║██║████╗  ██║██╔══██╗██╔════╝██║   ██║██╔══██╗██╔════╝         ║
║  ██║ █╗ ██║██║██╔██╗ ██║██║  ██║███████╗██║   ██║██████╔╝█████╗           ║
║  ██║███╗██║██║██║╚██╗██║██║  ██║╚════██║██║   ██║██╔══██╗██╔══╝           ║
║  ╚███╔███╔╝██║██║ ╚████║██████╔╝███████║╚██████╔╝██║  ██║██║              ║
║   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝              ║
║                                                                              ║
║  ██████╗ ███████╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗               ║
║  ██╔══██╗██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝               ║
║  ██║  ██║█████╗  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║                  ║
║  ██║  ██║██╔══╝  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║                  ║
║  ██████╔╝███████╗╚██████╗██║  ██║   ██║   ██║        ██║                  ║
║  ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝                  ║
║                                                                              ║
║  [bright_yellow]WindSurfDecrypt v1.0[/bright_yellow]                                               ║
║  [cyan]US1BZA[/cyan]                                                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝"""

class Config:
    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.load_config()
        
    def load_config(self):
        """Загрузка конфигурации из файла."""
        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.config = {
                "api": {
                    "enabled": False,
                    "endpoint": "",
                    "api_key": "",
                    "headers": {
                        "Content-Type": "application/json",
                        "User-Agent": "WindsurfMonitor/1.0"
                    }
                },
                "monitoring": {
                    "watch_directory": ".",
                    "output_directory": "logs",
                    "max_history": 100,
                    "save_to_disk": True
                }
            }
            self.save_config()
            
    def save_config(self):
        """Сохранение конфигурации в файл."""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)
            
    def update_api_config(self, endpoint, api_key):
        """Обновление конфигурации API."""
        self.config["api"]["enabled"] = True
        self.config["api"]["endpoint"] = endpoint
        self.config["api"]["api_key"] = api_key
        self.save_config()

class WindsurfMessage:
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.timestamp = datetime.now()
        self.parsed_data = {}
        self.hex_dump = ""
        self.api_sent = False
        
    def __str__(self):
        return f"{self.timestamp.isoformat()} - {self.parsed_data.get('client_version', 'Unknown')}"
        
    def to_dict(self):
        """Преобразование сообщения в словарь для передачи по API."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "parsed_data": self.parsed_data,
            "hex_dump": self.hex_dump,
            "raw_data": self.raw_data.hex() if isinstance(self.raw_data, bytes) else self.raw_data
        }

    def get_detailed_view(self):
        """Генерация подробного представления сообщения для отображения."""
        sections = [
            ("Информация о сообщении", [
                ("Время", self.timestamp.strftime("%Y-%m-%d %H:%M:%S")),
                ("Статус API", "Отправлено ✓" if self.api_sent else "Не отправлено ✗")
            ]),
            ("Данные клиента", [
                ("Версия клиента", self.parsed_data.get('client_version', 'Неизвестно')),
                ("ID сессии", self.parsed_data.get('session_id', 'Неизвестно')),
                ("Язык", self.parsed_data.get('language', 'Неизвестно')),
                ("Версия", self.parsed_data.get('version', 'Неизвестно'))
            ]),
            ("Системная информация", [
                ("ID машины", self.parsed_data.get('machine_id', 'Неизвестно')),
                ("Путь установки", self.parsed_data.get('installation_path', 'Неизвестно'))
            ]),
            ("Технические детали", [
                ("Размер", f"{len(self.raw_data)} байт"),
                ("Магический заголовок", "Присутствует" if self.raw_data.startswith(b'\xC1\x0A') else "Отсутствует")
            ])
        ]
        return sections

class APIClient:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        if config.config["api"]["api_key"]:
            self.session.headers.update({
                "Authorization": f"Bearer {config.config['api']['api_key']}"
            })
        self.session.headers.update(config.config["api"]["headers"])
        
    def send_message(self, message):
        """Отправка сообщения на настроенный конечный API."""
        if not self.config.config["api"]["enabled"]:
            return False
            
        try:
            response = self.session.post(
                self.config.config["api"]["endpoint"],
                json=message.to_dict()
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logging.error(f"Не удалось отправить сообщение по API: {e}")
            return False

class WindsurfDecryptor:
    def __init__(self, config):
        self.config = config
        self.magic_header = b'\xC1\x0A'
        self.output_dir = Path(config.config["monitoring"]["output_directory"])
        self.output_dir.mkdir(exist_ok=True)
        self.messages = []
        self.api_client = APIClient(config)
        self.setup_logging()
        
    def setup_logging(self):
        """Настройка конфигурации логирования."""
        log_file = self.output_dir / "windsurf_decryptor.log"
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                RichHandler(rich_tracebacks=True),
                logging.FileHandler(log_file)
            ]
        )
        self.logger = logging.getLogger("WindsurfDecryptor")

    def _hex_dump(self, data, offset=0):
        """Создание отформатированного дампа в шестнадцатеричном формате из двоичных данных."""
        hex_lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_vals = ' '.join(f'{b:02x}' for b in chunk)
            ascii_vals = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_lines.append(f'{i+offset:04x}: {hex_vals:<48} {ascii_vals}')
        return '\n'.join(hex_lines)

    def _parse_message(self, data):
        """Разбор Windsurf сообщения на его компоненты."""
        try:
            # Преобразование данных в строку, если они в байтах
            if isinstance(data, bytes):
                try:
                    message = data.decode('utf-8', errors='ignore')
                except:
                    message = data.decode('latin1', errors='ignore')
            else:
                message = data

            parts = {}

            # Извлечение версии клиента и ID сессии
            if 'windsurf' in message.lower():
                parts['client_version'] = message.split('$')[0].strip()
                if '$' in message:
                    session_part = message.split('$')[1]
                    if '"' in session_part:
                        parts['session_id'] = session_part.split('"')[0].strip()

            # Извлечение языка и версии
            if 'en:' in message:
                lang_part = message.split('en:')[1]
                if ' ' in lang_part:
                    parts['version'] = lang_part.split(' ')[0].strip()
                    parts['language'] = 'ru'
            else:
                parts['language'] = 'ru'

            # Извлечение ID машины
            if 'R$' in message:
                machine_part = message.split('R$')[1]
                if 'windsurf' in machine_part.lower():
                    parts['machine_id'] = machine_part.split('windsurf')[0].strip()

            # Извлечение пути установки
            if 'Program Files' in message:
                path_parts = message.split('Program Files')[1:]
                if path_parts:
                    parts['installation_path'] = 'C:\\Program Files' + path_parts[0].split('\x00')[0]

            return parts
        except Exception as e:
            self.logger.error(f"Ошибка при разборе сообщения: {e}")
            return {'error': str(e)}

    def process_message(self, data):
        """Обработка и расшифровка Windsurf сообщения."""
        try:
            message = WindsurfMessage(data)
            
            # Обработка различных форматов ввода
            if isinstance(data, str):
                try:
                    data = data.strip().strip("'").strip('"').strip()
                    if '\\x' in data:
                        hex_parts = [p for p in data.split('\\x') if p]
                        bytes_parts = []
                        for part in hex_parts:
                            if len(part) >= 2:
                                try:
                                    bytes_parts.append(bytes.fromhex(part[:2]))
                                    if len(part) > 2:
                                        bytes_parts.append(part[2:].encode('latin1'))
                                except:
                                    bytes_parts.append(part.encode('latin1'))
                            else:
                                bytes_parts.append(part.encode('latin1'))
                        data = b''.join(bytes_parts)
                    else:
                        data = data.encode('latin1')
                except Exception as e:
                    self.logger.warning(f"Ошибка при преобразовании в hex: {e}")
                    data = data.encode('latin1')

            message.raw_data = data
            message.hex_dump = self._hex_dump(data)
            message.parsed_data = self._parse_message(data)
            
            # Сохранение сообщения в файл, если включено
            if self.config.config["monitoring"]["save_to_disk"]:
                self._save_message(message)
            
            # Отправка в API, если настроено
            if self.config.config["api"]["enabled"]:
                message.api_sent = self.api_client.send_message(message)
            
            # Добавление сообщения в историю сообщений
            self.messages.append(message)
            if len(self.messages) > self.config.config["monitoring"]["max_history"]:
                self.messages.pop(0)
                
            return message

        except Exception as e:
            self.logger.error(f"Ошибка при обработке сообщения: {e}")
            return None

    def _save_message(self, message):
        """Сохранение сообщения в файл JSON."""
        try:
            timestamp = message.timestamp.strftime("%Y%m%d_%H%M%S")
            filename = self.output_dir / f"message_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(message.to_dict(), f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Ошибка при сохранении сообщения: {e}")

def display_decrypted_message(message, show_banner=True):
    """Отображение расшифрованного сообщения с баннером и подробной информацией."""
    if show_banner:
        console.print(WINDDECRYPT_BANNER, style="bold blue")

    # Обзор сообщения
    console.print("\n[bold cyan]═══ Обзор сообщения ═══[/bold cyan]")
    overview_table = Table(show_header=False, box=box.SIMPLE)
    overview_table.add_column("Поле", style="bright_yellow")
    overview_table.add_column("Значение", style="bright_white")
    
    sections = message.get_detailed_view()
    for section_name, items in sections:
        console.print(f"\n[bold green]─── {section_name} ───[/bold green]")
        for key, value in items:
            overview_table.add_row(key, str(value))
        overview_table.add_row("", "")
    console.print(overview_table)

    # Шестнадцатеричный дамп
    console.print("\n[bold cyan]═══ Шестнадцатеричный дамп ═══[/bold cyan]")
    console.print(Panel(message.hex_dump, border_style="blue"))

class WindsurfMonitor:
    def __init__(self, decryptor):
        self.decryptor = decryptor
        self.layout = Layout()
        self._setup_layout()
        
    def _setup_layout(self):
        """Настройка макета пользовательского интерфейса терминала."""
        self.layout.split(
            Layout(name="banner", size=17),
            Layout(name="main")
        )
        self.layout["main"].split_row(
            Layout(name="messages", ratio=2),
            Layout(name="details", ratio=3)
        )

    def _generate_banner(self):
        """Создание баннера."""
        api_status = "[green]Включено[/green]" if self.decryptor.config.config["api"]["enabled"] else "[red]Отключено[/red]"
        return Panel(
            f"Монитор сообщений Windsurf - Активен с {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - API: {api_status}",
            style="bold white on blue"
        )

    def _generate_message_table(self):
        """Создание таблицы истории сообщений."""
        table = Table(title="Последние сообщения", box=box.DOUBLE)
        table.add_column("Время", style="cyan")
        table.add_column("Версия клиента", style="green")
        table.add_column("ID сессии", style="yellow")
        table.add_column("API", style="magenta")
        
        for msg in self.decryptor.messages[-10:]:
            api_status = "[green]✓[/green]" if msg.api_sent else "[red]✗[/red]"
            table.add_row(
                msg.timestamp.strftime("%H:%M:%S"),
                msg.parsed_data.get('client_version', 'Неизвестно'),
                msg.parsed_data.get('session_id', 'Неизвестно'),
                api_status
            )
        
        return Panel(table, title="История сообщений", border_style="blue")

    def _generate_details(self, message=None):
        """Создание панели с подробной информацией."""
        if not message:
            return Panel("Сообщение не выбрано", title="Подробности")

        sections = message.get_detailed_view()
        details = []
        
        for section_name, items in sections:
            details.append(f"\n[bold green]{section_name}[/bold green]")
            for key, value in items:
                details.append(f"[yellow]{key}:[/yellow] {value}")
        
        return Panel("\n".join(details), title="Подробности сообщения", border_style="blue")

    def update_display(self):
        """Обновление отображения с текущими данными."""
        self.layout["banner"].update(self._generate_banner())
        self.layout["messages"].update(self._generate_message_table())
        if self.decryptor.messages:
            self.layout["details"].update(self._generate_details(self.decryptor.messages[-1]))
        return self.layout

class MessageWatcher(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor
        
    def on_created(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith('.msg'):
            with open(event.src_path, 'rb') as f:
                data = f.read()
            self.monitor.decryptor.process_message(data)

@click.group()
def cli():
    """Инструмент для расшифровки и мониторинга сообщений Windsurf"""
    pass

@cli.command()
@click.argument('input_data')
@click.option('--file', '-f', is_flag=True, help='Входные данные - это файл, содержащий сообщение')
@click.option('--output-dir', '-o', default='logs', help='Каталог для сохранения выходных файлов')
@click.option('--api-endpoint', help='Конечная точка API для отправки расшифрованных сообщений')
@click.option('--api-key', help='Ключ API для аутентификации')
def decrypt(input_data, file, output_dir, api_endpoint, api_key):
    """Расшифровать одно сообщение Windsurf."""
    config = Config()
    if api_endpoint:
        config.update_api_config(api_endpoint, api_key)
    
    decryptor = WindsurfDecryptor(config)
    
    try:
        if file:
            with open(input_data, 'rb') as f:
                data = f.read()
        else:
            data = input_data

        message = decryptor.process_message(data)
        if message:
            if config.config["api"]["enabled"]:
                message.api_sent = decryptor.api_client.send_message(message)
            
            display_decrypted_message(message)
            
    except Exception as e:
        console.print(f"[red]Ошибка: {str(e)}[/red]")
        sys.exit(1)

@cli.command()
@click.option('--watch-dir', '-w', default='.', help='Каталог для отслеживания новых сообщений')
@click.option('--output-dir', '-o', default='logs', help='Каталог для сохранения выходных файлов')
@click.option('--api-endpoint', help='Конечная точка API для отправки расшифрованных сообщений')
@click.option('--api-key', help='Ключ API для аутентификации')
def monitor(watch_dir, output_dir, api_endpoint, api_key):
    """Мониторинг новых сообщений Windsurf."""
    config = Config()
    if api_endpoint:
        config.update_api_config(api_endpoint, api_key)
    
    config.config["monitoring"]["watch_directory"] = watch_dir
    config.config["monitoring"]["output_directory"] = output_dir
    config.save_config()
    
    decryptor = WindsurfDecryptor(config)
    monitor = WindsurfMonitor(decryptor)
    
    # Setup file system observer
    observer = Observer()
    observer.schedule(MessageWatcher(monitor), watch_dir, recursive=False)
    observer.start()
    
    try:
        with Live(monitor.update_display(), refresh_per_second=4) as live:
            while True:
                time.sleep(0.25)
                live.update(monitor.update_display())
    except KeyboardInterrupt:
        observer.stop()
        observer.join()

@cli.command()
@click.argument('endpoint')
@click.option('--api-key', help='Ключ API для аутентификации')
def configure_api(endpoint, api_key):
    """Настройка конечной точки API для отправки сообщений."""
    config = Config()
    config.update_api_config(endpoint, api_key)
    console.print(f"[green]Конфигурация API обновлена:[/green]")
    console.print(f"Конечная точка: {endpoint}")
    if api_key:
        console.print("Ключ API: [Установлен]")

if __name__ == "__main__":
    cli() 