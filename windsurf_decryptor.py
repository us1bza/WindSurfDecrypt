#!/usr/bin/env python3
import sys
import os
import binascii
import click
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime

console = Console()

class WindsurfDecryptor:
    def __init__(self):
        self.magic_header = b'\xC1\x0A'  # Магические байты, которые начинают сообщения Windsurf
        
    def _hex_dump(self, data, offset=0):
        """Создание форматированного шестнадцатеричного дампа двоичных данных."""
        hex_lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_vals = ' '.join(f'{b:02x}' for b in chunk)
            ascii_vals = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_lines.append(f'{i+offset:04x}: {hex_vals:<48} {ascii_vals}')
        return '\n'.join(hex_lines)

    def _parse_message(self, data):
        """Разбор сообщения Windsurf на компоненты."""
        try:
            # Пропустить магический заголовок, если присутствует
            if data.startswith(self.magic_header):
                data = data[2:]

            # Разделить сообщение на компоненты
            parts = {}
            
            # Преобразовать в строку для разбора
            try:
                message = data.decode('utf-8', errors='ignore')
            except:
                message = data.decode('latin1', errors='ignore')

            # Извлечь версию клиента и ID сессии
            if 'windsurf' in message.lower():
                parts['client_version'] = message.split('$')[0].strip()
                if '$' in message:
                    session_part = message.split('$')[1]
                    if '"' in session_part:
                        parts['session_id'] = session_part.split('"')[0].strip()

            # Извлечь язык и версию
            if 'en:' in message:
                lang_part = message.split('en:')[1]
                if ' ' in lang_part:
                    parts['version'] = lang_part.split(' ')[0].strip()
                    parts['language'] = 'ru'

            # Извлечь ID машины
            if 'R$' in message:
                machine_part = message.split('R$')[1]
                if 'windsurf' in machine_part.lower():
                    parts['machine_id'] = machine_part.split('windsurf')[0].strip()

            # Извлечь путь установки
            if 'Program Files' in message:
                path_parts = message.split('Program Files')[1:]
                if path_parts:
                    parts['installation_path'] = 'C:\\Program Files' + path_parts[0].split('\x00')[0]

            return parts
            
        except Exception as e:
            return {'error': str(e)}

    def decrypt_message(self, data):
        """Расшифровать и проанализировать сообщение Windsurf."""
        try:
            # Обработка различных форматов ввода
            if isinstance(data, str):
                try:
                    # Удалить кавычки и пробелы
                    data = data.strip().strip("'").strip('"').strip()
                    
                    # Обработка формата с экранированным шестнадцатеричным кодом
                    if '\\x' in data:
                        # Разделить по \x и отфильтровать пустые части
                        hex_parts = [p for p in data.split('\\x') if p]
                        # Преобразовать каждую часть в байты
                        bytes_parts = []
                        for part in hex_parts:
                            if len(part) >= 2:
                                # Первые два символа - шестнадцатеричные, остальное - буквальное
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
                        # Обработать как необработанную строку
                        data = data.encode('latin1')
                except Exception as e:
                    console.print(f"[yellow]Предупреждение: Ошибка при преобразовании в шестнадцатеричный формат: {e}[/yellow]")
                    data = data.encode('latin1')

            # Создать таблицу результатов
            table = Table(title="Анализ сообщения Windsurf", show_header=True)
            table.add_column("Поле", style="cyan")
            table.add_column("Значение", style="green")

            # Добавить шестнадцатеричный дамп
            console.print("\n[yellow]Шестнадцатеричный дамп:[/yellow]")
            console.print(Panel(self._hex_dump(data), border_style="blue"))

            # Разобрать и отобразить компоненты сообщения
            components = self._parse_message(data)
            
            for key, value in components.items():
                table.add_row(key.replace('_', ' ').title(), str(value))

            console.print(table)

            return components

        except Exception as e:
            console.print(f"[red]Ошибка расшифровки сообщения: {str(e)}[/red]")
            return None

@click.command()
@click.argument('input_data', required=True)
@click.option('--file', '-f', is_flag=True, help='Входные данные - это файл, содержащий сообщение')
@click.option('--raw', '-r', is_flag=True, help='Обрабатывать ввод как необработанные байты')
def main(input_data, file, raw):
    """Расшифровать и проанализировать сообщения Windsurf.
    
    INPUT_DATA: Сообщение для расшифровки (или путь к файлу, если используется --file)
    """
    decryptor = WindsurfDecryptor()
    
    try:
        if file:
            with open(input_data, 'rb') as f:
                data = f.read()
        else:
            data = input_data

        if not raw and isinstance(data, str):
            # Попытаться очистить входные данные
            data = data.strip()
            if data.startswith("b'") or data.startswith('b"'):
                data = data[2:-1]

        decryptor.decrypt_message(data)

    except Exception as e:
        console.print(f"[red]Ошибка: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main() 