#!/usr/bin/env python3
"""
Phishing Awareness Testing Framework
Безопасный инструмент для тестирования осведомленности о фишинге
Использовать только с разрешения организации!
"""

import argparse
import sqlite3
import json
import uuid
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict, Optional
import csv
import sys
import os

@dataclass
class EmailTemplate:
    """Шаблон тестового email-сообщения"""
    name: str
    subject: str
    body: str
    sender: str
    difficulty: str

class PhishingSimulator:
    """Основной класс для управления тестированием фишинга"""
    
    def __init__(self, db_path: str = "phishing_tests.db"):
        """Инициализация симулятора с базой данных"""
        self.db_path = db_path
        self._init_database()
        self.templates = self._load_templates()
    
    def _init_database(self) -> None:
        """Создание необходимых таблиц в БД"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS campaigns (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        template TEXT NOT NULL,
                        created TEXT NOT NULL,
                        status TEXT DEFAULT 'active'
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS employees (
                        id TEXT PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        name TEXT,
                        department TEXT,
                        campaign_id TEXT,
                        FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS results (
                        id TEXT PRIMARY KEY,
                        employee_id TEXT,
                        campaign_id TEXT,
                        email_sent INTEGER DEFAULT 0,
                        link_clicked INTEGER DEFAULT 0,
                        phishing_reported INTEGER DEFAULT 0,
                        clicked_at TEXT,
                        reported_at TEXT,
                        token TEXT UNIQUE,
                        FOREIGN KEY (employee_id) REFERENCES employees(id),
                        FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                    )
                ''')
                
        except sqlite3.Error as e:
            print(f"Ошибка БД: {e}")
            sys.exit(1)
    
    def _load_templates(self) -> Dict[str, EmailTemplate]:
        """Загрузка предустановленных шаблонов писем"""
        return {
            "password_reset": EmailTemplate(
                name="password_reset",
                subject="Срочный сброс пароля",
                body="""Уважаемый сотрудник,

Наша система безопасности обнаружила подозрительную активность.
Для защиты данных требуется немедленный сброс пароля.

Ссылка: {link}

С уважением,
Отдел ИБ""",
                sender="security@company.com",
                difficulty="low"
            ),
            "software_update": EmailTemplate(
                name="software_update",
                subject="Критическое обновление ПО",
                body="""Здравствуйте,

Требуется установить обновление безопасности.
Пожалуйста, перейдите по ссылке для установки:

{link}

С уважением,
IT отдел""",
                sender="it-support@company.com",
                difficulty="medium"
            ),
            "ceo_request": EmailTemplate(
                name="ceo_request",
                subject="Срочный запрос от руководства",
                body="""Добрый день,

Прошу вас ознакомиться с важным документом.
Доступ по ссылке:

{link}

С уважением,
Генеральный директор""",
                sender="ceo@company.com",
                difficulty="high"
            )
        }
    
    def create_campaign(self, name: str, template: str) -> str:
        """
        Создание новой тестовой кампании
        
        Args:
            name: Название кампании
            template: Имя шаблона
        
        Returns:
            ID созданной кампании
        """
        if template not in self.templates:
            raise ValueError(f"Неизвестный шаблон: {template}")
        
        campaign_id = str(uuid.uuid4())
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO campaigns (id, name, template, created)
                    VALUES (?, ?, ?, ?)
                ''', (campaign_id, name, template, datetime.now().isoformat()))
                
            print(f"Создана кампания: {name} (ID: {campaign_id})")
            return campaign_id
            
        except sqlite3.Error as e:
            raise RuntimeError(f"Ошибка создания кампании: {e}")
    
    def add_employees(self, campaign_id: str, employees_file: str) -> None:
        """
        Добавление сотрудников в кампанию из CSV файла
        
        Args:
            campaign_id: ID кампании
            employees_file: Путь к CSV файлу с сотрудниками
        """
        try:
            employees = []
            with open(employees_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if not all(key in row for key in ['email', 'name', 'department']):
                        raise ValueError("CSV должен содержать поля: email, name, department")
                    employees.append(row)
            
            if not employees:
                raise ValueError("Файл не содержит данных")
            
        except FileNotFoundError:
            raise FileNotFoundError(f"Файл не найден: {employees_file}")
        except Exception as e:
            raise RuntimeError(f"Ошибка чтения CSV: {e}")
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for emp in employees:
                    emp_id = str(uuid.uuid4())
                    token = str(uuid.uuid4())
                    
                    # Добавляем сотрудника
                    cursor.execute('''
                        INSERT OR IGNORE INTO employees (id, email, name, department, campaign_id)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (emp_id, emp['email'], emp['name'], emp['department'], campaign_id))
                    
                    # Создаем запись для отслеживания
                    result_id = str(uuid.uuid4())
                    cursor.execute('''
                        INSERT INTO results (id, employee_id, campaign_id, token)
                        VALUES (?, ?, ?, ?)
                    ''', (result_id, emp_id, campaign_id, token))
                
                print(f"Добавлено сотрудников: {len(employees)}")
                
        except sqlite3.Error as e:
            raise RuntimeError(f"Ошибка добавления сотрудников: {e}")
    
    def generate_emails(self, campaign_id: str, output_dir: str = "emails") -> None:
        """
        Генерация тестовых писем без реальной отправки
        
        Args:
            campaign_id: ID кампании
            output_dir: Директория для сохранения писем
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Получаем информацию о кампании
                cursor.execute('''
                    SELECT name, template FROM campaigns WHERE id = ?
                ''', (campaign_id,))
                campaign_data = cursor.fetchone()
                
                if not campaign_data:
                    raise ValueError("Кампания не найдена")
                
                campaign_name, template_name = campaign_data
                template = self.templates.get(template_name)
                
                if not template:
                    raise ValueError(f"Шаблон не найден: {template_name}")
                
                # Получаем сотрудников
                cursor.execute('''
                    SELECT e.email, e.name, r.token
                    FROM employees e
                    JOIN results r ON e.id = r.employee_id
                    WHERE e.campaign_id = ?
                ''', (campaign_id,))
                
                employees = cursor.fetchall()
                
        except sqlite3.Error as e:
            raise RuntimeError(f"Ошибка БД: {e}")
        
        # Создаем директорию для писем
        os.makedirs(output_dir, exist_ok=True)
        
        # Генерируем письма
        for email, name, token in employees:
            tracking_link = f"http://localhost:8080/track/{token}"
            email_content = template.body.replace("{link}", tracking_link)
            
            email_filename = f"{output_dir}/{email.replace('@', '_')}.txt"
            with open(email_filename, 'w', encoding='utf-8') as f:
                f.write(f"Кому: {email}\n")
                f.write(f"Тема: {template.subject}\n")
                f.write(f"От: {template.sender}\n")
                f.write(f"\n{email_content}\n")
                f.write(f"\n---\n")
                f.write(f"Тестовое письмо для кампании: {campaign_name}\n")
                f.write(f"Токен отслеживания: {token}\n")
            
            # Помечаем письмо как отправленное
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE results 
                        SET email_sent = 1 
                        WHERE token = ?
                    ''', (token,))
            except sqlite3.Error:
                pass  # Игнорируем ошибки обновления
        
        print(f"Сгенерировано писем: {len(employees)}")
        print(f"Письма сохранены в: {output_dir}/")
    
    def simulate_click(self, token: str) -> None:
        """
        Симуляция клика по ссылке (для тестирования)
        
        Args:
            token: Токен отслеживания
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE results 
                    SET link_clicked = 1, clicked_at = ?
                    WHERE token = ?
                ''', (datetime.now().isoformat(), token))
                
                if cursor.rowcount == 0:
                    print(f"Токен не найден: {token}")
                else:
                    print("Клик зарегистрирован")
                    
        except sqlite3.Error as e:
            print(f"Ошибка БД: {e}")
    
    def report_phishing(self, email: str, campaign_id: str) -> None:
        """
        Регистрация отчета о фишинге от сотрудника
        
        Args:
            email: Email сотрудника
            campaign_id: ID кампании
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE results 
                    SET phishing_reported = 1, reported_at = ?
                    WHERE employee_id IN (
                        SELECT id FROM employees 
                        WHERE email = ? AND campaign_id = ?
                    )
                ''', (datetime.now().isoformat(), email, campaign_id))
                
                if cursor.rowcount == 0:
                    print(f"Сотрудник не найден в кампании")
                else:
                    print("Отчет зарегистрирован")
                    
        except sqlite3.Error as e:
            print(f"Ошибка БД: {e}")
    
    def get_stats(self, campaign_id: str) -> Dict:
        """
        Получение статистики по кампании
        
        Args:
            campaign_id: ID кампании
        
        Returns:
            Словарь со статистикой
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Общая статистика
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total,
                        SUM(email_sent) as sent,
                        SUM(link_clicked) as clicked,
                        SUM(phishing_reported) as reported
                    FROM results 
                    WHERE campaign_id = ?
                ''', (campaign_id,))
                
                total, sent, clicked, reported = cursor.fetchone()
                total = total or 0
                sent = sent or 0
                clicked = clicked or 0
                reported = reported or 0
                
                # Статистика по отделам
                cursor.execute('''
                    SELECT 
                        e.department,
                        COUNT(*) as total,
                        SUM(r.link_clicked) as clicked,
                        SUM(r.phishing_reported) as reported
                    FROM employees e
                    JOIN results r ON e.id = r.employee_id
                    WHERE e.campaign_id = ?
                    GROUP BY e.department
                ''', (campaign_id,))
                
                dept_stats = cursor.fetchall()
                
        except sqlite3.Error as e:
            raise RuntimeError(f"Ошибка БД: {e}")
        
        return {
            "total_employees": total,
            "emails_sent": sent,
            "links_clicked": clicked,
            "phishing_reported": reported,
            "click_rate": round(clicked / total * 100, 2) if total > 0 else 0,
            "report_rate": round(reported / total * 100, 2) if total > 0 else 0,
            "department_stats": [
                {
                    "department": dept,
                    "total": dept_total,
                    "clicked": dept_clicked or 0,
                    "reported": dept_reported or 0
                }
                for dept, dept_total, dept_clicked, dept_reported in dept_stats
            ]
        }
    
    def export_report(self, campaign_id: str, format: str = "csv") -> None:
        """
        Экспорт отчета в указанном формате
        
        Args:
            campaign_id: ID кампании
            format: Формат экспорта (csv, json)
        """
        stats = self.get_stats(campaign_id)
        
        filename = f"report_{campaign_id[:8]}.{format}"
        
        if format == "csv":
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                writer.writerow(["Статистика кампании"])
                writer.writerow(["Метрика", "Значение"])
                writer.writerow(["Всего сотрудников", stats["total_employees"]])
                writer.writerow(["Писем отправлено", stats["emails_sent"]])
                writer.writerow(["Кликов по ссылкам", stats["links_clicked"]])
                writer.writerow(["Отчетов о фишинге", stats["phishing_reported"]])
                writer.writerow(["Процент кликов", f"{stats['click_rate']}%"])
                writer.writerow(["Процент отчетов", f"{stats['report_rate']}%"])
                writer.writerow([])
                
                writer.writerow(["Статистика по отделам"])
                writer.writerow(["Отдел", "Всего", "Кликов", "Отчетов"])
                
                for dept in stats["department_stats"]:
                    writer.writerow([
                        dept["department"],
                        dept["total"],
                        dept["clicked"],
                        dept["reported"]
                    ])
        
        elif format == "json":
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)
        
        else:
            raise ValueError(f"Неподдерживаемый формат: {format}")
        
        print(f"Отчет сохранен: {filename}")
    
    def list_campaigns(self) -> None:
        """Вывод списка всех кампаний"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, name, template, created, status FROM campaigns')
                campaigns = cursor.fetchall()
                
                if not campaigns:
                    print("Нет созданных кампаний")
                    return
                
                print("\nСписок кампаний:")
                print("-" * 80)
                for camp_id, name, template, created, status in campaigns:
                    print(f"ID: {camp_id[:8]}...")
                    print(f"  Название: {name}")
                    print(f"  Шаблон: {template}")
                    print(f"  Создана: {created[:10]}")
                    print(f"  Статус: {status}")
                    print()
                    
        except sqlite3.Error as e:
            print(f"Ошибка БД: {e}")

def main():
    """Основная функция CLI интерфейса"""
    parser = argparse.ArgumentParser(
        description="Инструмент тестирования осведомленности о фишинге",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s new --name "Тест Q1" --template password_reset
  %(prog)s add --campaign ID --file employees.csv
  %(prog)s generate --campaign ID
  %(prog)s stats --campaign ID
  %(prog)s export --campaign ID --format json
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Команды')
    
    # Команда создания кампании
    new_parser = subparsers.add_parser('new', help='Создать новую кампанию')
    new_parser.add_argument('--name', required=True, help='Название кампании')
    new_parser.add_argument('--template', required=True, 
                          choices=['password_reset', 'software_update', 'ceo_request'],
                          help='Шаблон письма')
    
    # Команда добавления сотрудников
    add_parser = subparsers.add_parser('add', help='Добавить сотрудников')
    add_parser.add_argument('--campaign', required=True, help='ID кампании')
    add_parser.add_argument('--file', required=True, help='CSV файл с сотрудниками')
    
    # Команда генерации писем
    gen_parser = subparsers.add_parser('generate', help='Сгенерировать письма')
    gen_parser.add_argument('--campaign', required=True, help='ID кампании')
    gen_parser.add_argument('--output', default='emails', help='Директория для писем')
    
    # Команда симуляции клика
    click_parser = subparsers.add_parser('click', help='Симулировать клик')
    click_parser.add_argument('--token', required=True, help='Токен отслеживания')
    
    # Команда отчета
    report_parser = subparsers.add_parser('report', help='Зарегистрировать отчет')
    report_parser.add_argument('--email', required=True, help='Email сотрудника')
    report_parser.add_argument('--campaign', required=True, help='ID кампании')
    
    # Команда статистики
    stats_parser = subparsers.add_parser('stats', help='Показать статистику')
    stats_parser.add_argument('--campaign', required=True, help='ID кампании')
    
    # Команда экспорта
    export_parser = subparsers.add_parser('export', help='Экспортировать отчет')
    export_parser.add_argument('--campaign', required=True, help='ID кампании')
    export_parser.add_argument('--format', choices=['csv', 'json'], default='csv',
                              help='Формат экспорта')
    
    # Команда списка кампаний
    subparsers.add_parser('list', help='Показать все кампании')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    simulator = PhishingSimulator()
    
    try:
        if args.command == 'new':
            camp_id = simulator.create_campaign(args.name, args.template)
            print(f"ID новой кампании: {camp_id}")
            
        elif args.command == 'add':
            simulator.add_employees(args.campaign, args.file)
            
        elif args.command == 'generate':
            simulator.generate_emails(args.campaign, args.output)
            
        elif args.command == 'click':
            simulator.simulate_click(args.token)
            
        elif args.command == 'report':
            simulator.report_phishing(args.email, args.campaign)
            
        elif args.command == 'stats':
            stats = simulator.get_stats(args.campaign)
            print(f"\nСтатистика кампании {args.campaign[:8]}...")
            print(f"Всего сотрудников: {stats['total_employees']}")
            print(f"Писем отправлено: {stats['emails_sent']}")
            print(f"Кликов по ссылкам: {stats['links_clicked']}")
            print(f"Отчетов о фишинге: {stats['phishing_reported']}")
            print(f"Процент кликов: {stats['click_rate']}%")
            print(f"Процент отчетов: {stats['report_rate']}%")
            
            if stats['department_stats']:
                print("\nПо отделам:")
                for dept in stats['department_stats']:
                    print(f"  {dept['department']}: {dept['clicked']}/{dept['total']} кликов")
            
        elif args.command == 'export':
            simulator.export_report(args.campaign, args.format)
            
        elif args.command == 'list':
            simulator.list_campaigns()
            
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("=" * 70)
    print("ФРЕЙМВОРК ТЕСТИРОВАНИЯ ОСВЕДОМЛЕННОСТИ О ФИШИНГЕ")
    print("Используйте только с разрешения организации!")
    print("=" * 70)
    main()