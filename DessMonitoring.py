# -*- coding: utf-8 -*-
"""DessMonitor -> Telegram: отключение/восстановление сети и низкий SOC (версия для разовых запусков по cron)."""
import hashlib
import html
import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit, parse_qsl, quote

import requests

# -------------------- НАСТРОЙКИ --------------------
TELEGRAM_API = 'https://api.telegram.org'
TG_TOKEN = os.getenv('TG_TOKEN', '')
TG_CHAT_IDS = [int(x) for x in os.getenv('TG_CHAT_IDS', '').replace(',', ' ').split() if x]

DESS_REQUEST_URL = os.getenv('DESS_REQUEST_URL', '')

# Парсинг параметров устройства из DESS_REQUEST_URL, если он задан
_url_params = dict(parse_qsl(urlsplit(DESS_REQUEST_URL).query, keep_blank_values=True)) if DESS_REQUEST_URL else {}

DESS_PN       = os.getenv('DESS_PN') or _url_params.get('pn', '')
DESS_DEVCODE  = os.getenv('DESS_DEVCODE') or _url_params.get('devcode', '')
DESS_DEVADDR  = os.getenv('DESS_DEVADDR') or _url_params.get('devaddr', '')
DESS_SN       = os.getenv('DESS_SN') or _url_params.get('sn', '')

DESS_USER = os.getenv('DESS_USER', '')
DESS_PASSWORD = os.getenv('DESS_PASSWORD', '')
DESS_COMPANY_KEY = os.getenv('DESS_COMPANY_KEY', '')
DESS_API_BASE = 'https://web.dessmonitor.com/public/'

LOW_BATTERY_SOC = 20    # %
RECOVERY_BATTERY_SOC = 25  # гистерезис SOC
LOW_BATTERY_VOLTAGE = float((os.getenv('DESS_LOW_BATTERY_VOLTAGE', '0') or '0').replace(',', '.')) or 0.0
HTTP_TIMEOUT = 20

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / 'dessmonitor_state.json'

def save_state(state):
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding='utf-8')

logger = logging.getLogger('dessmonitor_bot')
logger.setLevel(logging.INFO)
logger.propagate = False


def validate_settings():
    missing = []
    if not TG_TOKEN: missing.append('TG_TOKEN')
    if not TG_CHAT_IDS: missing.append('TG_CHAT_IDS')
    if not DESS_USER: missing.append('DESS_USER')
    if not DESS_PASSWORD: missing.append('DESS_PASSWORD')
    if not DESS_COMPANY_KEY: missing.append('DESS_COMPANY_KEY')
    if not all((DESS_PN, DESS_DEVCODE, DESS_DEVADDR, DESS_SN)):
        missing.append('Параметры устройства (pn, devcode, devaddr, sn) не найдены ни в DESS_REQUEST_URL, ни в переменных окружения')
    if missing:
        raise SystemExit('Не заполнены настройки: ' + ', '.join(missing))


def setup_logging():
    logger.handlers.clear()
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', '%Y-%m-%d %H:%M:%S'))
    logger.addHandler(h)


def sha1(value):
    return hashlib.sha1(value.encode('utf-8')).hexdigest()


class DessMonitorClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'})
        self.token = None
        self.secret = None
        self.device_parameters = [
            ('action', 'querySPDeviceLastData'),
            ('pn', DESS_PN), ('devcode', DESS_DEVCODE),
            ('devaddr', DESS_DEVADDR), ('sn', DESS_SN),
        ]

    def get_json(self, url):
        response = self.session.get(url, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        obj = response.json()
        if not isinstance(obj, dict):
            raise ValueError('API вернул не JSON-объект')
        code = obj.get('code', obj.get('err', 0))
        if str(code) != '0':
            desc = obj.get('desc') or obj.get('message') or obj.get('msg') or ''
            raise RuntimeError(f'DessMonitor вернул код {code}: {desc}')
        return obj

    def authenticate(self):
        salt = str(int(time.time() * 1000))
        action_params = [
            ('action', 'authSource'), ('usr', DESS_USER),
            ('source', '1'), ('company-key', DESS_COMPANY_KEY),
        ]
        action = '&' + urlencode(action_params, quote_via=quote)
        sign = sha1(salt + sha1(DESS_PASSWORD) + action)
        url = f'{DESS_API_BASE}?sign={sign}&salt={salt}{action}'
        data = self.get_json(url).get('dat') or {}
        self.token = data.get('token')
        self.secret = data.get('secret')
        if not self.token or not self.secret:
            raise RuntimeError('Авторизация прошла без token/secret. Проверь company-key.')
        logger.info('DessMonitor: авторизация выполнена успешно')

    def read(self):
        self.authenticate()
        salt = str(int(time.time() * 1000))
        action = '&' + urlencode(self.device_parameters, quote_via=quote)
        sign = sha1(salt + self.secret + self.token + action)
        url = f'{DESS_API_BASE}?sign={sign}&salt={salt}&token={self.token}{action}'
        return self.get_json(url)


def flatten_items(value):
    if isinstance(value, dict):
        if 'val' in value and ('par' in value or 'id' in value):
            yield value
        for k, v in value.items():
            if k not in ('val',):
                yield from flatten_items(v)
    elif isinstance(value, list):
        for item in value:
            yield from flatten_items(item)


def as_number(value):
    try:
        return float(str(value).replace(',', '.').strip())
    except (TypeError, ValueError):
        return None


def extract_snapshot(payload):
    data = payload.get('dat') or {}
    pars = data.get('pars')
    if not pars:
        raise ValueError('В ответе нет dat.pars')
    items = list(flatten_items(pars))
    
    grid = next((as_number(i.get('val')) for i in items if i.get('id') == 'gd_eybond_read_7'), None)
    if grid is None:
        grid = next((as_number(i.get('val')) for i in items if re.search(r'^grid\s+voltage$', str(i.get('par', '')).strip(), re.I)), None)
    
    mode = next((str(i.get('val', '')).strip() for i in items if re.search(r'operating\s*mode|working\s*mode', str(i.get('par', '')), re.I)), None)
    soc = next((as_number(i.get('val')) for i in items if re.search(r'\b(battery\s+(soc|capacity)|state\s+of\s+charge)\b', str(i.get('par', '')), re.I) and str(i.get('unit', '')).strip() in ('', '%')), None)
    
    battery_voltage = next((as_number(i.get('val')) for i in items if re.search(r'\bbattery\s+voltage\b', str(i.get('par', '')), re.I) and str(i.get('unit', '')).strip() == 'V'), None)
    if battery_voltage is None:
        battery_voltage = next((as_number(i.get('val')) for i in items if i.get('id') == 'bt_eybond_read_20'), None)

    ts = data.get('gts')
    measured_at = None
    if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.isdigit()):
        numeric = float(ts)
        if numeric > 1e12:
            numeric /= 1000.0
        measured_at = datetime.fromtimestamp(numeric, timezone.utc)

    if grid is None and not mode:
        raise ValueError('Не найдены ни Grid Voltage, ни Operating mode')

    status = 'OFF' if (grid is not None and grid <= 30) or (grid is None and mode and 'offgrid' in mode.lower()) else 'ON'
    return {
        'status': status, 'voltage': grid, 'mode': mode,
        'soc': soc, 'battery_voltage': battery_voltage,
        'measured_at': measured_at.isoformat() if measured_at else None,
        'sample_id': str(ts) if ts is not None else None
    }


def load_state():
    try:
        return json.loads(STATE_FILE.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {'grid_status': None, 'last_seen_sample': None, 'low_battery': False}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding='utf-8')


def send_to_chat(chat_id, message):
    try:
        r = requests.post(f'{TELEGRAM_API}/bot{TG_TOKEN}/sendMessage',
                          json={'chat_id': str(chat_id), 'text': message, 'parse_mode': 'HTML'}, timeout=20)
        if r.status_code == 200 and r.json().get('ok'):
            return True
    except Exception as error:
        logger.error('❌ Ошибка доставки в чат %s: %s', chat_id, error)
    return False


def notify(message):
    for chat_id in TG_CHAT_IDS:
        send_to_chat(chat_id, message)


def fmt_voltage(value):
    return f'{value:.1f} В' if value is not None else 'не передано'


def main():
    validate_settings()
    setup_logging()
    
    client = DessMonitorClient()
    state = load_state()

    try:
        snap = extract_snapshot(client.read())
    except Exception as exc:
        logger.error('Ошибка получения данных от API: %s', exc)
        return

    current_sample = snap['sample_id']
    current_status = snap['status']
    last_sample = state.get('last_seen_sample')
    prev_status = state.get('grid_status')

    logger.info('Текущий семпл: %s | Статус: %s | Напряжение: %s | SOC: %s', 
                current_sample, current_status, fmt_voltage(snap['voltage']), snap['soc'])

    # Если появился новый замер и статус изменился по сравнению с предыдущим
    if current_sample != last_sample:
        if prev_status is not None and current_status != prev_status:
            time_label = datetime.now(timezone.utc).astimezone().strftime('%d.%m.%Y %H:%M:%S')
            if current_status == 'OFF':
                notify(f'🔴 <b>ОТКЛЮЧИЛИ СВЕТ</b>\n\nСеть: {fmt_voltage(snap["voltage"])}\nОбнаружено: {time_label}')
            else:
                notify(f'🟢 <b>СВЕТ ПОЯВИЛСЯ</b>\n\nСеть: {fmt_voltage(snap["voltage"])}\nОбнаружено: {time_label}')
        
        state['grid_status'] = current_status
        state['last_seen_sample'] = current_sample

    # Проверка уровня заряда батареи
    soc = snap['soc']
    if soc is not None and 0 <= soc <= 100:
        if soc <= LOW_BATTERY_SOC and not state.get('low_battery', False):
            notify(f'🪫 <b>Низкий заряд аккумулятора: {soc:.0f}%</b>')
            state['low_battery'] = True
        elif soc >= RECOVERY_BATTERY_SOC:
            state['low_battery'] = False

    save_state(state)


if __name__ == '__main__':
    main()
