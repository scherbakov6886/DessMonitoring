import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit, parse_qsl, quote
from zoneinfo import ZoneInfo

import requests

# -------------------- НАСТРОЙКИ --------------------
TELEGRAM_API = 'https://api.telegram.org'
TG_TOKEN = os.getenv('TG_TOKEN', '')
TG_CHAT_IDS = [int(x) for x in os.getenv('TG_CHAT_IDS', '').replace(',', ' ').split() if x]

DESS_REQUEST_URL = os.getenv('DESS_REQUEST_URL', '')

DESS_USER = os.getenv('DESS_USER', '')
DESS_PASSWORD = os.getenv('DESS_PASSWORD', '')
DESS_COMPANY_KEY = os.getenv('DESS_COMPANY_KEY', '')
DESS_API_BASE = 'https://web.dessmonitor.com/public/'

LOW_BATTERY_SOC = 20
RECOVERY_BATTERY_SOC = 25
LOW_BATTERY_VOLTAGE = float((os.getenv('DESS_LOW_BATTERY_VOLTAGE', '0') or '0').replace(',', '.')) or 0.0
HTTP_TIMEOUT = 20

CHECK_CYCLES = max(1, int(os.getenv('DESS_CYCLES', '9') or '9'))
CHECK_INTERVAL = max(1, int(os.getenv('DESS_INTERVAL', '30') or '30'))

DESS_TZ = os.getenv('DESS_TZ', '') or 'Europe/Kyiv'
DESS_TS_TZ = os.getenv('DESS_TS_TZ', '')

_raw_offset = (os.getenv('DESS_TS_ASSUMED_OFFSET', '8') or '').strip().lower()
try:
    TS_ASSUMED_OFFSET = None if _raw_offset in ('', 'off', 'none') else float(_raw_offset.replace(',', '.'))
except ValueError:
    TS_ASSUMED_OFFSET = None

QUIET_WEEKDAYS = os.getenv('DESS_QUIET_WEEKDAYS', '')
QUIET_WEEKENDS = os.getenv('DESS_QUIET_WEEKENDS', '')
DEFAULT_QUIET_WEEKDAYS = '23:00-06:00'
DEFAULT_QUIET_WEEKENDS = '23:00-08:00'

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / 'dessmonitor_state.json'

logger = logging.getLogger('dessmonitor_bot')
logger.setLevel(logging.INFO)
logger.propagate = False


def get_tz(name):
    try:
        return ZoneInfo(name)
    except Exception:
        logger.warning('Неизвестный часовой пояс "%s", используется UTC', name)
        return timezone.utc


def parse_measured_at(ts):
    if ts is None:
        return None
    display_tz = get_tz(DESS_TZ)

    if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.strip().isdigit()):
        numeric = float(ts)
        if numeric > 1e12:
            numeric /= 1000.0
        utc_dt = datetime.fromtimestamp(numeric, timezone.utc)
        if TS_ASSUMED_OFFSET is not None:
            wall = (utc_dt + timedelta(hours=TS_ASSUMED_OFFSET)).replace(tzinfo=None)
            return wall.replace(tzinfo=display_tz)
        return utc_dt.astimezone(display_tz)

    if isinstance(ts, str):
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y/%m/%d %H:%M:%S'):
            try:
                naive = datetime.strptime(ts.strip(), fmt)
            except ValueError:
                continue
            if DESS_TS_TZ:
                return naive.replace(tzinfo=get_tz(DESS_TS_TZ)).astimezone(display_tz)
            return naive.replace(tzinfo=display_tz)
    return None


def fmt_dt(value):
    return value.strftime('%d.%m.%Y %H:%M:%S') if value else 'не передано'


def parse_interval(raw, default):
    cleaned = re.sub(r'\s+', '', raw or '')
    for candidate in (cleaned, default):
        match = re.fullmatch(r'(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})', candidate)
        if match:
            h1, m1, h2, m2 = (int(x) for x in match.groups())
            if h1 < 24 and h2 < 24 and m1 < 60 and m2 < 60:
                if candidate != cleaned and cleaned:
                    logger.warning('Неверный формат интервала "%s", используется %s', raw, default)
                return h1 * 60 + m1, h2 * 60 + m2
    return 23 * 60, 6 * 60


def is_quiet_time(now=None):
    now = now or datetime.now(get_tz(DESS_TZ))
    if now.weekday() >= 5:
        start, end = parse_interval(QUIET_WEEKENDS, DEFAULT_QUIET_WEEKENDS)
    else:
        start, end = parse_interval(QUIET_WEEKDAYS, DEFAULT_QUIET_WEEKDAYS)
    minutes = now.hour * 60 + now.minute
    if start == end:
        return False
    if start < end:
        return start <= minutes < end
    return minutes >= start or minutes < end


def validate_settings():
    missing = []
    if not TG_TOKEN: missing.append('TG_TOKEN')
    if not TG_CHAT_IDS: missing.append('TG_CHAT_IDS')
    if not DESS_USER: missing.append('DESS_USER')
    if not DESS_PASSWORD: missing.append('DESS_PASSWORD')
    if not DESS_COMPANY_KEY: missing.append('DESS_COMPANY_KEY')
    if not DESS_REQUEST_URL: missing.append('DESS_REQUEST_URL')
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

        if DESS_REQUEST_URL:
            params = [(k, v) for k, v in parse_qsl(urlsplit(DESS_REQUEST_URL).query, keep_blank_values=True)
                      if k not in ('sign', 'salt', 'token')]
            if not any(k == 'action' for k, _ in params):
                params.insert(0, ('action', 'querySPDeviceLastData'))
            self.device_parameters = params
        else:
            self.device_parameters = [('action', 'querySPDeviceLastData')]

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

    def _request_data(self):
        salt = str(int(time.time() * 1000))
        action = '&' + urlencode(self.device_parameters, quote_via=quote)
        sign = sha1(salt + self.secret + self.token + action)
        url = f'{DESS_API_BASE}?sign={sign}&salt={salt}&token={self.token}{action}'
        return self.get_json(url)

    def read(self):
        if not self.token or not self.secret:
            self.authenticate()
        try:
            return self._request_data()
        except Exception as exc:
            logger.warning('Ошибка запроса данных (%s), повторная авторизация', exc)
            self.token = None
            self.secret = None
            self.authenticate()
            return self._request_data()


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
    measured_at = parse_measured_at(ts)

    lag_sec = (datetime.now(get_tz(DESS_TZ)) - measured_at).total_seconds() if measured_at else None

    if grid is None and not mode:
        raise ValueError('Не найдены ни Grid Voltage, ни Operating mode')

    status = 'OFF' if (grid is not None and grid <= 30) or (grid is None and mode and 'offgrid' in mode.lower()) else 'ON'
    return {
        'status': status, 'voltage': grid, 'mode': mode,
        'soc': soc, 'battery_voltage': battery_voltage,
        'measured_at': measured_at.isoformat() if measured_at else None,
        'measured_label': fmt_dt(measured_at) if measured_at else None,
        'lag_sec': lag_sec,
        'sample_id': str(ts) if ts is not None else None
    }


def load_state():
    try:
        return json.loads(STATE_FILE.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {'grid_status': None, 'last_seen_sample': None, 'low_battery': False}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding='utf-8')


def send_to_chat(chat_id, message, silent=False):
    try:
        r = requests.post(f'{TELEGRAM_API}/bot{TG_TOKEN}/sendMessage',
                          json={'chat_id': str(chat_id), 'text': message, 'parse_mode': 'HTML',
                                'disable_notification': silent}, timeout=20)
        if r.status_code == 200 and r.json().get('ok'):
            return True
        logger.error('❌ Telegram вернул %s для чата %s: %s', r.status_code, chat_id, r.text[:200])
    except Exception as error:
        logger.error('❌ Ошибка доставки в чат %s: %s', chat_id, error)
    return False


def notify(message):
    silent = is_quiet_time()
    logger.info('Отправка уведомления (беззвучно: %s)', 'да' if silent else 'нет')
    for chat_id in TG_CHAT_IDS:
        send_to_chat(chat_id, message, silent)


def fmt_voltage(value):
    return f'{value:.1f} В' if value is not None else 'не передано'


def run_check(client, state):
    snap = extract_snapshot(client.read())

    current_sample = snap['sample_id']
    current_status = snap['status']
    last_sample = state.get('last_seen_sample')
    prev_status = state.get('grid_status')

    time_label = snap['measured_label'] or fmt_dt(datetime.now(get_tz(DESS_TZ)))

    lag = snap['lag_sec']
    lag_label = f'{lag:.0f} с' if lag is not None else 'н/д'
    logger.info('Текущий семпл: %s | Статус: %s | Напряжение: %s | SOC: %s | Замер: %s | Возраст данных: %s',
                current_sample, current_status, fmt_voltage(snap['voltage']), snap['soc'], time_label, lag_label)

    if current_sample != last_sample:
        if prev_status is not None and current_status != prev_status:
            if current_status == 'OFF':
                notify(f'🔴 <b>ОТКЛЮЧИЛИ СВЕТ</b>\n\nСеть: {fmt_voltage(snap["voltage"])}\nВремя замера: {time_label}')
            else:
                notify(f'🟢 <b>СВЕТ ПОЯВИЛСЯ</b>\n\nСеть: {fmt_voltage(snap["voltage"])}\nВремя замера: {time_label}')

        state['grid_status'] = current_status
        state['last_seen_sample'] = current_sample

    soc = snap['soc']
    if soc is not None and 0 <= soc <= 100:
        if soc <= LOW_BATTERY_SOC and not state.get('low_battery', False):
            notify(f'🪫 <b>Низкий заряд аккумулятора: {soc:.0f}%</b>\n\nВремя замера: {time_label}')
            state['low_battery'] = True
        elif soc >= RECOVERY_BATTERY_SOC:
            state['low_battery'] = False

    save_state(state)


def main():
    validate_settings()
    setup_logging()

    client = DessMonitorClient()
    state = load_state()
    started = time.monotonic()

    logger.info('Старт запуска: %d проверок с интервалом %d сек', CHECK_CYCLES, CHECK_INTERVAL)

    for cycle in range(CHECK_CYCLES):
        logger.info('--- Проверка %d из %d ---', cycle + 1, CHECK_CYCLES)
        try:
            run_check(client, state)
        except Exception as exc:
            logger.error('Ошибка получения данных от API: %s', exc)

        if cycle < CHECK_CYCLES - 1:
            next_tick = started + (cycle + 1) * CHECK_INTERVAL
            delay = next_tick - time.monotonic()
            if delay > 0:
                time.sleep(delay)

    logger.info('Запуск завершён за %.0f сек', time.monotonic() - started)


if __name__ == '__main__':
    main()
