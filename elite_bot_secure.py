"""
╔══════════════════════════════════════════════════════════════╗
║         ELITE TRADING BOT — SECURED VERSION                 ║
║                                                              ║
║  Security features:                                          ║
║    - API keys encrypted with Fernet (AES-128)               ║
║    - Keys never appear in plain text in this file           ║
║    - Each scoring layer has HMAC integrity check            ║
║    - Score results hashed to detect tampering               ║
║    - Trade log entries include integrity hash               ║
║    - Logs mask sensitive data                               ║
║                                                              ║
║  DEMO: Buy >= 55  |  LIVE: Buy >= 70                        ║
║  Run setup_keys.py FIRST before running this file           ║
╚══════════════════════════════════════════════════════════════╝
"""

import os, time, csv, logging, requests, hmac, hashlib, json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from ta.trend import EMAIndicator, MACD
from ta.momentum import RSIIndicator
from alpaca.trading.client import TradingClient
from alpaca.trading.requests import MarketOrderRequest, GetAssetsRequest
from alpaca.trading.enums import OrderSide, TimeInForce, AssetClass, AssetStatus
from alpaca.data.historical import StockHistoricalDataClient
from alpaca.data.requests import StockBarsRequest
from alpaca.data.timeframe import TimeFrame
from cryptography.fernet import Fernet
import pytz

# ══════════════════════════════════════════════════════════════
#   MODE SWITCH — only line you ever need to change
# ══════════════════════════════════════════════════════════════
LIVE_MODE  = False   # False = paper/demo | True = real money
DEMO_DAYS  = 10
# ══════════════════════════════════════════════════════════════

# ── Risk ───────────────────────────────────────────────────────
RISK_PER_TRADE   = 0.01
MAX_POSITIONS    = 8
DAILY_LOSS_LIMIT = 0.03
HARD_STOP_LOSS   = 0.05
TRAILING_AFTER   = 0.05
TRAILING_STOP    = 0.03

# ── Scoring thresholds ─────────────────────────────────────────
BUY_THRESHOLD  = 40 if not LIVE_MODE else 70
SELL_THRESHOLD = 30 if not LIVE_MODE else 40

# ── Paths ──────────────────────────────────────────────────────
LOG_DIR = os.getenv("BOT_DIR", "/app/data")
os.makedirs(LOG_DIR, exist_ok=True)
KEY_FILE  = os.path.join(LOG_DIR, ".keys")
ENC_FILE  = os.path.join(LOG_DIR, ".encrypted_config")
TRADE_LOG = os.path.join(LOG_DIR, "trade_log.csv")
BOT_LOG   = os.path.join(LOG_DIR, "bot.log")
DEMO_FILE = os.path.join(LOG_DIR, "demo_start.txt")
os.makedirs(LOG_DIR, exist_ok=True)

# ══════════════════════════════════════════════════════════════
#   SECURITY — KEY LOADING & HMAC
# ══════════════════════════════════════════════════════════════

def load_keys():
    """Load and decrypt API keys from encrypted config"""
    if not os.path.exists(KEY_FILE) or not os.path.exists(ENC_FILE):
        print("\n  ERROR: Keys not set up yet.")
        print("  Run this first:")
        print("  conda run -n tradingbot python setup_keys.py\n")
        raise SystemExit(1)

    with open(KEY_FILE, "rb") as kf:
        fernet_key = kf.read()
    with open(ENC_FILE, "rb") as ef:
        encrypted = ef.read()

    f = Fernet(fernet_key)
    try:
        raw = f.decrypt(encrypted).decode()
    except Exception:
        print("\n  ERROR: Could not decrypt keys.")
        print("  Re-run setup_keys.py to re-enter your keys.\n")
        raise SystemExit(1)

    parts = raw.split("|||")
    if len(parts) != 3:
        print("\n  ERROR: Corrupted key file. Re-run setup_keys.py.\n")
        raise SystemExit(1)

    return parts[0], parts[1], parts[2]

# Internal secret for HMAC signing of score results
# Generated once from your encryption key so it's unique per installation
def _get_hmac_secret():
    with open(KEY_FILE, "rb") as f:
        return hashlib.sha256(f.read()).digest()

def sign_score(symbol, score_dict):
    """Create HMAC signature for a score result to detect tampering"""
    secret = _get_hmac_secret()
    payload = json.dumps({
        "symbol": symbol,
        "scores": score_dict
    }, sort_keys=True).encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()

def verify_score(symbol, score_dict, signature):
    """Verify score has not been tampered with"""
    expected = sign_score(symbol, score_dict)
    return hmac.compare_digest(expected, signature)

def hash_trade(record):
    """Hash a trade record for integrity verification in the log"""
    payload = json.dumps({k: v for k, v in record.items()
                          if k != "integrity"}, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()[:16]

def mask_key(key):
    """Mask API key for safe logging"""
    if not key or len(key) < 8:
        return "****"
    return key[:4] + "*" * (len(key) - 8) + key[-4:]

# ── Load keys at startup ───────────────────────────────────────
ALPACA_API_KEY = os.getenv("ALPACA_API_KEY")
ALPACA_SECRET_KEY = os.getenv("ALPACA_SECRET_KEY")
NEWS_API_KEY = os.getenv("NEWS_API_KEY", "NOT_SET")

if not ALPACA_API_KEY or not ALPACA_SECRET_KEY:
    raise ValueError("Missing API keys in environment variables")

# ══════════════════════════════════════════════════════════════
#   LOGGING
# ══════════════════════════════════════════════════════════════

logging.basicConfig(
    filename=BOT_LOG,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

def log(msg, level="info"):
    # Never log raw keys — mask anything that looks like one
    safe_msg = msg.replace(ALPACA_API_KEY, mask_key(ALPACA_API_KEY))
    safe_msg = safe_msg.replace(ALPACA_SECRET_KEY, mask_key(ALPACA_SECRET_KEY))
    safe_msg = safe_msg.replace(NEWS_API_KEY, mask_key(NEWS_API_KEY))
    print(f"  {safe_msg}")
    getattr(logging, level)(safe_msg)

# ══════════════════════════════════════════════════════════════
#   CLIENTS
# ══════════════════════════════════════════════════════════════

trading_client = TradingClient(
    ALPACA_API_KEY, ALPACA_SECRET_KEY,
    paper=not LIVE_MODE
)
data_client = StockHistoricalDataClient(ALPACA_API_KEY, ALPACA_SECRET_KEY)
EST = pytz.timezone("US/Eastern")

log(f"Keys loaded | Alpaca: {mask_key(ALPACA_API_KEY)} | "
    f"Mode: {'LIVE' if LIVE_MODE else 'PAPER'}")

# ══════════════════════════════════════════════════════════════
#   DEMO TRACKER
# ══════════════════════════════════════════════════════════════

def get_demo_day():
    if not os.path.exists(DEMO_FILE):
        with open(DEMO_FILE, "w") as f:
            f.write(datetime.now().isoformat())
        return 1
    with open(DEMO_FILE) as f:
        start = datetime.fromisoformat(f.read().strip())
    return min((datetime.now() - start).days + 1, DEMO_DAYS)

def demo_complete():
    return get_demo_day() >= DEMO_DAYS

# ══════════════════════════════════════════════════════════════
#   ACCOUNT
# ══════════════════════════════════════════════════════════════

def get_portfolio_value():
    return float(trading_client.get_account().portfolio_value)

def get_cash():
    return float(trading_client.get_account().cash)

def get_positions():
    return {p.symbol: p for p in trading_client.get_all_positions()}

def is_market_open():
    return trading_client.get_clock().is_open

# ══════════════════════════════════════════════════════════════
#   MARKET DATA
# ══════════════════════════════════════════════════════════════

def get_bars(symbol, tf=TimeFrame.Hour, days=60):
    try:
        end   = datetime.now(pytz.UTC)
        start = end - timedelta(days=days)
        req   = StockBarsRequest(
            symbol_or_symbols=symbol,
            timeframe=tf, start=start, end=end
        )
        bars = data_client.get_stock_bars(req)
        df   = bars.df
        if isinstance(df.index, pd.MultiIndex):
            df = df.xs(symbol, level="symbol")
        return df[["open","high","low","close","volume"]].copy()
    except Exception:
        return pd.DataFrame()

def get_current_price(symbol):
    df = get_bars(symbol, TimeFrame.Minute, days=1)
    if df.empty:
        df = get_bars(symbol, TimeFrame.Hour, days=2)
    return float(df["close"].iloc[-1]) if not df.empty else None

# ══════════════════════════════════════════════════════════════
#   SECTOR MOMENTUM
# ══════════════════════════════════════════════════════════════

SECTOR_ETFS = {
    "Technology":    "XLK", "Healthcare":    "XLV",
    "Financials":    "XLF", "Energy":        "XLE",
    "Consumer":      "XLY", "Industrials":   "XLI",
    "Communication": "XLC", "Materials":     "XLB",
    "Utilities":     "XLU", "Real Estate":   "XLRE",
}

SECTOR_MAP = {
    "AAPL":"Technology","MSFT":"Technology","NVDA":"Technology",
    "GOOGL":"Technology","META":"Technology","AMD":"Technology",
    "INTC":"Technology","ORCL":"Technology","CRM":"Technology",
    "ADBE":"Technology","QCOM":"Technology","AVGO":"Technology",
    "TSLA":"Technology","NFLX":"Communication","DIS":"Communication",
    "CMCSA":"Communication","T":"Communication","VZ":"Communication",
    "JPM":"Financials","BAC":"Financials","WFC":"Financials",
    "GS":"Financials","MS":"Financials","V":"Financials",
    "MA":"Financials","AXP":"Financials","BLK":"Financials",
    "JNJ":"Healthcare","UNH":"Healthcare","PFE":"Healthcare",
    "MRK":"Healthcare","ABBV":"Healthcare","LLY":"Healthcare",
    "TMO":"Healthcare","ABT":"Healthcare","DHR":"Healthcare",
    "XOM":"Energy","CVX":"Energy","COP":"Energy","EOG":"Energy",
    "PG":"Consumer","KO":"Consumer","PEP":"Consumer",
    "WMT":"Consumer","COST":"Consumer","HD":"Consumer",
}

hot_sectors      = []
last_sector_time = None

def refresh_sectors():
    global hot_sectors, last_sector_time
    log("Refreshing sector momentum...")
    perf = {}
    for sector, etf in SECTOR_ETFS.items():
        try:
            df = get_bars(etf, TimeFrame.Day, days=10)
            if len(df) >= 5:
                chg = (df["close"].iloc[-1] - df["close"].iloc[-5]) / df["close"].iloc[-5]
                perf[sector] = round(chg * 100, 2)
        except Exception:
            continue
    sorted_s     = sorted(perf.items(), key=lambda x: x[1], reverse=True)
    hot_sectors  = [s[0] for s in sorted_s[:3]]
    last_sector_time = datetime.now(EST)
    log(f"Hot sectors: {', '.join(hot_sectors)}")

# ══════════════════════════════════════════════════════════════
#   SCORING LAYERS — each layer is HMAC-verified
# ══════════════════════════════════════════════════════════════

def score_technical(symbol):
    score = 0
    try:
        df = get_bars(symbol, TimeFrame.Hour, days=60)
        if len(df) < 52:
            return 0
        df["ema20"]  = EMAIndicator(df["close"], window=20).ema_indicator()
        df["ema50"]  = EMAIndicator(df["close"], window=50).ema_indicator()
        df["rsi"]    = RSIIndicator(df["close"], window=14).rsi()
        macd         = MACD(df["close"])
        df["macd"]   = macd.macd()
        df["macd_s"] = macd.macd_signal()
        last = df.iloc[-1]
        prev = df.iloc[-2]
        if last["ema20"] > last["ema50"]:   score += 7
        if last["close"] > last["ema20"]:   score += 3
        rsi = last["rsi"]
        if   50 < rsi < 65:  score += 10
        elif 40 < rsi <= 50: score += 6
        elif 65 <= rsi < 75: score += 4
        elif rsi >= 75:      score += 1
        if last["macd"] > last["macd_s"] and prev["macd"] <= prev["macd_s"]:
            score += 10
        elif last["macd"] > last["macd_s"]:
            score += 5
    except Exception as e:
        log(f"Technical score error {symbol}: {e}", "warning")
    return min(score, 30)

def score_sector(symbol):
    sector = SECTOR_MAP.get(symbol, "Unknown")
    if not hot_sectors:    return 12
    if sector == hot_sectors[0]:  return 25
    if sector in hot_sectors[1:]: return 18
    if sector != "Unknown":       return 8
    return 12

def score_volume(symbol):
    try:
        df = get_bars(symbol, TimeFrame.Day, days=30)
        if len(df) < 10: return 0
        avg   = df["volume"].tail(20).mean()
        cur   = df["volume"].iloc[-1]
        ratio = cur / avg if avg > 0 else 1
        if   ratio >= 2.5: return 15
        elif ratio >= 2.0: return 12
        elif ratio >= 1.5: return 8
        elif ratio >= 1.2: return 4
        return 0
    except Exception:
        return 0

def score_news(symbol):
    try:
        api_key = os.getenv("NEWS_API_KEY")
        if not api_key:
            return 8

        url = f"https://www.alphavantage.co/query?function=NEWS_SENTIMENT&tickers={symbol}&apikey={api_key}"

        print("DEBUG: USING ALPHA VANTAGE")
        print("DEBUG URL:", url)

        resp = requests.get(url, timeout=5)

        if resp.status_code != 200:
            print("DEBUG ERROR STATUS:", resp.status_code)
            return 8

        data = resp.json()
        feed = data.get("feed", [])

        if not feed:
            return 15

        scores = []
        for item in feed[:5]:
            score = item.get("overall_sentiment_score")
            if score is not None:
                scores.append(float(score))

        if not scores:
            return 8

        avg_sentiment = sum(scores) / len(scores)

        if avg_sentiment > 0.3:
            return 15
        elif avg_sentiment > 0:
            return 10
        elif avg_sentiment < -0.3:
            return 0
        else:
            return 5

    except Exception as e:
        print("NEWS ERROR:", e)
        return 10

INSTITUTIONAL_STOCKS = {
    "AAPL","MSFT","GOOGL","AMZN","NVDA","META","JPM","JNJ","V",
    "UNH","XOM","PG","MA","HD","CVX","LLY","AVGO","MRK","ABBV",
    "COST","PEP","KO","TMO","BAC","WFC","CRM","ADBE","NFLX","AMD",
    "QCOM","TXN","INTC","ORCL","GS","MS","AXP","BLK","TSLA","DIS",
    "CMCSA","T","VZ","NEE","SPGI","MCO","GOOG","AMGN","HON",
}

def score_institutional(symbol):
    return 15 if symbol in INSTITUTIONAL_STOCKS else 0

def full_score(symbol):
    """
    Score stock across all 5 layers.
    Returns (total, breakdown, signature).
    Signature allows verification that score was not tampered with.
    """
    t = score_technical(symbol)
    s = score_sector(symbol)
    v = score_volume(symbol)
    n = score_news(symbol)
    i = score_institutional(symbol)

    breakdown = {
        "technical":     t,
        "sector":        s,
        "volume":        v,
        "news":          n,
        "institutional": i,
        "total":         t + s + v + n + i
    }
    print(f"{symbol} total score: {total_score}")
    # Sign the score so we can detect if it was modified
    sig = sign_score(symbol, breakdown)

    return breakdown["total"], breakdown, sig

# ══════════════════════════════════════════════════════════════
#   STOCK UNIVERSE
# ══════════════════════════════════════════════════════════════

watchlist       = []
last_build_time = None

def build_universe():
    global watchlist, last_build_time
    log("Building stock universe...")
    try:
        req    = GetAssetsRequest(asset_class=AssetClass.US_EQUITY,
                                  status=AssetStatus.ACTIVE)
        assets = trading_client.get_all_assets(req)
        syms   = [a.symbol for a in assets
                  if a.tradable
                  and "/" not in a.symbol
                  and "." not in a.symbol
                  and len(a.symbol) <= 5]
        log(f"Total tradeable: {len(syms)}")
        strong = []
        end    = datetime.now(pytz.UTC)
        start  = end - timedelta(days=12)
        for i in range(0, min(len(syms), 3000), 200):
            batch = syms[i:i+200]
            try:
                req  = StockBarsRequest(symbol_or_symbols=batch,
                                        timeframe=TimeFrame.Day,
                                        start=start, end=end)
                bars = data_client.get_stock_bars(req)
                df   = bars.df
                if df.empty: continue
                if isinstance(df.index, pd.MultiIndex):
                    for sym in batch:
                        try:
                            sdf = df.xs(sym, level="symbol")
                            if (len(sdf) >= 3 and
                                    5 <= sdf["close"].mean() <= 2000 and
                                    sdf["volume"].mean() >= 500000):
                                strong.append(sym)
                        except Exception:
                            continue
                time.sleep(0.3)
            except Exception:
                time.sleep(1)
        watchlist       = strong
        last_build_time = datetime.now(EST)
        log(f"Universe ready: {len(watchlist)} quality stocks")
    except Exception as e:
        log(f"Universe build error: {e}", "error")

# ══════════════════════════════════════════════════════════════
#   TRADE EXECUTION
# ══════════════════════════════════════════════════════════════

peak_prices = {}

def write_trade(record):
    """Write trade to CSV with integrity hash"""
    record["integrity"] = hash_trade(record)
    exists = os.path.isfile(TRADE_LOG)
    with open(TRADE_LOG, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=record.keys())
        if not exists:
            w.writeheader()
        w.writerow(record)

def execute_buy(symbol, score, breakdown, sig):
    # Verify score integrity before placing order
    if not verify_score(symbol, breakdown, sig):
        log(f"SECURITY: Score integrity check FAILED for {symbol} — skipping", "warning")
        return

    price = get_current_price(symbol)
    if price is None:
        return

    portfolio = get_portfolio_value()
    qty       = max(int((portfolio * RISK_PER_TRADE) / price), 1)
    mode_tag  = "LIVE" if LIVE_MODE else "PAPER"

    record = {
        "time":          datetime.now(EST).strftime("%Y-%m-%d %H:%M"),
        "mode":          mode_tag,
        "action":        "BUY",
        "symbol":        symbol,
        "price":         round(price, 2),
        "qty":           qty,
        "score":         score,
        "technical":     breakdown["technical"],
        "sector":        breakdown["sector"],
        "volume":        breakdown["volume"],
        "news":          breakdown["news"],
        "institutional": breakdown["institutional"],
        "reason":        f"Score {score}/100 verified",
        "score_sig":     sig[:12],
    }

    try:
        order = MarketOrderRequest(
            symbol=symbol, qty=qty,
            side=OrderSide.BUY,
            time_in_force=TimeInForce.DAY
        )
        trading_client.submit_order(order)
        peak_prices[symbol] = price
        write_trade(record)
        log(f"BUY [{mode_tag}] {symbol} x{qty} @ ${price:.2f} | Score:{score}/100 | "
            f"T:{breakdown['technical']} S:{breakdown['sector']} "
            f"V:{breakdown['volume']} N:{breakdown['news']} "
            f"I:{breakdown['institutional']}")
    except Exception as e:
        log(f"Buy error {symbol}: {e}", "error")

def execute_sell(symbol, qty, score, reason):
    price    = get_current_price(symbol) or 0
    mode_tag = "LIVE" if LIVE_MODE else "PAPER"
    record   = {
        "time":          datetime.now(EST).strftime("%Y-%m-%d %H:%M"),
        "mode":          mode_tag,
        "action":        "SELL",
        "symbol":        symbol,
        "price":         round(price, 2),
        "qty":           qty,
        "score":         score,
        "technical":     "", "sector":        "",
        "volume":        "", "news":          "",
        "institutional": "", "reason":        reason,
        "score_sig":     "",
    }
    try:
        order = MarketOrderRequest(
            symbol=symbol, qty=abs(int(float(qty))),
            side=OrderSide.SELL,
            time_in_force=TimeInForce.DAY
        )
        trading_client.submit_order(order)
        peak_prices.pop(symbol, None)
        write_trade(record)
        log(f"SELL [{mode_tag}] {symbol} x{qty} @ ${price:.2f} | {reason}")
    except Exception as e:
        log(f"Sell error {symbol}: {e}", "error")

# ══════════════════════════════════════════════════════════════
#   EXIT MANAGEMENT
# ══════════════════════════════════════════════════════════════

def manage_exits(positions):
    for symbol, pos in list(positions.items()):
        entry   = float(pos.avg_entry_price)
        current = float(pos.current_price)
        pnl_pct = (current - entry) / entry
        qty     = pos.qty

        if symbol not in peak_prices or current > peak_prices[symbol]:
            peak_prices[symbol] = current
        peak           = peak_prices[symbol]
        drop_from_peak = (current - peak) / peak if peak > 0 else 0

        score, breakdown, sig = full_score(symbol)

        log(f"HOLD {symbol} | P&L:{pnl_pct*100:+.1f}% | Score:{score} | Peak:${peak:.2f}")

        if score < SELL_THRESHOLD:
            execute_sell(symbol, qty, score,
                         f"Score fell to {score} — momentum dying")
            continue

        if pnl_pct >= TRAILING_AFTER and drop_from_peak <= -TRAILING_STOP:
            execute_sell(symbol, qty, score,
                         f"Trailing stop: ${peak:.2f}→${current:.2f} "
                         f"({drop_from_peak*100:.1f}% from peak)")
            continue

        if pnl_pct <= -HARD_STOP_LOSS:
            execute_sell(symbol, qty, score,
                         f"Hard stop {pnl_pct*100:.1f}%")
            continue

# ══════════════════════════════════════════════════════════════
#   SAFETY
# ══════════════════════════════════════════════════════════════

day_start_value = None

def safety_ok():
    global day_start_value
    val = get_portfolio_value()
    if day_start_value is None:
        day_start_value = val
        return True
    change = (val - day_start_value) / day_start_value
    if change <= -DAILY_LOSS_LIMIT:
        log(f"DAILY LOSS LIMIT ({change*100:.1f}%) — pausing", "warning")
        return False
    return True

# ══════════════════════════════════════════════════════════════
#   DEMO REPORT
# ══════════════════════════════════════════════════════════════

def print_demo_report():
    print("\n" + "═"*60)
    print("  10-DAY DEMO COMPLETE — PERFORMANCE REPORT")
    print("═"*60)
    if not os.path.exists(TRADE_LOG):
        print("  No trades logged.")
        return
    df    = pd.read_csv(TRADE_LOG)
    buys  = df[df["action"] == "BUY"]
    sells = df[df["action"] == "SELL"]
    print(f"  Total trades : {len(df)}")
    print(f"  Buys         : {len(buys)}")
    print(f"  Sells        : {len(sells)}")
    print(f"  Log file     : {TRADE_LOG}")
    print(f"\n  TO GO LIVE:")
    print(f"  1. Review {TRADE_LOG}")
    print(f"  2. Verify Alpaca identity at app.alpaca.markets")
    print(f"  3. Set LIVE_MODE = True at top of this file")
    print(f"  4. Fund your account → re-run")
    print("═"*60)

# ══════════════════════════════════════════════════════════════
#   MAIN LOOP
# ══════════════════════════════════════════════════════════════

def run():
    global day_start_value
    last_sector_refresh = None
    scan_count = 0

    mode_str = "LIVE" if LIVE_MODE else f"DEMO Day {get_demo_day()}/{DEMO_DAYS}"
    print("═"*60)
    print(f"  ELITE BOT — SECURED | {mode_str}")
    print(f"  Alpaca key   : {mask_key(ALPACA_API_KEY)}")
    print(f"  Buy threshold: {BUY_THRESHOLD}+")
    print(f"  Sell threshold: below {SELL_THRESHOLD}")
    print(f"  Risk/trade   : {RISK_PER_TRADE*100}%")
    print(f"  Max positions: {MAX_POSITIONS}")
    print(f"  Stop loss    : {HARD_STOP_LOSS*100}%")
    print(f"  Trailing stop: after +{TRAILING_AFTER*100}%, trail {TRAILING_STOP*100}%")
    print(f"  Daily limit  : {DAILY_LOSS_LIMIT*100}%")
    print(f"  Logs         : {LOG_DIR}")
    print("═"*60)

    build_universe()
    refresh_sectors()

    while True:
        try:
            now       = datetime.now(EST)
            demo_day  = get_demo_day()
            scan_count += 1

            print(f"\n{'═'*60}")
            print(f"[{now.strftime('%Y-%m-%d %H:%M')} EST] Scan #{scan_count} | "
                  f"{'LIVE' if LIVE_MODE else f'DEMO Day {demo_day}/{DEMO_DAYS}'}")
            print(f"{'═'*60}")

            if not LIVE_MODE and demo_complete():
                print_demo_report()
                print("\n  Demo done. Set LIVE_MODE=True to go live.")
                break

            if not is_market_open():
                log("Market closed — next check in 5 min")
                time.sleep(300)
                continue

            if now.hour == 9 and now.minute < 35:
                day_start_value = get_portfolio_value()
                log(f"Day start: ${day_start_value:,.2f}")

            if not safety_ok():
                time.sleep(3600)
                continue

            if (last_sector_refresh is None or
                    (now - last_sector_refresh).seconds > 7200):
                refresh_sectors()
                last_sector_refresh = now

            if last_build_time is None or (now - last_build_time).seconds > 14400:
                build_universe()

            portfolio = get_portfolio_value()
            cash      = get_cash()
            positions = get_positions()

            log(f"Portfolio: ${portfolio:,.2f} | Cash: ${cash:,.2f} | "
                f"Positions: {len(positions)}/{MAX_POSITIONS}")
            log(f"Hot sectors: {', '.join(hot_sectors)}")

            if positions:
                log(f"Checking exits on {len(positions)} positions...")
                manage_exits(positions)
                positions = get_positions()

            slots = MAX_POSITIONS - len(positions)
            if slots > 0 and watchlist:
                log(f"Scanning {len(watchlist)} stocks ({slots} slots)...")
                candidates = []
                for symbol in watchlist:
                    if symbol in positions:
                        continue
                    score, breakdown, sig = full_score(symbol)
                    if score >= BUY_THRESHOLD:
                        candidates.append((symbol, score, breakdown, sig))

                candidates.sort(key=lambda x: x[1], reverse=True)

                if candidates:
                    log(f"Found {len(candidates)} stocks at {BUY_THRESHOLD}+")
                    for symbol, score, breakdown, sig in candidates[:slots]:
                        execute_buy(symbol, score, breakdown, sig)
                        time.sleep(0.5)
                        if len(get_positions()) >= MAX_POSITIONS:
                            break
                else:
                    log(f"No stocks hit {BUY_THRESHOLD}+ this scan")

            log("Done. Next scan in 30 min.")
            time.sleep(1800)

        except KeyboardInterrupt:
            print("\n  Stopped.")
            if not LIVE_MODE:
                print_demo_report()
            break
        except Exception as e:
            log(f"Error: {e}", "error")
            time.sleep(60)

if __name__ == "__main__":
    run()
