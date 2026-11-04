/*
# Create core Cortex AI tables

Plain-English summary: creates every table the trading dashboard, client panel and admin panel read from and write to. Tables were derived from the app's own screens and data types because the uploaded schema file was not present.

1. New Tables
- profiles: one row per signed-in user (email, disclaimer acceptance, reseller link).
- admin_roles: staff accounts (super admin / sub admin) with credit balance.
- bots, trades, trade_history, positions: trading bots and their activity.
- user_funds, broker_keys, broker_api_logs: exchange balances, connected exchange keys and API logs.
- licenses, transactions, credit_requests: subscriptions, payments and admin credit purchases.
- bot_templates, master_traders, copy_relationships: bot marketplace and copy trading.
- api_settings, risk_settings, system_settings: platform configuration.
- signals, sentiment_scores: market intelligence feeds.
- client_updates, admin_activity_log: notifications and audit trail.

2. Security
- Row level security is enabled on every new table. Access rules are added in the follow-up migration; until then nothing is readable.
- Grants are given to the signed-in role (authenticated) and to the server role (service_role) for backend functions. The anonymous role gets nothing.

3. Notes
- Money and percentage values use numeric columns; status and type fields are plain text so existing screens can save their values without rejection.
- Owner columns default to the signed-in user so inserts that omit them still work.
- Indexes cover the columns the screens filter and sort on.
*/

CREATE TABLE IF NOT EXISTS profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email text NOT NULL,
  disclaimer_accepted boolean NOT NULL DEFAULT false,
  disclaimer_accepted_at timestamptz,
  admin_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  email text NOT NULL,
  name text,
  role text NOT NULL CHECK (role IN ('super_admin', 'sub_admin')),
  permissions jsonb NOT NULL DEFAULT '{}'::jsonb,
  is_active boolean NOT NULL DEFAULT true,
  credit_balance numeric NOT NULL DEFAULT 0 CHECK (credit_balance >= 0),
  last_login timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL,
  market_type text,
  coin text,
  strategy text,
  status text NOT NULL DEFAULT 'idle',
  profit_loss numeric NOT NULL DEFAULT 0,
  trade_direction text,
  bot_type text,
  martingale_multiplier numeric,
  max_martingale_steps integer,
  order_type text,
  leverage numeric,
  capital numeric,
  indicators_enabled boolean,
  indicator text,
  quantity_mode text,
  quantity_value numeric,
  percent_value numeric,
  max_trades_per_day integer,
  rr_ratio numeric,
  tp_sl_mode text,
  take_profit numeric,
  stop_loss numeric,
  tp_fixed numeric,
  sl_fixed numeric,
  trailing_enabled boolean,
  trailing_distance numeric,
  max_daily_loss numeric,
  max_daily_profit numeric,
  cooldown_minutes integer,
  is_paper_mode boolean,
  strategy_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS trades (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  client_name text,
  coin text NOT NULL,
  market_type text,
  direction text,
  entry_price numeric,
  amount numeric,
  quantity numeric,
  leverage numeric,
  position_size numeric,
  tp_pct numeric,
  sl_pct numeric,
  status text NOT NULL DEFAULT 'open',
  executed_by text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS trade_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  timestamp timestamptz NOT NULL DEFAULT now(),
  pair text NOT NULL,
  side text NOT NULL,
  amount numeric,
  price numeric,
  pnl numeric NOT NULL DEFAULT 0,
  strategy text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS positions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  bot_id uuid REFERENCES bots(id) ON DELETE SET NULL,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  symbol text NOT NULL,
  side text NOT NULL,
  entry_price numeric NOT NULL,
  quantity numeric NOT NULL,
  leverage numeric NOT NULL DEFAULT 1,
  take_profit_pct numeric,
  stop_loss_pct numeric,
  trailing_enabled boolean NOT NULL DEFAULT false,
  trailing_distance_pct numeric,
  current_stop_loss numeric,
  highest_price numeric,
  lowest_price numeric,
  unrealized_pnl numeric NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'open',
  is_paper boolean NOT NULL DEFAULT false,
  exchange_order_id text,
  closed_at timestamptz,
  close_price numeric,
  close_pnl numeric,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_funds (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  exchange_name text NOT NULL,
  balance numeric NOT NULL DEFAULT 0,
  unrealized_pnl numeric NOT NULL DEFAULT 0,
  realized_pnl numeric NOT NULL DEFAULT 0,
  manual_trading_enabled boolean NOT NULL DEFAULT false,
  breakdown jsonb,
  source text,
  last_synced_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS licenses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  plan_name text NOT NULL,
  bot_limit integer NOT NULL DEFAULT 0,
  is_active boolean NOT NULL DEFAULT true,
  valid_from timestamptz NOT NULL DEFAULT now(),
  valid_until timestamptz,
  monthly_fee numeric NOT NULL DEFAULT 0,
  license_key text,
  allowed_bots text[],
  payment_reference text,
  payment_screenshot_url text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bot_templates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  description text,
  strategy_type text,
  market_type text,
  default_tp_pct numeric NOT NULL DEFAULT 0,
  default_sl_pct numeric NOT NULL DEFAULT 0,
  risk_level text,
  is_public boolean NOT NULL DEFAULT false,
  total_copies integer NOT NULL DEFAULT 0,
  bot_type text,
  strategy_id text,
  tier text,
  required_tier text NOT NULL DEFAULT 'starter',
  indicator text,
  take_profit numeric,
  stop_loss numeric,
  martingale_multiplier numeric,
  max_martingale_steps integer,
  execution_mode text,
  strategies text[],
  indicators text[],
  max_drawdown_pct numeric,
  tp_sl_ratio numeric,
  max_leverage numeric,
  source_exchanges text[],
  overall_pnl numeric NOT NULL DEFAULT 0,
  active_users integer NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'active',
  win_rate numeric,
  expected_return text,
  strategy_settings jsonb,
  risk_settings jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS broker_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  exchange_name text NOT NULL,
  api_key text,
  api_secret text,
  is_connected boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS broker_api_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  broker text NOT NULL,
  endpoint text,
  status text NOT NULL DEFAULT 'pending',
  latency_ms integer,
  detail text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS master_traders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  bio text,
  exchange text,
  strategy text,
  market text,
  roi_percentage numeric NOT NULL DEFAULT 0,
  win_rate numeric NOT NULL DEFAULT 0,
  active_copiers integer NOT NULL DEFAULT 0,
  risk_level text NOT NULL DEFAULT 'Medium',
  max_drawdown numeric,
  commission_pct numeric NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS copy_relationships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  trader_id uuid NOT NULL REFERENCES master_traders(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT copy_relationships_user_trader_key UNIQUE (user_id, trader_id)
);

CREATE TABLE IF NOT EXISTS api_settings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  openai_api_key text,
  anthropic_api_key text,
  deepseek_api_key text,
  gemini_api_key text,
  coingecko_api_key text,
  coinmarketcap_api_key text,
  tradingview_license_key text,
  binance_api_key text,
  binance_api_secret text,
  coindcx_api_key text,
  coindcx_api_secret text,
  delta_api_key text,
  delta_api_secret text,
  wazirx_api_key text,
  wazirx_api_secret text,
  pi42_api_key text,
  pi42_api_secret text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS risk_settings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  global_kill_switch boolean NOT NULL DEFAULT false,
  max_leverage numeric NOT NULL DEFAULT 10,
  max_daily_loss_pct numeric NOT NULL DEFAULT 5,
  api_health_alerts boolean NOT NULL DEFAULT true,
  auto_disable_on_breach boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT now(),
  live_usd_inr_rate numeric NOT NULL DEFAULT 88.5,
  manual_usd_inr_rate numeric,
  rate_updated_at timestamptz,
  ai_circuit_breaker boolean NOT NULL DEFAULT false,
  max_slippage_pct numeric NOT NULL DEFAULT 0.5
);

CREATE TABLE IF NOT EXISTS system_settings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key text NOT NULL,
  value text,
  admin_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS signals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  coin text NOT NULL,
  type text NOT NULL,
  confidence numeric,
  entry numeric,
  target numeric,
  stop_loss numeric,
  timeframe text,
  source text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sentiment_scores (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  overall_score numeric,
  classification text,
  fear_greed_index numeric,
  news_sentiment_score numeric,
  news_sentiment_label text,
  bullish_percentage numeric,
  bearish_percentage numeric,
  ai_summary text,
  recommendation text,
  long_entries_blocked boolean NOT NULL DEFAULT false,
  trailing_tightened boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS client_updates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  update_type text NOT NULL,
  title text NOT NULL,
  message text,
  severity text NOT NULL DEFAULT 'info',
  executed_by text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_activity_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_email text,
  admin_name text,
  action_type text NOT NULL,
  message text NOT NULL,
  severity text NOT NULL DEFAULT 'info',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS credit_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sub_admin_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  credits_requested numeric NOT NULL CHECK (credits_requested > 0),
  amount_paid numeric NOT NULL DEFAULT 0,
  utr_number text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  processed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS transactions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_name text NOT NULL,
  client_email text,
  plan_name text NOT NULL,
  amount numeric NOT NULL DEFAULT 0,
  currency text NOT NULL DEFAULT 'INR',
  status text NOT NULL DEFAULT 'pending',
  payment_method text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS admin_roles_active_idx ON admin_roles (user_id) WHERE is_active;
CREATE INDEX IF NOT EXISTS bots_user_status_idx ON bots (user_id, status);
CREATE INDEX IF NOT EXISTS bots_created_idx ON bots (created_at DESC);
CREATE INDEX IF NOT EXISTS trades_client_status_idx ON trades (client_id, status);
CREATE INDEX IF NOT EXISTS trades_created_idx ON trades (created_at DESC);
CREATE INDEX IF NOT EXISTS trade_history_user_ts_idx ON trade_history (user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS positions_user_status_idx ON positions (user_id, status);
CREATE INDEX IF NOT EXISTS positions_bot_idx ON positions (bot_id);
CREATE INDEX IF NOT EXISTS user_funds_user_idx ON user_funds (user_id);
CREATE INDEX IF NOT EXISTS licenses_user_active_idx ON licenses (user_id, is_active);
CREATE INDEX IF NOT EXISTS broker_keys_user_idx ON broker_keys (user_id);
CREATE INDEX IF NOT EXISTS broker_api_logs_created_idx ON broker_api_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS copy_relationships_trader_idx ON copy_relationships (trader_id);
CREATE INDEX IF NOT EXISTS signals_created_idx ON signals (created_at DESC);
CREATE INDEX IF NOT EXISTS sentiment_scores_created_idx ON sentiment_scores (created_at DESC);
CREATE INDEX IF NOT EXISTS client_updates_client_idx ON client_updates (client_id, created_at DESC);
CREATE INDEX IF NOT EXISTS admin_activity_log_created_idx ON admin_activity_log (created_at DESC);
CREATE INDEX IF NOT EXISTS credit_requests_sub_admin_idx ON credit_requests (sub_admin_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS system_settings_admin_key_idx ON system_settings (admin_id, key) NULLS NOT DISTINCT;

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE bots ENABLE ROW LEVEL SECURITY;
ALTER TABLE trades ENABLE ROW LEVEL SECURITY;
ALTER TABLE trade_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE positions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_funds ENABLE ROW LEVEL SECURITY;
ALTER TABLE licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE bot_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE broker_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE broker_api_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE master_traders ENABLE ROW LEVEL SECURITY;
ALTER TABLE copy_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE sentiment_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_updates ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_activity_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE credit_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON profiles, admin_roles, bots, trades, trade_history, positions, user_funds, licenses, bot_templates, broker_keys, broker_api_logs, master_traders, copy_relationships, api_settings, risk_settings, system_settings, signals, sentiment_scores, client_updates, admin_activity_log, credit_requests, transactions TO authenticated;
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
