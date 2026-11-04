/*
# Add access rules, admin functions and seed rows

Plain-English summary: decides who can read and change each table, adds the admin helper checks, and creates the database functions the admin screens call (license allotment, credit transfers, credit approvals, user lookup, master settings). Also seeds the single risk and API settings rows and grants the platform owner account super admin access when that account exists.

1. Helper checks
- is_platform_admin(): true when the signed-in user has an active admin role.
- is_super_admin(): true when the signed-in user has an active super admin role.
- Admin access is stored in the admin_roles table only. Nothing is granted by email address alone.

2. Row access rules
- Personal data (bots, positions, trade history, funds, broker keys, copy relationships): the owner can manage their own rows; admins can manage all rows.
- Trades and client updates: the client can read their own; admins manage all.
- Licenses: the client can read their own; a database trigger stops clients from changing plan, limits, validity or fees.
- Profiles: users manage their own; a trigger stops clients from changing their reseller assignment.
- Public catalogue data (risk settings, signals, sentiment, master traders): readable by signed-in users; written by admins only.
- Secret settings (API keys, system settings): admin only, with reseller-scoped rows for system settings.
- Activity log: admins read; any signed-in user may add an entry (used by bug reports).

3. New functions
- allot_license, transfer_credits, approve_credit_request, find_user_by_email, get_master_settings. Only signed-in admins may execute them; anonymous visitors may not.

4. Seed data
- One risk settings row and one API settings row, only if none exist.
- Existing signed-in accounts without a profile get one.
- The platform owner account becomes a super admin if it has signed up.

5. Notes
- Live trading is not enabled by this migration.
- Broker API keys and platform API keys are stored in these tables for now; they should move to server-side secrets before live trading.
*/

CREATE OR REPLACE FUNCTION public.is_platform_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM admin_roles r WHERE r.user_id = auth.uid() AND r.is_active
  );
$$;

CREATE OR REPLACE FUNCTION public.is_super_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM admin_roles r WHERE r.user_id = auth.uid() AND r.is_active AND r.role = 'super_admin'
  );
$$;

CREATE OR REPLACE FUNCTION public.guard_profile_admin_link()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF NEW.admin_id IS DISTINCT FROM OLD.admin_id AND NOT public.is_platform_admin() THEN
    RAISE EXCEPTION 'Only administrators can change a reseller assignment';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_profile_admin_link ON profiles;
CREATE TRIGGER guard_profile_admin_link
  BEFORE UPDATE ON profiles
  FOR EACH ROW EXECUTE FUNCTION public.guard_profile_admin_link();

CREATE OR REPLACE FUNCTION public.guard_license_fields()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF NOT public.is_platform_admin() AND (
    NEW.user_id, NEW.plan_name, NEW.bot_limit, NEW.is_active, NEW.valid_from,
    NEW.valid_until, NEW.monthly_fee, NEW.allowed_bots, NEW.license_key
  ) IS DISTINCT FROM (
    OLD.user_id, OLD.plan_name, OLD.bot_limit, OLD.is_active, OLD.valid_from,
    OLD.valid_until, OLD.monthly_fee, OLD.allowed_bots, OLD.license_key
  ) THEN
    RAISE EXCEPTION 'Only administrators can change license terms';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_license_fields ON licenses;
CREATE TRIGGER guard_license_fields
  BEFORE UPDATE ON licenses
  FOR EACH ROW EXECUTE FUNCTION public.guard_license_fields();

-- profiles
DROP POLICY IF EXISTS "profiles_select_own_or_admin" ON profiles;
CREATE POLICY "profiles_select_own_or_admin" ON profiles FOR SELECT TO authenticated
  USING (id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "profiles_insert_own" ON profiles;
CREATE POLICY "profiles_insert_own" ON profiles FOR INSERT TO authenticated
  WITH CHECK (id = auth.uid());
DROP POLICY IF EXISTS "profiles_update_own_or_admin" ON profiles;
CREATE POLICY "profiles_update_own_or_admin" ON profiles FOR UPDATE TO authenticated
  USING (id = auth.uid() OR public.is_platform_admin())
  WITH CHECK (id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "profiles_delete_admin" ON profiles;
CREATE POLICY "profiles_delete_admin" ON profiles FOR DELETE TO authenticated
  USING (public.is_platform_admin());

-- admin_roles
DROP POLICY IF EXISTS "admin_roles_select_own_or_admin" ON admin_roles;
CREATE POLICY "admin_roles_select_own_or_admin" ON admin_roles FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "admin_roles_insert_super" ON admin_roles;
CREATE POLICY "admin_roles_insert_super" ON admin_roles FOR INSERT TO authenticated
  WITH CHECK (public.is_super_admin());
DROP POLICY IF EXISTS "admin_roles_update_super" ON admin_roles;
CREATE POLICY "admin_roles_update_super" ON admin_roles FOR UPDATE TO authenticated
  USING (public.is_super_admin()) WITH CHECK (public.is_super_admin());
DROP POLICY IF EXISTS "admin_roles_delete_super" ON admin_roles;
CREATE POLICY "admin_roles_delete_super" ON admin_roles FOR DELETE TO authenticated
  USING (public.is_super_admin());

-- bots
DROP POLICY IF EXISTS "bots_select_owner_or_admin" ON bots;
CREATE POLICY "bots_select_owner_or_admin" ON bots FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "bots_insert_owner" ON bots;
CREATE POLICY "bots_insert_owner" ON bots FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "bots_update_owner_or_admin" ON bots;
CREATE POLICY "bots_update_owner_or_admin" ON bots FOR UPDATE TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin())
  WITH CHECK (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "bots_delete_owner_or_admin" ON bots;
CREATE POLICY "bots_delete_owner_or_admin" ON bots FOR DELETE TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());

-- trades (client_id is the owning client)
DROP POLICY IF EXISTS "trades_select_owner_or_admin" ON trades;
CREATE POLICY "trades_select_owner_or_admin" ON trades FOR SELECT TO authenticated
  USING (client_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "trades_insert_admin" ON trades;
CREATE POLICY "trades_insert_admin" ON trades FOR INSERT TO authenticated
  WITH CHECK (public.is_platform_admin());
DROP POLICY IF EXISTS "trades_update_owner_or_admin" ON trades;
CREATE POLICY "trades_update_owner_or_admin" ON trades FOR UPDATE TO authenticated
  USING (client_id = auth.uid() OR public.is_platform_admin())
  WITH CHECK (client_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "trades_delete_admin" ON trades;
CREATE POLICY "trades_delete_admin" ON trades FOR DELETE TO authenticated
  USING (public.is_platform_admin());

-- trade_history
DROP POLICY IF EXISTS "trade_history_select_owner_or_admin" ON trade_history;
CREATE POLICY "trade_history_select_owner_or_admin" ON trade_history FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "trade_history_insert_owner_or_admin" ON trade_history;
CREATE POLICY "trade_history_insert_owner_or_admin" ON trade_history FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "trade_history_update_owner_or_admin" ON trade_history;
CREATE POLICY "trade_history_update_owner_or_admin" ON trade_history FOR UPDATE TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin())
  WITH CHECK (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "trade_history_delete_owner_or_admin" ON trade_history;
CREATE POLICY "trade_history_delete_owner_or_admin" ON trade_history FOR DELETE TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());

-- positions
DROP POLICY IF EXISTS "positions_select_owner_or_admin" ON positions;
CREATE POLICY "positions_select_owner_or_admin" ON positions FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "positions_insert_owner_or_admin" ON positions;
CREATE POLICY "positions_insert_owner_or_admin" ON positions FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "positions_update_owner_or_admin" ON positions;
CREATE POLICY "positions_update_owner_or_admin" ON positions FOR UPDATE TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin())
  WITH CHECK (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "positions_delete_owner_or_admin" ON positions;
CREATE POLICY "positions_delete_owner_or_admin" ON positions FOR DELETE TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());

-- user_funds
DROP POLICY IF EXISTS "user_funds_select_owner_or_admin" ON user_funds;
CREATE POLICY "user_funds_select_owner_or_admin" ON user_funds FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "user_funds_insert_owner_or_admin" ON user_funds;
CREATE POLICY "user_funds_insert_owner_or_admin" ON user_funds FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "user_funds_update_owner_or_admin" ON user_funds;
CREATE POLICY "user_funds_update_owner_or_admin" ON user_funds FOR UPDATE TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin())
  WITH CHECK (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "user_funds_delete_owner_or_admin" ON user_funds;
CREATE POLICY "user_funds_delete_owner_or_admin" ON user_funds FOR DELETE TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());

-- licenses (client changes limited to payment fields by trigger)
DROP POLICY IF EXISTS "licenses_select_owner_or_admin" ON licenses;
CREATE POLICY "licenses_select_owner_or_admin" ON licenses FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "licenses_insert_admin" ON licenses;
CREATE POLICY "licenses_insert_admin" ON licenses FOR INSERT TO authenticated
  WITH CHECK (public.is_platform_admin());
DROP POLICY IF EXISTS "licenses_update_owner_or_admin" ON licenses;
CREATE POLICY "licenses_update_owner_or_admin" ON licenses FOR UPDATE TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin())
  WITH CHECK (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "licenses_delete_admin" ON licenses;
CREATE POLICY "licenses_delete_admin" ON licenses FOR DELETE TO authenticated
  USING (public.is_platform_admin());

-- bot_templates
DROP POLICY IF EXISTS "bot_templates_select_public_or_admin" ON bot_templates;
CREATE POLICY "bot_templates_select_public_or_admin" ON bot_templates FOR SELECT TO authenticated
  USING (is_public OR public.is_platform_admin());
DROP POLICY IF EXISTS "bot_templates_insert_admin" ON bot_templates;
CREATE POLICY "bot_templates_insert_admin" ON bot_templates FOR INSERT TO authenticated
  WITH CHECK (public.is_platform_admin());
DROP POLICY IF EXISTS "bot_templates_update_admin" ON bot_templates;
CREATE POLICY "bot_templates_update_admin" ON bot_templates FOR UPDATE TO authenticated
  USING (public.is_platform_admin()) WITH CHECK (public.is_platform_admin());
DROP POLICY IF EXISTS "bot_templates_delete_admin" ON bot_templates;
CREATE POLICY "bot_templates_delete_admin" ON bot_templates FOR DELETE TO authenticated
  USING (public.is_platform_admin());

-- broker_keys
DROP POLICY IF EXISTS "broker_keys_select_owner_or_admin" ON broker_keys;
CREATE POLICY "broker_keys_select_owner_or_admin" ON broker_keys FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "broker_keys_insert_owner" ON broker_keys;
CREATE POLICY "broker_keys_insert_owner" ON broker_keys FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "broker_keys_update_owner" ON broker_keys;
CREATE POLICY "broker_keys_update_owner" ON broker_keys FOR UPDATE TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "broker_keys_delete_owner" ON broker_keys;
CREATE POLICY "broker_keys_delete_owner" ON broker_keys FOR DELETE TO authenticated
  USING (user_id = auth.uid());

-- broker_api_logs (written by server only)
DROP POLICY IF EXISTS "broker_api_logs_select_owner_or_admin" ON broker_api_logs;
CREATE POLICY "broker_api_logs_select_owner_or_admin" ON broker_api_logs FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());

-- master_traders (public marketplace; admin writes)
DROP POLICY IF EXISTS "master_traders_select_signed_in" ON master_traders;
CREATE POLICY "master_traders_select_signed_in" ON master_traders FOR SELECT TO authenticated
  USING (true);
DROP POLICY IF EXISTS "master_traders_insert_super" ON master_traders;
CREATE POLICY "master_traders_insert_super" ON master_traders FOR INSERT TO authenticated
  WITH CHECK (public.is_super_admin());
DROP POLICY IF EXISTS "master_traders_update_super" ON master_traders;
CREATE POLICY "master_traders_update_super" ON master_traders FOR UPDATE TO authenticated
  USING (public.is_super_admin()) WITH CHECK (public.is_super_admin());
DROP POLICY IF EXISTS "master_traders_delete_super" ON master_traders;
CREATE POLICY "master_traders_delete_super" ON master_traders FOR DELETE TO authenticated
  USING (public.is_super_admin());

-- copy_relationships
DROP POLICY IF EXISTS "copy_relationships_select_owner_or_admin" ON copy_relationships;
CREATE POLICY "copy_relationships_select_owner_or_admin" ON copy_relationships FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "copy_relationships_insert_owner" ON copy_relationships;
CREATE POLICY "copy_relationships_insert_owner" ON copy_relationships FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "copy_relationships_update_owner" ON copy_relationships;
CREATE POLICY "copy_relationships_update_owner" ON copy_relationships FOR UPDATE TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "copy_relationships_delete_owner" ON copy_relationships;
CREATE POLICY "copy_relationships_delete_owner" ON copy_relationships FOR DELETE TO authenticated
  USING (user_id = auth.uid());

-- api_settings (secrets; admin only)
DROP POLICY IF EXISTS "api_settings_select_admin" ON api_settings;
CREATE POLICY "api_settings_select_admin" ON api_settings FOR SELECT TO authenticated
  USING (public.is_platform_admin());
DROP POLICY IF EXISTS "api_settings_insert_super" ON api_settings;
CREATE POLICY "api_settings_insert_super" ON api_settings FOR INSERT TO authenticated
  WITH CHECK (public.is_super_admin());
DROP POLICY IF EXISTS "api_settings_update_super" ON api_settings;
CREATE POLICY "api_settings_update_super" ON api_settings FOR UPDATE TO authenticated
  USING (public.is_super_admin()) WITH CHECK (public.is_super_admin());
DROP POLICY IF EXISTS "api_settings_delete_super" ON api_settings;
CREATE POLICY "api_settings_delete_super" ON api_settings FOR DELETE TO authenticated
  USING (public.is_super_admin());

-- risk_settings (kill switch is read by every signed-in user)
DROP POLICY IF EXISTS "risk_settings_select_signed_in" ON risk_settings;
CREATE POLICY "risk_settings_select_signed_in" ON risk_settings FOR SELECT TO authenticated
  USING (true);
DROP POLICY IF EXISTS "risk_settings_insert_admin" ON risk_settings;
CREATE POLICY "risk_settings_insert_admin" ON risk_settings FOR INSERT TO authenticated
  WITH CHECK (public.is_platform_admin());
DROP POLICY IF EXISTS "risk_settings_update_admin" ON risk_settings;
CREATE POLICY "risk_settings_update_admin" ON risk_settings FOR UPDATE TO authenticated
  USING (public.is_platform_admin()) WITH CHECK (public.is_platform_admin());
DROP POLICY IF EXISTS "risk_settings_delete_admin" ON risk_settings;
CREATE POLICY "risk_settings_delete_admin" ON risk_settings FOR DELETE TO authenticated
  USING (public.is_platform_admin());

-- system_settings (global rows are admin_id null; reseller rows are scoped)
DROP POLICY IF EXISTS "system_settings_select_scoped" ON system_settings;
CREATE POLICY "system_settings_select_scoped" ON system_settings FOR SELECT TO authenticated
  USING (
    public.is_platform_admin()
    OR admin_id IS NULL
    OR admin_id = (SELECT p.admin_id FROM profiles p WHERE p.id = auth.uid())
  );
DROP POLICY IF EXISTS "system_settings_insert_scoped" ON system_settings;
CREATE POLICY "system_settings_insert_scoped" ON system_settings FOR INSERT TO authenticated
  WITH CHECK (public.is_super_admin() OR admin_id = auth.uid());
DROP POLICY IF EXISTS "system_settings_update_scoped" ON system_settings;
CREATE POLICY "system_settings_update_scoped" ON system_settings FOR UPDATE TO authenticated
  USING (public.is_super_admin() OR admin_id = auth.uid())
  WITH CHECK (public.is_super_admin() OR admin_id = auth.uid());
DROP POLICY IF EXISTS "system_settings_delete_scoped" ON system_settings;
CREATE POLICY "system_settings_delete_scoped" ON system_settings FOR DELETE TO authenticated
  USING (public.is_super_admin() OR admin_id = auth.uid());

-- signals and sentiment (read by signed-in users; admin writes)
DROP POLICY IF EXISTS "signals_select_signed_in" ON signals;
CREATE POLICY "signals_select_signed_in" ON signals FOR SELECT TO authenticated
  USING (true);
DROP POLICY IF EXISTS "signals_insert_admin" ON signals;
CREATE POLICY "signals_insert_admin" ON signals FOR INSERT TO authenticated
  WITH CHECK (public.is_platform_admin());
DROP POLICY IF EXISTS "signals_update_admin" ON signals;
CREATE POLICY "signals_update_admin" ON signals FOR UPDATE TO authenticated
  USING (public.is_platform_admin()) WITH CHECK (public.is_platform_admin());
DROP POLICY IF EXISTS "signals_delete_admin" ON signals;
CREATE POLICY "signals_delete_admin" ON signals FOR DELETE TO authenticated
  USING (public.is_platform_admin());

DROP POLICY IF EXISTS "sentiment_scores_select_signed_in" ON sentiment_scores;
CREATE POLICY "sentiment_scores_select_signed_in" ON sentiment_scores FOR SELECT TO authenticated
  USING (true);
DROP POLICY IF EXISTS "sentiment_scores_insert_admin" ON sentiment_scores;
CREATE POLICY "sentiment_scores_insert_admin" ON sentiment_scores FOR INSERT TO authenticated
  WITH CHECK (public.is_platform_admin());
DROP POLICY IF EXISTS "sentiment_scores_update_admin" ON sentiment_scores;
CREATE POLICY "sentiment_scores_update_admin" ON sentiment_scores FOR UPDATE TO authenticated
  USING (public.is_platform_admin()) WITH CHECK (public.is_platform_admin());
DROP POLICY IF EXISTS "sentiment_scores_delete_admin" ON sentiment_scores;
CREATE POLICY "sentiment_scores_delete_admin" ON sentiment_scores FOR DELETE TO authenticated
  USING (public.is_platform_admin());

-- client_updates
DROP POLICY IF EXISTS "client_updates_select_owner_or_admin" ON client_updates;
CREATE POLICY "client_updates_select_owner_or_admin" ON client_updates FOR SELECT TO authenticated
  USING (client_id = auth.uid() OR public.is_platform_admin());
DROP POLICY IF EXISTS "client_updates_insert_admin" ON client_updates;
CREATE POLICY "client_updates_insert_admin" ON client_updates FOR INSERT TO authenticated
  WITH CHECK (public.is_platform_admin());
DROP POLICY IF EXISTS "client_updates_update_admin" ON client_updates;
CREATE POLICY "client_updates_update_admin" ON client_updates FOR UPDATE TO authenticated
  USING (public.is_platform_admin()) WITH CHECK (public.is_platform_admin());
DROP POLICY IF EXISTS "client_updates_delete_admin" ON client_updates;
CREATE POLICY "client_updates_delete_admin" ON client_updates FOR DELETE TO authenticated
  USING (public.is_platform_admin());

-- admin_activity_log (any signed-in user may file an entry, e.g. bug reports; only admins read)
DROP POLICY IF EXISTS "admin_activity_log_select_admin" ON admin_activity_log;
CREATE POLICY "admin_activity_log_select_admin" ON admin_activity_log FOR SELECT TO authenticated
  USING (public.is_platform_admin());
DROP POLICY IF EXISTS "admin_activity_log_insert_signed_in" ON admin_activity_log;
CREATE POLICY "admin_activity_log_insert_signed_in" ON admin_activity_log FOR INSERT TO authenticated
  WITH CHECK (true);
DROP POLICY IF EXISTS "admin_activity_log_update_admin" ON admin_activity_log;
CREATE POLICY "admin_activity_log_update_admin" ON admin_activity_log FOR UPDATE TO authenticated
  USING (public.is_super_admin()) WITH CHECK (public.is_super_admin());
DROP POLICY IF EXISTS "admin_activity_log_delete_admin" ON admin_activity_log;
CREATE POLICY "admin_activity_log_delete_admin" ON admin_activity_log FOR DELETE TO authenticated
  USING (public.is_super_admin());

-- credit_requests (approved through approve_credit_request)
DROP POLICY IF EXISTS "credit_requests_select_admin" ON credit_requests;
CREATE POLICY "credit_requests_select_admin" ON credit_requests FOR SELECT TO authenticated
  USING (public.is_platform_admin());
DROP POLICY IF EXISTS "credit_requests_insert_own" ON credit_requests;
CREATE POLICY "credit_requests_insert_own" ON credit_requests FOR INSERT TO authenticated
  WITH CHECK (sub_admin_id = auth.uid() AND public.is_platform_admin());

-- transactions (payment records; super admin writes)
DROP POLICY IF EXISTS "transactions_select_admin" ON transactions;
CREATE POLICY "transactions_select_admin" ON transactions FOR SELECT TO authenticated
  USING (public.is_platform_admin());
DROP POLICY IF EXISTS "transactions_insert_super" ON transactions;
CREATE POLICY "transactions_insert_super" ON transactions FOR INSERT TO authenticated
  WITH CHECK (public.is_super_admin());
DROP POLICY IF EXISTS "transactions_update_super" ON transactions;
CREATE POLICY "transactions_update_super" ON transactions FOR UPDATE TO authenticated
  USING (public.is_super_admin()) WITH CHECK (public.is_super_admin());
DROP POLICY IF EXISTS "transactions_delete_super" ON transactions;
CREATE POLICY "transactions_delete_super" ON transactions FOR DELETE TO authenticated
  USING (public.is_super_admin());

-- profiles: owner-scoped SELECT/INSERT policies for the profile row used by sign-up
-- (covered above)

CREATE OR REPLACE FUNCTION public.get_master_settings()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT COALESCE(jsonb_object_agg(s.key, s.value), '{}'::jsonb)
  FROM system_settings s
  WHERE s.admin_id IS NULL;
$$;

CREATE OR REPLACE FUNCTION public.find_user_by_email(p_email text)
RETURNS TABLE (id uuid, email text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT p.id, p.email
  FROM profiles p
  WHERE lower(p.email) = lower(p_email) AND public.is_platform_admin()
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.allot_license(
  p_target_user_id uuid,
  p_plan_type text,
  p_validity_days integer,
  p_allowed_bots text[] DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_bots text[];
  v_limit integer;
BEGIN
  IF NOT public.is_platform_admin() THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  IF p_plan_type NOT IN ('starter', 'pro', 'enterprise') THEN
    RAISE EXCEPTION 'Unknown plan: %', p_plan_type;
  END IF;
  IF p_validity_days IS NULL OR p_validity_days < 1 THEN
    RAISE EXCEPTION 'Validity must be at least 1 day';
  END IF;

  v_limit := CASE p_plan_type WHEN 'starter' THEN 2 WHEN 'pro' THEN 5 ELSE 9999 END;

  SELECT l.allowed_bots INTO v_bots
  FROM licenses l
  WHERE l.user_id = p_target_user_id AND l.is_active
  ORDER BY l.created_at DESC
  LIMIT 1;
  v_bots := COALESCE(p_allowed_bots, v_bots);

  UPDATE licenses SET is_active = false WHERE user_id = p_target_user_id AND is_active;

  INSERT INTO licenses (user_id, plan_name, bot_limit, is_active, valid_from, valid_until, monthly_fee, allowed_bots)
  VALUES (p_target_user_id, p_plan_type, v_limit, true, now(), now() + make_interval(days => p_validity_days), 0, v_bots);
END;
$$;

CREATE OR REPLACE FUNCTION public.transfer_credits(p_target_email text, p_credits numeric)
RETURNS TABLE (target_name text, new_balance numeric)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_caller admin_roles%ROWTYPE;
  v_target admin_roles%ROWTYPE;
BEGIN
  SELECT * INTO v_caller FROM admin_roles WHERE user_id = auth.uid() AND is_active;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  IF p_credits IS NULL OR p_credits < 1 THEN
    RAISE EXCEPTION 'Enter a valid credit amount (minimum 1)';
  END IF;

  SELECT * INTO v_target FROM admin_roles WHERE lower(email) = lower(p_target_email) AND is_active;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'No active admin found with that email';
  END IF;
  IF v_target.id = v_caller.id THEN
    RAISE EXCEPTION 'Cannot transfer credits to yourself';
  END IF;

  IF v_caller.role = 'sub_admin' THEN
    IF v_caller.credit_balance < p_credits THEN
      RAISE EXCEPTION 'Insufficient credits';
    END IF;
    UPDATE admin_roles SET credit_balance = credit_balance - p_credits WHERE id = v_caller.id;
  END IF;

  UPDATE admin_roles SET credit_balance = credit_balance + p_credits WHERE id = v_target.id;

  RETURN QUERY SELECT COALESCE(v_target.name, v_target.email), v_target.credit_balance + p_credits;
END;
$$;

CREATE OR REPLACE FUNCTION public.approve_credit_request(req_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_req credit_requests%ROWTYPE;
  v_rows integer;
BEGIN
  IF NOT public.is_super_admin() THEN
    RETURN jsonb_build_object('success', false, 'error', 'Only super admins can approve credit requests');
  END IF;

  SELECT * INTO v_req FROM credit_requests WHERE id = req_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error', 'Request not found');
  END IF;
  IF v_req.status <> 'pending' THEN
    RETURN jsonb_build_object('success', false, 'error', 'Request is not pending');
  END IF;

  UPDATE admin_roles SET credit_balance = credit_balance + v_req.credits_requested WHERE user_id = v_req.sub_admin_id;
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  IF v_rows = 0 THEN
    RETURN jsonb_build_object('success', false, 'error', 'Sub-admin account not found');
  END IF;

  UPDATE credit_requests SET status = 'approved', processed_at = now() WHERE id = req_id;
  RETURN jsonb_build_object('success', true);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.is_platform_admin() FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.is_super_admin() FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.get_master_settings() FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.find_user_by_email(text) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.allot_license(uuid, text, integer, text[]) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.transfer_credits(text, numeric) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.approve_credit_request(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_platform_admin() TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_super_admin() TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_master_settings() TO authenticated;
GRANT EXECUTE ON FUNCTION public.find_user_by_email(text) TO authenticated;
GRANT EXECUTE ON FUNCTION public.allot_license(uuid, text, integer, text[]) TO authenticated;
GRANT EXECUTE ON FUNCTION public.transfer_credits(text, numeric) TO authenticated;
GRANT EXECUTE ON FUNCTION public.approve_credit_request(uuid) TO authenticated;

INSERT INTO risk_settings (global_kill_switch)
SELECT false
WHERE NOT EXISTS (SELECT 1 FROM risk_settings);

INSERT INTO api_settings (id)
SELECT gen_random_uuid()
WHERE NOT EXISTS (SELECT 1 FROM api_settings);

INSERT INTO profiles (id, email)
SELECT u.id, COALESCE(u.email, '')
FROM auth.users u
WHERE NOT EXISTS (SELECT 1 FROM profiles p WHERE p.id = u.id);

INSERT INTO admin_roles (user_id, email, name, role)
SELECT u.id, u.email, 'Master Admin', 'super_admin'
FROM auth.users u
WHERE lower(u.email) = 'vinodbardev@gmail.com'
  AND NOT EXISTS (SELECT 1 FROM admin_roles r WHERE r.user_id = u.id);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['admin_roles', 'bots', 'trades', 'positions', 'client_updates']
  LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = t
    ) THEN
      EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I', t);
    END IF;
  END LOOP;
END;
$$;
