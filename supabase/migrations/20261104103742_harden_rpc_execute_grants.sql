/*
# Restrict admin and settings RPCs to signed-in users

## Plain-English summary
Five database functions (remote procedure calls) are reachable from the app's API. By default Postgres lets the public role, including logged-out visitors, run any function. This migration removes that default for the five functions that the app uses, so only signed-in users can call them.

## Functions affected
- allot_license(uuid, text, integer, text[]) - admin-only internally, now signed-in only.
- approve_credit_request(uuid) - super admin only internally, now signed-in only.
- find_user_by_email(text) - admin only internally, now signed-in only.
- get_master_settings() - read-only global settings used by paid-plan screens, now signed-in only.
- transfer_credits(text, numeric) - admin only internally, now signed-in only.

## Security changes
- REVOKE EXECUTE from PUBLIC and anon on each function above.
- Existing authenticated grants are left unchanged.
- Each function already checks the caller's role (or auth.uid()) internally, except get_master_settings, which returns only global settings intended for signed-in clients.

## Important notes
1. No data is changed. Only function execution rights are adjusted.
2. Re-running this migration is safe.
*/

REVOKE EXECUTE ON FUNCTION public.allot_license(uuid, text, integer, text[]) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.approve_credit_request(uuid) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.find_user_by_email(text) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.get_master_settings() FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.transfer_credits(text, numeric) FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION public.allot_license(uuid, text, integer, text[]) TO authenticated;
GRANT EXECUTE ON FUNCTION public.approve_credit_request(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.find_user_by_email(text) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_master_settings() TO authenticated;
GRANT EXECUTE ON FUNCTION public.transfer_credits(text, numeric) TO authenticated;
