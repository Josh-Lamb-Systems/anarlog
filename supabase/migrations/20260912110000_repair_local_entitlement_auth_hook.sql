-- The original local-entitlement migration replaced the current upstream hook
-- and dropped billing, workspace, SSO, and OAuth behavior. Compose with the
-- preserved upstream hook instead, then add self-hosted grants to its result.
CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = ''
AS $$
DECLARE
  claims jsonb;
  entitlements jsonb;
  v_user_id uuid := (event->>'user_id')::uuid;
BEGIN
  event := public.custom_access_token_hook_base(event);
  claims := event->'claims';

  SELECT COALESCE(
    jsonb_agg(granted.lookup_key ORDER BY granted.lookup_key),
    '[]'::jsonb
  )
  INTO entitlements
  FROM (
    SELECT jsonb_array_elements_text(
      COALESCE(claims->'entitlements', '[]'::jsonb)
    ) AS lookup_key

    UNION

    SELECT entitlement.lookup_key
    FROM public.local_entitlements AS entitlement
    WHERE entitlement.user_id = v_user_id
  ) AS granted;

  claims := jsonb_set(claims, '{entitlements}', entitlements);

  IF NULLIF(claims->>'client_id', '') IS NOT NULL THEN
    claims := jsonb_set(
      claims,
      '{aud}',
      '["https://api.anarlog.so/mcp"]'::jsonb
    );
  END IF;

  event := jsonb_set(event, '{claims}', claims);

  RETURN event;
END;
$$;

GRANT EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb)
  TO supabase_auth_admin;
REVOKE EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb)
  FROM authenticated, anon, public;
