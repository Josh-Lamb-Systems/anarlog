BEGIN;

CREATE TABLE private.local_entitlement_settings (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  auto_grant_pro_to_new_users boolean NOT NULL DEFAULT true
);

COMMENT ON TABLE private.local_entitlement_settings IS
  'Deployment settings for self-hosted local entitlement grants.';

REVOKE ALL ON TABLE private.local_entitlement_settings
  FROM PUBLIC, anon, authenticated;

INSERT INTO private.local_entitlement_settings (
  singleton,
  auto_grant_pro_to_new_users
)
VALUES (true, true)
ON CONFLICT (singleton) DO NOTHING;

CREATE OR REPLACE FUNCTION private.handle_new_user_local_pro()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF COALESCE(NEW.is_anonymous, false) THEN
    RETURN NEW;
  END IF;

  IF NOT COALESCE(
    (
      SELECT settings.auto_grant_pro_to_new_users
      FROM private.local_entitlement_settings AS settings
      WHERE settings.singleton
    ),
    false
  ) THEN
    RETURN NEW;
  END IF;

  INSERT INTO public.local_entitlements (user_id, lookup_key)
  VALUES (NEW.id, 'hyprnote_pro')
  ON CONFLICT (user_id, lookup_key) DO NOTHING;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION private.handle_new_user_local_pro()
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION private.handle_new_user_local_pro()
  TO supabase_auth_admin;

DROP TRIGGER IF EXISTS on_auth_user_local_pro_created ON auth.users;
CREATE TRIGGER on_auth_user_local_pro_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION private.handle_new_user_local_pro();

COMMIT;
