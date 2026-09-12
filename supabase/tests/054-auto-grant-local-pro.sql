begin;
select plan(8);

select ok(
  to_regclass('private.local_entitlement_settings') is not null
    and not has_table_privilege(
      'authenticated',
      'private.local_entitlement_settings',
      'SELECT'
    )
    and not has_table_privilege(
      'authenticated',
      'private.local_entitlement_settings',
      'UPDATE'
    ),
  'Local entitlement settings are private'
);

select ok(
  exists (
    select 1
    from pg_proc as procedure
    join pg_namespace as namespace
      on namespace.oid = procedure.pronamespace
    where namespace.nspname = 'private'
      and procedure.proname = 'handle_new_user_local_pro'
      and procedure.prosecdef
      and 'search_path=""' = any(
        coalesce(procedure.proconfig, array[]::text[])
      )
  ),
  'The automatic grant trigger function is hardened'
);

select ok(
  exists (
    select 1
    from pg_trigger as trigger
    where trigger.tgrelid = 'auth.users'::regclass
      and trigger.tgname = 'on_auth_user_local_pro_created'
      and trigger.tgenabled = 'O'
      and not trigger.tgisinternal
  ),
  'The automatic grant trigger is enabled on auth.users'
);

update private.local_entitlement_settings
set auto_grant_pro_to_new_users = true
where singleton;

select tests.create_supabase_user(
  'auto_local_pro',
  'auto-local-pro@example.com'
);

select results_eq(
  $$
    select lookup_key
    from public.local_entitlements
    where user_id = tests.get_supabase_uid('auto_local_pro')
  $$,
  array['hyprnote_pro'::text],
  'A new non-anonymous user receives the local Pro entitlement'
);

select results_eq(
  $$
    select (
      public.custom_access_token_hook(
        jsonb_build_object(
          'user_id', tests.get_supabase_uid('auto_local_pro')::text,
          'claims', '{}'::jsonb
        )
      ) -> 'claims' -> 'entitlements'
    )::jsonb
  $$,
  array['["hyprnote_pro"]'::jsonb],
  'The automatic grant appears in new access tokens'
);

select results_eq(
  format(
    $$
      select status
      from public.verify_cloud_api_user(%L::uuid)
    $$,
    tests.get_supabase_uid('auto_local_pro')
  ),
  array['cloud_api_not_enabled'::text],
  'The automatic grant authorizes Cloud API opt-in'
);

insert into auth.users (
  id,
  raw_user_meta_data,
  raw_app_meta_data,
  is_anonymous,
  created_at,
  updated_at
)
values (
  gen_random_uuid(),
  '{}'::jsonb,
  '{}'::jsonb,
  true,
  now(),
  now()
);

select results_eq(
  $$
    select count(*)
    from public.local_entitlements as entitlement
    join auth.users as account
      on account.id = entitlement.user_id
    where account.is_anonymous
      and entitlement.lookup_key = 'hyprnote_pro'
  $$,
  array[0::bigint],
  'Anonymous users do not receive Pro'
);

update private.local_entitlement_settings
set auto_grant_pro_to_new_users = false
where singleton;

select tests.create_supabase_user(
  'auto_local_pro_disabled',
  'auto-local-pro-disabled@example.com'
);

select results_eq(
  $$
    select count(*)
    from public.local_entitlements
    where user_id = tests.get_supabase_uid('auto_local_pro_disabled')
  $$,
  array[0::bigint],
  'The deployment setting can disable automatic grants'
);

select * from finish();
rollback;
