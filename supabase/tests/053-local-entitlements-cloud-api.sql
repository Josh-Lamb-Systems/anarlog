begin;
select plan(4);

select tests.create_supabase_user(
  'local_cloud_api_user',
  'local-cloud-api-user@example.com'
);

select tests.authenticate_as_service_role();

insert into public.local_entitlements (user_id, lookup_key)
values (
  tests.get_supabase_uid('local_cloud_api_user'),
  'hyprnote_pro'
);

select results_eq(
  format(
    $$
      select status
      from public.verify_cloud_api_user(%L::uuid)
    $$,
    tests.get_supabase_uid('local_cloud_api_user')
  ),
  array['cloud_api_not_enabled'::text],
  'A local Pro entitlement authorizes Cloud API opt-in'
);

select results_eq(
  format(
    $$
      select enabled
      from public.set_cloud_api_enabled(%L::uuid, true)
    $$,
    tests.get_supabase_uid('local_cloud_api_user')
  ),
  array[true],
  'A locally entitled user can enable Cloud API & Connectors'
);

select results_eq(
  format(
    $$
      select status
      from public.verify_cloud_api_user(%L::uuid)
    $$,
    tests.get_supabase_uid('local_cloud_api_user')
  ),
  array['ok'::text],
  'An opted-in locally entitled user verifies successfully'
);

delete from public.local_entitlements
where user_id = tests.get_supabase_uid('local_cloud_api_user')
  and lookup_key = 'hyprnote_pro';

select results_eq(
  format(
    $$
      select status
      from public.verify_cloud_api_user(%L::uuid)
    $$,
    tests.get_supabase_uid('local_cloud_api_user')
  ),
  array['subscription_required'::text],
  'Removing the local Pro entitlement revokes Cloud API access'
);

select * from finish();
rollback;
