-- Local entitlement source for self-hosted anarlog deployments.
--
-- Upstream, custom_access_token_hook derives the `entitlements` JWT claim
-- solely from stripe.active_entitlements. With no Stripe configured that table
-- is empty, so every token carries `entitlements: []` and the client reports
-- isPaid = false.
--
-- Do NOT seed stripe.active_entitlements directly: its `lookup_key` column is
-- UNIQUE, so you would get exactly one 'hyprnote_pro' row across all users.
--
-- This migration adds a separate local table and UNIONs it into the existing
-- lookup. Only the entitlements SELECT changes; the subscription_status and
-- trial_end logic is copied verbatim from upstream so this stays easy to rebase.

begin;

create table if not exists public.local_entitlements (
  user_id    uuid not null references auth.users(id) on delete cascade,
  lookup_key text not null,
  granted_at timestamptz not null default now(),
  primary key (user_id, lookup_key)
);

comment on table public.local_entitlements is
  'Self-hosted entitlement grants. Unioned into the JWT entitlements claim by custom_access_token_hook.';

-- Deliberately NOT using RLS here. The hook is STABLE, not SECURITY DEFINER, so
-- it executes as supabase_auth_admin; an RLS policy that role does not satisfy
-- would silently yield an empty entitlements array and be painful to debug.
-- Revoking table privileges is sufficient to keep it off PostgREST.
revoke all on table public.local_entitlements from public, anon, authenticated;
grant select on table public.local_entitlements to supabase_auth_admin;
grant all    on table public.local_entitlements to service_role;

create or replace function public.custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
stable
as $$
declare
  claims jsonb;
  entitlements jsonb := '[]'::jsonb;
  v_user_id uuid := (event->>'user_id')::uuid;
  v_customer_id text;
  v_subscription_status text;
  v_trial_end bigint;
begin
  select p.stripe_customer_id
    into v_customer_id
    from public.profiles p
   where p.id = v_user_id;

  -- ── CHANGED FROM UPSTREAM ────────────────────────────────────────────────
  -- Union the Stripe-derived entitlements with locally granted ones so a
  -- self-hosted deployment works without billing, while a Stripe-backed one
  -- keeps functioning unchanged.
  select coalesce(
           jsonb_agg(distinct src.lookup_key order by src.lookup_key),
           '[]'::jsonb
         )
    into entitlements
    from (
      select ae.lookup_key
        from public.profiles p
        join stripe.active_entitlements ae
          on ae.customer = p.stripe_customer_id
       where p.id = v_user_id
         and ae.lookup_key is not null

      union

      select le.lookup_key
        from public.local_entitlements le
       where le.user_id = v_user_id
    ) src;
  -- ── END CHANGE ───────────────────────────────────────────────────────────

  if v_customer_id is not null then
    select s.status::text,
           (s.trial_end #>> '{}')::bigint
      into v_subscription_status, v_trial_end
      from stripe.subscriptions s
     where s.customer = v_customer_id
       and s.status in ('trialing', 'active')
     order by case s.status when 'active' then 1 when 'trialing' then 2 end,
              s.created desc
     limit 1;
  end if;

  claims := event->'claims';
  claims := jsonb_set(claims, '{entitlements}', entitlements);

  if v_subscription_status is not null then
    claims := jsonb_set(claims, '{subscription_status}', to_jsonb(v_subscription_status));
  end if;

  if v_trial_end is not null then
    claims := jsonb_set(claims, '{trial_end}', to_jsonb(v_trial_end));
  end if;

  event := jsonb_set(event, '{claims}', claims);

  return event;
end;
$$;

commit;


-- ─────────────────────────────────────────────────────────────────────────────
-- Grant yourself Pro. Run separately AFTER you have signed up at least once,
-- because the row references auth.users and your account must exist first.
--
--   insert into public.local_entitlements (user_id, lookup_key)
--   select id, 'hyprnote_pro'
--     from auth.users
--    where email = 'you@example.com'
--   on conflict do nothing;
--
-- Verify:
--   select u.email, le.lookup_key
--     from public.local_entitlements le
--     join auth.users u on u.id = le.user_id;
-- ─────────────────────────────────────────────────────────────────────────────
