-- Regression fixture: one table per check, each with a known expected result.
-- Expected summary: 2 crit, 2 high, 2 med; t_good INFO only; t_forced no findings.
-- Supabase-like setup: roles + auth.uid()
create role anon nologin;
create role authenticated nologin;
create schema auth;
create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;

-- 1) RLS off, granted to anon  -> expect CRITICAL
create table public.t_rls_off (id int primary key, user_id uuid not null);
grant select on public.t_rls_off to anon, authenticated;

-- 2) USING (true)  -> CRITICAL
create table public.t_using_true (id int primary key, user_id uuid not null);
alter table public.t_using_true enable row level security;
create policy p_all on public.t_using_true for select to anon, authenticated using (true);
grant select on public.t_using_true to anon, authenticated;

-- 3) logged-in check only  -> HIGH
create table public.t_logged_in (id int primary key, user_id uuid not null);
alter table public.t_logged_in enable row level security;
create policy p_read on public.t_logged_in for select to authenticated using (auth.uid() is not null);
grant select on public.t_logged_in to authenticated;

-- 4) INSERT, WITH CHECK (true)  -> HIGH
create table public.t_insert_open (id int primary key, user_id uuid not null);
alter table public.t_insert_open enable row level security;
create policy p_sel on public.t_insert_open for select to authenticated using (auth.uid() = user_id);
create policy p_ins on public.t_insert_open for insert to authenticated with check (true);
grant select, insert on public.t_insert_open to authenticated;

-- 5) nullable owner column  -> MEDIUM
create table public.t_nullable_owner (id int primary key, user_id uuid);
alter table public.t_nullable_owner enable row level security;
create policy p_own on public.t_nullable_owner for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
grant select, insert, update, delete on public.t_nullable_owner to authenticated;

-- 6) RLS on, no policies  -> MEDIUM
create table public.t_no_policy (id int primary key, user_id uuid not null);
alter table public.t_no_policy enable row level security;
grant select on public.t_no_policy to authenticated;

-- 7) correct, not forced  -> INFO only
create table public.t_good (id int primary key, user_id uuid not null);
alter table public.t_good enable row level security;
create policy p_own on public.t_good for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
grant select, insert, update, delete on public.t_good to authenticated;

-- 8) correct + FORCE  -> no findings
create table public.t_forced (id int primary key, user_id uuid not null);
alter table public.t_forced enable row level security;
alter table public.t_forced force row level security;
create policy p_own on public.t_forced for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
grant select, insert, update, delete on public.t_forced to authenticated;

-- 9) view over an RLS table, owner's rights, readable by anon  -> CRITICAL (VIEW_BYPASSES_RLS)
create view public.v_leak as select * from public.t_good;
grant select on public.v_leak to anon, authenticated;

-- 10) same view with security_invoker  -> no finding
create view public.v_ok with (security_invoker = true) as select * from public.t_good;
grant select on public.v_ok to anon, authenticated;

-- 11) SECURITY DEFINER, callable by anon, never checks auth.uid(), mutable search_path
--     -> HIGH (DEFINER_FUNCTION_EXPOSED) + MEDIUM (DEFINER_SEARCH_PATH)
create function public.f_reset_all() returns void language sql security definer as $$ delete from public.t_good $$;
grant execute on function public.f_reset_all() to anon, authenticated;

-- 12) SECURITY DEFINER scoped to the caller, pinned search_path  -> INFO only
create function public.f_my_rows() returns setof public.t_good language sql security definer set search_path = ''
  as $$ select * from public.t_good where user_id = auth.uid() $$;
revoke execute on function public.f_my_rows() from public, anon;
grant execute on function public.f_my_rows() to authenticated;
