-- Popcorn English · teacher tools (delete students)
-- 1) Replace MY-PASSWORD below with a password only you know (keep the quotes).
-- 2) Paste the whole file in Supabase: SQL Editor → New query → Run.
-- To change the password later, run only the last statement again with a new password.

create table if not exists public.admin_settings (
  id int primary key default 1 check (id = 1),
  pass_hash text not null
);
alter table public.admin_settings enable row level security;
revoke all on public.admin_settings from anon, authenticated;

create or replace function public.admin_ok(p_pass text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare h text;
begin
  select pass_hash into h from admin_settings where id = 1;
  if h is null or h <> crypt(p_pass, h) then perform pg_sleep(0.7); return false; end if;
  return true;
end $$;

create or replace function public.admin_list(p_pass text)
returns table(id uuid, name text, stars int, level int, created_at timestamptz, updated_at timestamptz)
language plpgsql security definer set search_path = public as $$
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  return query select s.id, s.name, s.stars, s.level, s.created_at, s.updated_at from students s order by s.name_key;
end $$;

create or replace function public.admin_delete(p_pass text, p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  delete from students where students.id = p_id;
end $$;

revoke all on function public.admin_ok(text), public.admin_list(text), public.admin_delete(text, uuid) from public;
grant execute on function public.admin_list(text), public.admin_delete(text, uuid) to anon, authenticated;

insert into public.admin_settings(id, pass_hash) values (1, extensions.crypt('MY-PASSWORD', extensions.gen_salt('bf')))
on conflict (id) do update set pass_hash = excluded.pass_hash;
