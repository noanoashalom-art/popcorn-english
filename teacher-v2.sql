-- Popcorn English · teacher tools v2: classes, approving new students, each student's progress, blocking access
-- Run AFTER teacher-setup.sql (it uses the same teacher password).
-- Paste the whole file in Supabase: SQL Editor → New query → Run.

-- 0) classes: the teacher opens a class and gives students its code
create extension if not exists pgcrypto with schema extensions;
create table if not exists public.classes (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  code text not null unique,
  created_at timestamptz not null default now()
);
alter table public.classes enable row level security;
revoke all on public.classes from anon, authenticated;
alter table public.students add column if not exists class_id uuid references public.classes(id) on delete set null;

-- 1) every student who already exists stays approved; new sign-ups wait for the teacher
alter table public.students add column if not exists approved boolean not null default true;
alter table public.students alter column approved set default false;

-- 2) sign-up creates a waiting account (no token is handed out until the teacher approves)
drop function if exists public.sign_up(text, text);
create or replace function public.sign_up(p_name text, p_pin text, p_class text default null) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare k text := lower(btrim(p_name)); c uuid;
begin
  if length(k) < 2 or length(k) > 24 then raise exception 'bad_name'; end if;
  if p_pin !~ '^[0-9]{4}$' then raise exception 'bad_pin'; end if;
  if exists (select 1 from students where name_key = k) then raise exception 'name_taken'; end if;
  if coalesce(btrim(p_class), '') <> '' then
    select id into c from classes where code = upper(btrim(p_class));
    if c is null then raise exception 'bad_class'; end if;
  end if;
  insert into students(name, name_key, pin_hash, approved, class_id) values (btrim(p_name), k, crypt(p_pin, gen_salt('bf')), false, c);
  return null;
end $$;
revoke all on function public.sign_up(text, text, text) from public;
grant execute on function public.sign_up(text, text, text) to anon, authenticated;

create or replace function public.login(p_name text, p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare r students;
begin
  select * into r from students where name_key = lower(btrim(p_name));
  if r.id is null or r.pin_hash <> crypt(p_pin, r.pin_hash) then
    perform pg_sleep(0.5);
    raise exception 'bad_login';
  end if;
  if not r.approved then raise exception 'pending'; end if;
  return json_build_object('token', r.token, 'name', r.name, 'data', r.data);
end $$;

create or replace function public.load_progress(p_token uuid) returns json
language plpgsql security definer set search_path = public as $$
declare r students;
begin
  select * into r from students where token = p_token;
  if r.id is null then raise exception 'bad_token'; end if;
  if not r.approved then raise exception 'pending'; end if;
  return json_build_object('name', r.name, 'data', r.data);
end $$;

create or replace function public.save_progress(p_token uuid, p_data jsonb, p_stars int, p_week int, p_week_stars int, p_level int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if pg_column_size(p_data) > 3000000 then raise exception 'too_big'; end if;
  update students set data = p_data, stars = greatest(0, p_stars), week_id = p_week,
         week_stars = greatest(0, p_week_stars), level = least(greatest(p_level, 1), 5), updated_at = now()
   where token = p_token and approved;
  if not found then raise exception 'bad_token'; end if;
end $$;

create or replace function public.leaderboard() returns table(pid text, name text, stars int, week_id int, week_stars int, level int)
language sql security definer set search_path = public as $$
  select coalesce(data->>'id', id::text), name, stars, week_id, week_stars, level
    from students where approved order by stars desc limit 100;
$$;

-- 3) teacher functions
create or replace function public.admin_students(p_pass text)
returns table(id uuid, name text, stars int, level int, approved boolean, class_id uuid, created_at timestamptz, updated_at timestamptz)
language plpgsql security definer set search_path = public as $$
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  return query select s.id, s.name, s.stars, s.level, s.approved, s.class_id, s.created_at, s.updated_at from students s order by s.approved, s.name_key;
end $$;

create or replace function public.admin_classes(p_pass text)
returns table(id uuid, name text, code text, n bigint)
language plpgsql security definer set search_path = public as $$
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  return query select c.id, c.name, c.code, (select count(*) from students s where s.class_id = c.id) from classes c order by c.created_at;
end $$;

create or replace function public.admin_class_add(p_pass text, p_name text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare cd text;
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  if length(btrim(p_name)) < 1 then raise exception 'bad_name'; end if;
  loop
    cd := upper(substr(translate(encode(gen_random_bytes(6), 'base64'), '+/=01OIl', ''), 1, 5));
    exit when length(cd) = 5 and not exists (select 1 from classes where code = cd);
  end loop;
  insert into classes(name, code) values (btrim(p_name), cd);
  return cd;
end $$;

create or replace function public.admin_class_del(p_pass text, p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  delete from classes where id = p_id;
end $$;

create or replace function public.admin_set_class(p_pass text, p_id uuid, p_class uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  update students set class_id = p_class where id = p_id;
end $$;

create or replace function public.admin_student(p_pass text, p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare d jsonb;
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  select data into d from students where id = p_id;
  return d;
end $$;

create or replace function public.admin_approve(p_pass text, p_id uuid, p_ok boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  update students set approved = p_ok, token = case when p_ok then token else gen_random_uuid() end where id = p_id;
end $$;

revoke all on function public.admin_students(text), public.admin_student(text, uuid), public.admin_approve(text, uuid, boolean),
  public.admin_classes(text), public.admin_class_add(text, text), public.admin_class_del(text, uuid), public.admin_set_class(text, uuid, uuid) from public;
grant execute on function public.admin_students(text), public.admin_student(text, uuid), public.admin_approve(text, uuid, boolean),
  public.admin_classes(text), public.admin_class_add(text, text), public.admin_class_del(text, uuid), public.admin_set_class(text, uuid, uuid) to anon, authenticated;
