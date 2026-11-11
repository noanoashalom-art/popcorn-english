-- Popcorn English · קריאה אקדמית
-- Paste this whole file in Supabase: SQL Editor → New query → Run.
-- Students sign in with a nickname + 4-digit code. The table itself is closed;
-- the site can only use the functions below.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.students (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  name_key    text not null unique,
  pin_hash    text not null,
  token       uuid not null default gen_random_uuid() unique,
  data        jsonb,
  stars       int  not null default 0,
  week_id     int  not null default 0,
  week_stars  int  not null default 0,
  level       int  not null default 1,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

alter table public.students enable row level security;
revoke all on public.students from anon, authenticated;

create or replace function public.sign_up(p_name text, p_pin text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare t uuid; k text := lower(btrim(p_name));
begin
  if length(k) < 2 or length(k) > 24 then raise exception 'bad_name'; end if;
  if p_pin !~ '^[0-9]{4}$' then raise exception 'bad_pin'; end if;
  if exists (select 1 from students where name_key = k) then raise exception 'name_taken'; end if;
  insert into students(name, name_key, pin_hash) values (btrim(p_name), k, crypt(p_pin, gen_salt('bf'))) returning token into t;
  return t;
end $$;

create or replace function public.login(p_name text, p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare r students;
begin
  select * into r from students where name_key = lower(btrim(p_name));
  if r.id is null or r.pin_hash <> crypt(p_pin, r.pin_hash) then
    perform pg_sleep(0.5);
    raise exception 'bad_login';
  end if;
  return json_build_object('token', r.token, 'name', r.name, 'data', r.data);
end $$;

create or replace function public.load_progress(p_token uuid) returns json
language plpgsql security definer set search_path = public as $$
declare r students;
begin
  select * into r from students where token = p_token;
  if r.id is null then raise exception 'bad_token'; end if;
  return json_build_object('name', r.name, 'data', r.data);
end $$;

create or replace function public.save_progress(p_token uuid, p_data jsonb, p_stars int, p_week int, p_week_stars int, p_level int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if pg_column_size(p_data) > 3000000 then raise exception 'too_big'; end if;
  update students set data = p_data, stars = greatest(0, p_stars), week_id = p_week,
         week_stars = greatest(0, p_week_stars), level = least(greatest(p_level, 1), 5), updated_at = now()
   where token = p_token;
  if not found then raise exception 'bad_token'; end if;
end $$;

create or replace function public.leaderboard() returns table(pid text, name text, stars int, week_id int, week_stars int, level int)
language sql security definer set search_path = public as $$
  select coalesce(data->>'id', id::text), name, stars, week_id, week_stars, level
    from students order by stars desc limit 100;
$$;

revoke all on function public.sign_up(text, text), public.login(text, text), public.load_progress(uuid),
  public.save_progress(uuid, jsonb, int, int, int, int), public.leaderboard() from public;
grant execute on function public.sign_up(text, text), public.login(text, text), public.load_progress(uuid),
  public.save_progress(uuid, jsonb, int, int, int, int), public.leaderboard() to anon, authenticated;
