-- Popcorn English · teachers, classes, assignments (includes everything from teacher-v2.sql)
-- Run AFTER teacher-setup.sql (your admin password). You do NOT need to run teacher-v2.sql.
-- Paste the whole file in Supabase: SQL Editor → New query → Run. Safe to run again.

create extension if not exists pgcrypto with schema extensions;

-- ===== tables =====
create table if not exists public.teachers (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  name_key text not null unique,
  pass_hash text not null,
  token uuid not null default gen_random_uuid() unique,
  created_at timestamptz not null default now()
);
create table if not exists public.classes (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  code text not null unique,
  created_at timestamptz not null default now()
);
alter table public.classes add column if not exists color text not null default '#68489A';
alter table public.classes add column if not exists teacher_id uuid references public.teachers(id) on delete set null;
create table if not exists public.assignments (
  id uuid primary key default gen_random_uuid(),
  class_id uuid not null references public.classes(id) on delete cascade,
  kind text not null,
  ref text not null,
  title text not null,
  due date,
  is_test boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.teachers enable row level security;
alter table public.classes enable row level security;
alter table public.assignments enable row level security;
revoke all on public.teachers, public.classes, public.assignments from anon, authenticated;

alter table public.students add column if not exists class_id uuid references public.classes(id) on delete set null;
-- existing students stay approved; only new sign-ups wait
alter table public.students add column if not exists approved boolean not null default true;
alter table public.students alter column approved set default false;

-- ===== who is calling: the admin password, or a teacher's sign-in key =====
create or replace function public.k_role(p_key text, out role text, out tid uuid)
language plpgsql security definer set search_path = public as $$
begin
  if p_key ~ '^[0-9a-f-]{36}$' then
    select id into tid from teachers where token = p_key::uuid;
    if tid is not null then role := 'teacher'; return; end if;
  end if;
  if admin_ok(p_key) then role := 'admin'; tid := null; return; end if;
  raise exception 'bad_admin';
end $$;

create or replace function public.k_class_ok(p_key text, p_class uuid) returns boolean
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  select * into r from k_role(p_key);
  return r.role = 'admin' or exists (select 1 from classes where id = p_class and teacher_id = r.tid);
end $$;

create or replace function public.k_student_ok(p_key text, p_student uuid) returns boolean
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  select * into r from k_role(p_key);
  return r.role = 'admin' or exists (select 1 from students s join classes c on c.id = s.class_id where s.id = p_student and c.teacher_id = r.tid);
end $$;

-- ===== students: sign-up, login, saving =====
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

create or replace function public.login(p_name text, p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare r students;
begin
  select * into r from students where name_key = lower(btrim(p_name));
  if r.id is null or r.pin_hash <> crypt(p_pin, r.pin_hash) then perform pg_sleep(0.5); raise exception 'bad_login'; end if;
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
  select coalesce(data->>'id', id::text), name, stars, week_id, week_stars, level from students where approved order by stars desc limit 100;
$$;

create or replace function public.my_assignments(p_token uuid)
returns table(id uuid, kind text, ref text, title text, due date, is_test boolean, created_at timestamptz, class_name text, color text)
language sql security definer set search_path = public as $$
  select a.id, a.kind, a.ref, a.title, a.due, a.is_test, a.created_at, c.name, c.color
    from students s join classes c on c.id = s.class_id join assignments a on a.class_id = c.id
   where s.token = p_token and s.approved order by a.created_at desc;
$$;

-- ===== teacher sign-in =====
create or replace function public.teacher_login(p_name text, p_pass text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare t teachers;
begin
  select * into t from teachers where name_key = lower(btrim(p_name));
  if t.id is null or t.pass_hash <> crypt(p_pass, t.pass_hash) then perform pg_sleep(0.5); raise exception 'bad_admin'; end if;
  return json_build_object('token', t.token, 'name', t.name);
end $$;

create or replace function public.k_whoami(p_key text) returns json
language plpgsql security definer set search_path = public as $$
declare r record; n text;
begin
  select * into r from k_role(p_key);
  if r.role = 'teacher' then select name into n from teachers where id = r.tid; end if;
  return json_build_object('role', r.role, 'id', r.tid, 'name', coalesce(n, 'מנהלת'));
end $$;

-- ===== students for the teacher (admin: everyone; teacher: only her classes) =====
create or replace function public.t_students(p_key text)
returns table(id uuid, name text, stars int, level int, approved boolean, class_id uuid, created_at timestamptz, updated_at timestamptz)
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  select * into r from k_role(p_key);
  return query select s.id, s.name, s.stars, s.level, s.approved, s.class_id, s.created_at, s.updated_at from students s
    where r.role = 'admin' or s.class_id in (select c.id from classes c where c.teacher_id = r.tid)
    order by s.approved, s.name_key;
end $$;

create or replace function public.t_student(p_key text, p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not k_student_ok(p_key, p_id) then raise exception 'no_access'; end if;
  return (select data from students where id = p_id);
end $$;

create or replace function public.t_approve(p_key text, p_id uuid, p_ok boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not k_student_ok(p_key, p_id) then raise exception 'no_access'; end if;
  update students set approved = p_ok, token = case when p_ok then token else gen_random_uuid() end where id = p_id;
end $$;

create or replace function public.t_delete(p_key text, p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  select * into r from k_role(p_key);
  if r.role = 'admin' then delete from students where id = p_id; return; end if;
  -- a teacher may only remove a sign-up request that is still waiting in her class
  if not k_student_ok(p_key, p_id) then raise exception 'no_access'; end if;
  delete from students where id = p_id and not approved and updated_at = created_at;
end $$;

create or replace function public.t_set_class(p_key text, p_id uuid, p_class uuid) returns void
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  select * into r from k_role(p_key);
  if r.role <> 'admin' then
    if p_class is null or not k_class_ok(p_key, p_class) then raise exception 'no_access'; end if;
    if not k_student_ok(p_key, p_id) and exists (select 1 from students where id = p_id and class_id is not null) then raise exception 'no_access'; end if;
  end if;
  update students set class_id = p_class where id = p_id;
end $$;

-- ===== classes =====
create or replace function public.t_classes(p_key text)
returns table(id uuid, name text, code text, color text, teacher_id uuid, teacher_name text, n bigint)
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  select * into r from k_role(p_key);
  return query select c.id, c.name, c.code, c.color, c.teacher_id, t.name, (select count(*) from students s where s.class_id = c.id)
    from classes c left join teachers t on t.id = c.teacher_id
   where r.role = 'admin' or c.teacher_id = r.tid order by c.created_at;
end $$;

create or replace function public.t_class_add(p_key text, p_name text, p_color text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare r record; cd text;
begin
  select * into r from k_role(p_key);
  if length(btrim(p_name)) < 1 then raise exception 'bad_name'; end if;
  loop
    cd := upper(substr(translate(encode(gen_random_bytes(6), 'base64'), '+/=01OIl', ''), 1, 5));
    exit when length(cd) = 5 and not exists (select 1 from classes where code = cd);
  end loop;
  insert into classes(name, code, color, teacher_id) values (btrim(p_name), cd, coalesce(nullif(p_color, ''), '#68489A'), r.tid);
  return cd;
end $$;

create or replace function public.t_class_edit(p_key text, p_id uuid, p_name text, p_color text, p_teacher uuid) returns void
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  select * into r from k_role(p_key);
  if not k_class_ok(p_key, p_id) then raise exception 'no_access'; end if;
  update classes set name = coalesce(nullif(btrim(p_name), ''), name), color = coalesce(nullif(p_color, ''), color),
         teacher_id = case when r.role = 'admin' then p_teacher else teacher_id end
   where id = p_id;
end $$;

create or replace function public.t_class_del(p_key text, p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not k_class_ok(p_key, p_id) then raise exception 'no_access'; end if;
  delete from classes where id = p_id;
end $$;

-- ===== assignments and grades =====
create or replace function public.t_asg_list(p_key text, p_class uuid)
returns table(id uuid, kind text, ref text, title text, due date, is_test boolean, created_at timestamptz)
language plpgsql security definer set search_path = public as $$
begin
  if not k_class_ok(p_key, p_class) then raise exception 'no_access'; end if;
  return query select a.id, a.kind, a.ref, a.title, a.due, a.is_test, a.created_at from assignments a where a.class_id = p_class order by a.created_at desc;
end $$;

create or replace function public.t_asg_add(p_key text, p_class uuid, p_kind text, p_ref text, p_title text, p_due date, p_test boolean) returns uuid
language plpgsql security definer set search_path = public as $$
declare i uuid;
begin
  if not k_class_ok(p_key, p_class) then raise exception 'no_access'; end if;
  insert into assignments(class_id, kind, ref, title, due, is_test) values (p_class, p_kind, p_ref, p_title, p_due, coalesce(p_test, false)) returning id into i;
  return i;
end $$;

create or replace function public.t_asg_del(p_key text, p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
declare c uuid;
begin
  select class_id into c from assignments where id = p_id;
  if c is null or not k_class_ok(p_key, c) then raise exception 'no_access'; end if;
  delete from assignments where id = p_id;
end $$;

create or replace function public.t_class_grades(p_key text, p_class uuid)
returns table(id uuid, name text, approved boolean, asg jsonb, updated_at timestamptz)
language plpgsql security definer set search_path = public as $$
begin
  if not k_class_ok(p_key, p_class) then raise exception 'no_access'; end if;
  return query select s.id, s.name, s.approved, coalesce(s.data->'asg', '{}'::jsonb), s.updated_at from students s where s.class_id = p_class order by s.name_key;
end $$;

-- ===== admin only: teacher accounts =====
create or replace function public.a_teachers(p_pass text)
returns table(id uuid, name text, created_at timestamptz, classes bigint)
language plpgsql security definer set search_path = public as $$
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  return query select t.id, t.name, t.created_at, (select count(*) from classes c where c.teacher_id = t.id) from teachers t order by t.name_key;
end $$;

create or replace function public.a_teacher_add(p_pass text, p_name text, p_tpass text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare k text := lower(btrim(p_name));
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  if length(k) < 2 then raise exception 'bad_name'; end if;
  if length(p_tpass) < 6 then raise exception 'short_pass'; end if;
  if exists (select 1 from teachers where name_key = k) then raise exception 'name_taken'; end if;
  insert into teachers(name, name_key, pass_hash) values (btrim(p_name), k, crypt(p_tpass, gen_salt('bf')));
end $$;

create or replace function public.a_teacher_pass(p_pass text, p_id uuid, p_tpass text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  if length(p_tpass) < 6 then raise exception 'short_pass'; end if;
  update teachers set pass_hash = crypt(p_tpass, gen_salt('bf')), token = gen_random_uuid() where id = p_id;
end $$;

create or replace function public.a_teacher_del(p_pass text, p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not admin_ok(p_pass) then raise exception 'bad_admin'; end if;
  delete from teachers where id = p_id;
end $$;

-- ===== permissions: the site may call these functions, and nothing else =====
revoke all on function public.k_role(text), public.k_class_ok(text, uuid), public.k_student_ok(text, uuid) from public, anon, authenticated;
revoke all on function public.sign_up(text, text, text), public.my_assignments(uuid), public.teacher_login(text, text), public.k_whoami(text),
  public.t_students(text), public.t_student(text, uuid), public.t_approve(text, uuid, boolean), public.t_delete(text, uuid), public.t_set_class(text, uuid, uuid),
  public.t_classes(text), public.t_class_add(text, text, text), public.t_class_edit(text, uuid, text, text, uuid), public.t_class_del(text, uuid),
  public.t_asg_list(text, uuid), public.t_asg_add(text, uuid, text, text, text, date, boolean), public.t_asg_del(text, uuid), public.t_class_grades(text, uuid),
  public.a_teachers(text), public.a_teacher_add(text, text, text), public.a_teacher_pass(text, uuid, text), public.a_teacher_del(text, uuid) from public;
grant execute on function public.sign_up(text, text, text), public.my_assignments(uuid), public.teacher_login(text, text), public.k_whoami(text),
  public.t_students(text), public.t_student(text, uuid), public.t_approve(text, uuid, boolean), public.t_delete(text, uuid), public.t_set_class(text, uuid, uuid),
  public.t_classes(text), public.t_class_add(text, text, text), public.t_class_edit(text, uuid, text, text, uuid), public.t_class_del(text, uuid),
  public.t_asg_list(text, uuid), public.t_asg_add(text, uuid, text, text, text, date, boolean), public.t_asg_del(text, uuid), public.t_class_grades(text, uuid),
  public.a_teachers(text), public.a_teacher_add(text, text, text), public.a_teacher_pass(text, uuid, text), public.a_teacher_del(text, uuid) to anon, authenticated;
