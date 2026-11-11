-- Popcorn English · let students rename or delete their own account
-- Paste the whole file in Supabase: SQL Editor → New query → Run.

create or replace function public.rename_student(p_token uuid, p_name text) returns void
language plpgsql security definer set search_path = public as $$
declare k text := lower(btrim(p_name)); me uuid;
begin
  select id into me from students where token = p_token;
  if me is null then raise exception 'bad_token'; end if;
  if length(k) < 2 or length(k) > 24 then raise exception 'bad_name'; end if;
  if exists (select 1 from students where name_key = k and id <> me) then raise exception 'name_taken'; end if;
  update students set name = btrim(p_name), name_key = k, updated_at = now() where id = me;
end $$;

create or replace function public.delete_self(p_token uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  delete from students where token = p_token;
  if not found then raise exception 'bad_token'; end if;
end $$;

revoke all on function public.rename_student(uuid, text), public.delete_self(uuid) from public;
grant execute on function public.rename_student(uuid, text), public.delete_self(uuid) to anon, authenticated;
