-- Popcorn English · WhatsApp message to the admin for every new sign-up that waits for approval
-- Before running:
--   1) Get your free CallMeBot key (see the steps in the chat), then
--   2) put it instead of MY-API-KEY at the bottom of this file (keep the quotes).
-- Run in the project of the site (fstvghnkdgtmliqjyxpg): SQL Editor → New query → Run. Safe to run again.

create extension if not exists pg_net;

create table if not exists public.pe_notify (
  id int primary key default 1 check (id = 1),
  phone text not null,
  apikey text not null
);
alter table public.pe_notify enable row level security;
revoke all on public.pe_notify from anon, authenticated;

-- turns any text (Hebrew too) into a safe web-address part
create or replace function public.pe_urlencode(t text) returns text
language sql immutable as $$
  select coalesce(string_agg(case when ch ~ '^[A-Za-z0-9._~-]$' then ch
                                  else upper(regexp_replace(encode(convert_to(ch, 'UTF8'), 'hex'), '(..)', '%\1', 'g')) end, ''), '')
    from regexp_split_to_table(t, '') as ch;
$$;

-- runs by itself after every new sign-up
create or replace function public.pe_notify_signup() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
declare n pe_notify; cls text; msg text;
begin
  if new.approved then return new; end if;
  select * into n from pe_notify where id = 1;
  if n.phone is null then return new; end if;
  select name into cls from classes where id = new.class_id;
  msg := 'Popcorn English 🍿 הרשמה חדשה מחכה לאישור: ' || new.name || coalesce(' · כיתה: ' || cls, ' · בלי כיתה') ||
         '. לאישור: כניסת צוות ← מנהלת ← ממתינות לאישור.';
  perform net.http_get('https://api.callmebot.com/whatsapp.php?phone=' || pe_urlencode(n.phone) || '&text=' || pe_urlencode(msg) || '&apikey=' || pe_urlencode(n.apikey));
  return new;
exception when others then
  return new;  -- a message that fails never blocks the sign-up
end $$;

drop trigger if exists pe_notify_signup on public.students;
create trigger pe_notify_signup after insert on public.students
  for each row execute function public.pe_notify_signup();

insert into public.pe_notify(id, phone, apikey) values (1, '+9725XXXXXXXX', 'MY-API-KEY')
on conflict (id) do update set phone = excluded.phone, apikey = excluded.apikey;
