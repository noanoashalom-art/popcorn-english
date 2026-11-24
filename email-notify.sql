-- Popcorn English · e-mail to the admin for every new sign-up that waits for approval
-- Before running: put your Resend API key instead of MY-RESEND-KEY at the bottom (keep the quotes).
-- If your e-mail is not @gmail.com, fix it at the bottom too.
-- Run in the site's project (fstvghnkdgtmliqjyxpg): SQL Editor → New query → Run. Safe to run again.

create extension if not exists pg_net;

create table if not exists public.pe_mail (
  id int primary key default 1 check (id = 1),
  email text not null,
  apikey text not null
);
alter table public.pe_mail enable row level security;
revoke all on public.pe_mail from anon, authenticated;

-- runs by itself after every new sign-up
create or replace function public.pe_mail_signup() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
declare m pe_mail; cls text;
begin
  if new.approved then return new; end if;
  select * into m from pe_mail where id = 1;
  if m.email is null then return new; end if;
  select name into cls from classes where id = new.class_id;
  perform net.http_post(
    url := 'https://api.resend.com/emails',
    headers := jsonb_build_object('Authorization', 'Bearer ' || m.apikey, 'Content-Type', 'application/json'),
    body := jsonb_build_object(
      'from', 'Popcorn English <onboarding@resend.dev>',
      'to', jsonb_build_array(m.email),
      'subject', 'הרשמה חדשה מחכה לאישור: ' || new.name,
      'html', '<div dir="rtl" style="font-family:Arial,sans-serif;font-size:16px">' ||
              '<p>🍿 <b>' || replace(replace(new.name, '<', ''), '>', '') || '</b> נרשמה לקריאה אקדמית ומחכה לאישור.</p>' ||
              '<p>כיתה: ' || coalesce(replace(replace(cls, '<', ''), '>', ''), 'בלי כיתה') || '</p>' ||
              '<p>לאישור: באתר ← כניסת צוות ← מנהלת ← ממתינות לאישור.</p>' ||
              '<p><a href="https://noanoashalom-art.github.io/popcorn-english/">לאתר</a></p></div>'));
  return new;
exception when others then
  return new;  -- a message that fails never blocks the sign-up
end $$;

drop trigger if exists pe_mail_signup on public.students;
create trigger pe_mail_signup after insert on public.students
  for each row execute function public.pe_mail_signup();

-- the WhatsApp version is not used
drop trigger if exists pe_notify_signup on public.students;

insert into public.pe_mail(id, email, apikey) values (1, 'YOUR-EMAIL', 'MY-RESEND-KEY')
on conflict (id) do update set email = excluded.email, apikey = excluded.apikey;
