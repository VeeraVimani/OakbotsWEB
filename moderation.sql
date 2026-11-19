-- OakBots United: comment moderation. Run ONCE in Supabase → SQL Editor → New query → Run
-- (after setup.sql). Safe to run again.
--
-- What it does:
--  • Every new comment goes through a check in the database (can't be skipped from the website).
--  • A comment is held for YOUR review (hidden from the public) if:
--      - it contains a word from the banned-words list (also catches tricks like b@d or b.a.d)
--      - the name was already used by a different device or network
--      - the same device/network posts more than 3 comments in 10 minutes
--      - it contains a link
--  • Blocked devices/networks: their comments are silently hidden.
--  • You can switch comments between: auto (checked), review (you approve everything), off.
--  • Network (IP) addresses are stored only as a scrambled code (hash), never the real IP.

create extension if not exists pgcrypto with schema extensions;

-- 1) Comment columns for moderation
alter table public.comments add column if not exists status text not null default 'approved';
alter table public.comments add column if not exists flags text[] not null default '{}';
alter table public.comments add column if not exists device_id text;
alter table public.comments add column if not exists ip_hash text;
alter table public.comments drop constraint if exists comments_status_check;
alter table public.comments add constraint comments_status_check check (status in ('approved','pending','blocked'));
create index if not exists comments_post_status on public.comments (post_id, status);

-- Comments that were posted before moderation existed go to review (so you can check them).
update public.comments set status = 'pending', flags = array['posted before moderation']
  where device_id is null and ip_hash is null and status = 'approved' and flags = '{}';

-- 2) Settings (comments mode)
create table if not exists public.settings (key text primary key, value text not null);
insert into public.settings (key, value) values ('comments_mode', 'auto') on conflict (key) do nothing;
alter table public.settings enable row level security;
drop policy if exists "settings are public" on public.settings;
create policy "settings are public" on public.settings for select using (true);
drop policy if exists "admins change settings" on public.settings;
create policy "admins change settings" on public.settings for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- 3) Blocked devices / networks
create table if not exists public.blocked (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  kind text not null check (kind in ('device','ip')),
  value text not null,
  note text,
  unique (kind, value)
);
alter table public.blocked enable row level security;
drop policy if exists "admins manage blocked" on public.blocked;
create policy "admins manage blocked" on public.blocked for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- 4) Banned words (you can add/remove more from the admin page)
create table if not exists public.bad_words (word text primary key);
alter table public.bad_words enable row level security;
drop policy if exists "admins manage words" on public.bad_words;
create policy "admins manage words" on public.bad_words for all to authenticated using (public.is_admin()) with check (public.is_admin());
insert into public.bad_words (word) values
  ('fuck'),('fck'),('fuk'),('fuq'),('shit'),('sh1t'),('bitch'),('btch'),('bastard'),('asshole'),('arse'),('dick'),('cock'),('pussy'),('cunt'),('slut'),('whore'),
  ('wanker'),('twat'),('prick'),('motherfucker'),('mf'),('wtf'),('stfu'),('porn'),('sex'),('nude'),('nudes'),('boobs'),('penis'),('vagina'),
  ('retard'),('retarded'),('idiot'),('stupid'),('stoopid'),('stuped'),('dumb'),('loser'),('ugly'),('fat'),('trash'),('garbage'),('noob'),('suck'),('sucks'),('kys'),('kill'),('die'),('hate'),
  ('nigger'),('nigga'),('faggot'),('fag'),('chutiya'),('chutiye'),('madarchod'),('bhenchod'),('behenchod'),('bc'),('mc'),('bsdk'),('bhosdike'),('gandu'),('lavde'),('lauda'),('randi'),('harami'),('kutta'),('kutti'),('saala'),('kamina')
on conflict do nothing;

-- 5) The check that runs on every new comment
create or replace function public.post_comment(p_post_id text, p_name text, p_body text, p_device text default null)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_mode text;
  v_name text := btrim(coalesce(p_name, ''));
  v_body text := btrim(coalesce(p_body, ''));
  v_dev  text := left(nullif(btrim(coalesce(p_device, '')), ''), 64);
  v_ip   text;
  v_iph  text;
  v_flags text[] := '{}';
  v_status text := 'approved';
  v_norm text;
  v_collapsed text;
  v_tokens text[];
  w text;
begin
  select value into v_mode from settings where key = 'comments_mode';
  v_mode := coalesce(v_mode, 'auto');
  if v_mode = 'off' then raise exception 'Comments are turned off'; end if;
  if char_length(v_name) < 1 or char_length(v_name) > 40 then raise exception 'Name must be 1 to 40 characters'; end if;
  if char_length(v_body) < 1 or char_length(v_body) > 500 then raise exception 'Comment must be 1 to 500 characters'; end if;
  if p_post_id is null or char_length(p_post_id) > 80 then raise exception 'Bad post'; end if;

  -- network address → scrambled code
  begin
    v_ip := btrim(split_part(coalesce(current_setting('request.headers', true)::json ->> 'x-forwarded-for',
                                      current_setting('request.headers', true)::json ->> 'x-real-ip', ''), ',', 1));
  exception when others then v_ip := null; end;
  if v_ip is not null and v_ip <> '' then
    v_iph := encode(extensions.digest('oakbots:' || v_ip, 'sha256'), 'hex');
  end if;

  -- blocked?
  if exists (select 1 from blocked where (kind = 'device' and value = v_dev) or (kind = 'ip' and value = v_iph)) then
    v_status := 'blocked'; v_flags := v_flags || 'blocked device/network'::text;
  end if;

  -- bad words (normalise leetspeak, check whole words and squashed text)
  v_norm := translate(lower(v_name || ' ' || v_body), '013457@$!|', 'oieastasii');
  v_tokens := regexp_split_to_array(regexp_replace(v_norm, '[^a-z]+', ' ', 'g'), ' ');
  v_collapsed := regexp_replace(v_norm, '[^a-z]', '', 'g');
  -- join spelled-out letters: "f u c k" / "f.u.c.k" → "fuck"
  declare run text := ''; t text;
  begin
    foreach t in array v_tokens || array[''] loop
      if char_length(t) = 1 then run := run || t;
      else
        if char_length(run) >= 2 then v_tokens := v_tokens || run; end if;
        run := '';
      end if;
    end loop;
  end;
  for w in select word from bad_words loop
    if w = any (v_tokens) or (char_length(w) >= 5 and position(w in v_collapsed) > 0) then
      v_flags := v_flags || ('bad word: ' || w);
    end if;
  end loop;

  -- links
  if v_body ~* '(https?://|www\.|\.com|\.in/|\.ly/)' then v_flags := v_flags || 'contains a link'::text; end if;

  -- name already used by someone else (different device AND different network)
  if exists (select 1 from comments c where lower(btrim(c.name)) = lower(v_name)
             and (c.device_id is distinct from v_dev) and (v_iph is null or c.ip_hash is distinct from v_iph)) then
    v_flags := v_flags || 'name used before by another device'::text;
  end if;

  -- too many in 10 minutes
  if (select count(*) from comments c where c.created_at > now() - interval '10 minutes'
        and ((v_dev is not null and c.device_id = v_dev) or (v_iph is not null and c.ip_hash = v_iph))) >= 3 then
    v_flags := v_flags || 'posting too fast'::text;
  end if;

  if v_status <> 'blocked' and (array_length(v_flags, 1) > 0 or v_mode = 'review') then
    v_status := 'pending';
    if v_mode = 'review' and coalesce(array_length(v_flags, 1), 0) = 0 then v_flags := array['review mode']; end if;
  end if;

  insert into comments (post_id, name, body, status, flags, device_id, ip_hash)
  values (p_post_id, v_name, v_body, v_status, v_flags, v_dev, v_iph);

  -- don't tell blocked people they are blocked
  return case when v_status = 'approved' then 'approved' else 'pending' end;
end;
$$;
revoke all on function public.post_comment(text, text, text, text) from public;
grant execute on function public.post_comment(text, text, text, text) to anon, authenticated;

-- 6) Who can see / change comments now
drop policy if exists "comments are public" on public.comments;
drop policy if exists "anyone can comment" on public.comments;          -- comments now only go in through post_comment()
drop policy if exists "public sees approved comments" on public.comments;
create policy "public sees approved comments" on public.comments for select using (status = 'approved' or public.is_admin());
drop policy if exists "admins update comments" on public.comments;
create policy "admins update comments" on public.comments for update to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "admins delete comments" on public.comments;
create policy "admins delete comments" on public.comments for delete to authenticated using (public.is_admin());
