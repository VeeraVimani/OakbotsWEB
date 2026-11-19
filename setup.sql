-- OakBots United: run this ONCE in Supabase → SQL Editor → New query → Run.
-- 1) Change the email on the next line to the email of your admin account (the one you will log in with).
--    To allow more admins, add more emails: array['a@x.com','b@y.com']
create or replace function public.is_admin() returns boolean language sql stable as $$
  select coalesce((auth.jwt() ->> 'email') = any (array['YOUR_ADMIN_EMAIL@example.com']), false)
$$;

-- Posts
create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  date date not null default current_date,
  type text not null check (type in ('video','image')),
  media text[] not null,
  caption text not null default '' check (char_length(caption) <= 2200)
);
alter table public.posts enable row level security;
drop policy if exists "posts are public" on public.posts;
create policy "posts are public" on public.posts for select using (true);
drop policy if exists "admins manage posts" on public.posts;
create policy "admins manage posts" on public.posts for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- Comments (anyone can comment with a name; only admins can delete)
create table if not exists public.comments (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  post_id text not null check (char_length(post_id) <= 80),
  name text not null check (char_length(btrim(name)) between 1 and 40),
  body text not null check (char_length(btrim(body)) between 1 and 500)
);
alter table public.comments enable row level security;
drop policy if exists "comments are public" on public.comments;
create policy "comments are public" on public.comments for select using (true);
drop policy if exists "anyone can comment" on public.comments;
create policy "anyone can comment" on public.comments for insert to anon, authenticated with check (true);
drop policy if exists "admins delete comments" on public.comments;
create policy "admins delete comments" on public.comments for delete to authenticated using (public.is_admin());

-- Media storage (public to view, only admins can upload/delete)
insert into storage.buckets (id, name, public) values ('media', 'media', true) on conflict (id) do update set public = true;
drop policy if exists "admins upload media" on storage.objects;
create policy "admins upload media" on storage.objects for insert to authenticated with check (bucket_id = 'media' and public.is_admin());
drop policy if exists "admins delete media" on storage.objects;
create policy "admins delete media" on storage.objects for delete to authenticated using (bucket_id = 'media' and public.is_admin());
