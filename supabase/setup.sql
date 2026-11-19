-- Leonida Bird Log: database setup
-- Paste this whole file into Supabase → SQL Editor → New query, then click Run.
-- Safe to read: it contains no keys or secrets.

------------------------------------------------------------
-- 1. Profiles: one row per signed-in player
------------------------------------------------------------
create table public.profiles (
  id           uuid primary key references auth.users (id) on delete cascade,
  display_name text not null check (char_length(display_name) between 2 and 30),
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "Players can read their own profile"
  on public.profiles for select to authenticated
  using ((select auth.uid()) = id);

create policy "Players can update their own profile"
  on public.profiles for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

-- Players may only change their display name (rows are created by the trigger below)
grant select on public.profiles to authenticated;
grant update (display_name, updated_at) on public.profiles to authenticated;

------------------------------------------------------------
-- 2. Sightings: one row per bird a player has touched
------------------------------------------------------------
create table public.sightings (
  user_id    uuid not null default auth.uid() references auth.users (id) on delete cascade,
  bird_id    text not null check (char_length(bird_id) between 1 and 80),
  name       text not null check (char_length(name) between 1 and 60),
  habitat    text not null check (char_length(habitat) between 1 and 40),
  count      integer not null default 0 check (count between 0 and 100000),
  seen       boolean not null default false,
  custom     boolean not null default false,  -- a bird the player added themselves
  hidden     boolean not null default false,  -- a listed bird the player removed
  updated_at timestamptz not null default now(),
  primary key (user_id, bird_id)
);

alter table public.sightings enable row level security;

create policy "Players can read their own sightings"
  on public.sightings for select to authenticated
  using ((select auth.uid()) = user_id);

create policy "Players can add their own sightings"
  on public.sightings for insert to authenticated
  with check ((select auth.uid()) = user_id);

create policy "Players can update their own sightings"
  on public.sightings for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy "Players can delete their own sightings"
  on public.sightings for delete to authenticated
  using ((select auth.uid()) = user_id);

grant select, insert, update, delete on public.sightings to authenticated;

------------------------------------------------------------
-- 3. Create a profile automatically on first sign-in
--    (uses the first name from Google only, never the full name)
------------------------------------------------------------
create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  dn text;
begin
  dn := left(coalesce(nullif(trim(split_part(new.raw_user_meta_data ->> 'full_name', ' ', 1)), ''), 'Birder'), 30);
  if char_length(dn) < 2 then
    dn := 'Birder';
  end if;
  insert into public.profiles (id, display_name) values (new.id, dn);
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

------------------------------------------------------------
-- 4. Let players delete their own account (and all their data)
------------------------------------------------------------
create function public.delete_my_account()
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'Not signed in';
  end if;
  -- Deleting the login also deletes the profile and sightings (on delete cascade)
  delete from auth.users where id = auth.uid();
end;
$$;

revoke execute on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;
