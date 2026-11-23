create table public.entreprises (id uuid primary key default gen_random_uuid(), nom text not null);
create table public.membres (user_id uuid references auth.users, entreprise_id uuid references public.entreprises, role text default 'membre');
create table public.accidents (id uuid primary key default gen_random_uuid(), entreprise_id uuid references public.entreprises, victime text, description text, gravite int, created_at timestamptz default now());
alter table public.accidents enable row level security;
create policy accidents_select on public.accidents for select using (true);
