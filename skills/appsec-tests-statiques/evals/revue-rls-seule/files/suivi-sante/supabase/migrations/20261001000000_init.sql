create table public.cabinets (id uuid primary key default gen_random_uuid(), nom text not null);
create table public.profils (id uuid primary key references auth.users, cabinet_id uuid references public.cabinets, role text not null default 'patient');
create table public.mesures (id uuid primary key default gen_random_uuid(), patient_id uuid references public.profils, cabinet_id uuid references public.cabinets, tension text, glycemie numeric, note text);
alter table public.cabinets enable row level security;
alter table public.profils enable row level security;
alter table public.mesures enable row level security;

create function public.mon_cabinet() returns uuid language sql stable security definer set search_path = '' as $$
  select cabinet_id from public.profils where id = auth.uid()
$$;

create policy cabinets_select on public.cabinets for select to authenticated using (id = public.mon_cabinet());
create policy profils_select on public.profils for select to authenticated using (cabinet_id = public.mon_cabinet());
create policy profils_update_soi on public.profils for update to authenticated using (id = auth.uid());
create policy mesures_select on public.mesures for select to authenticated
  using (cabinet_id = (auth.jwt() -> 'user_metadata' ->> 'cabinet_id')::uuid);
create policy mesures_insert on public.mesures for insert to authenticated
  with check (cabinet_id = public.mon_cabinet() and patient_id = auth.uid());
