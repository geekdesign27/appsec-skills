insert into storage.buckets (id, name, public) values ('photos-accidents', 'photos-accidents', true);
create policy photos_read on storage.objects for select using (bucket_id = 'photos-accidents');
create or replace function public.stats_entreprise(p_entreprise uuid) returns json
language sql security definer as $$
  select json_build_object('nb', count(*), 'graves', count(*) filter (where gravite >= 3)) from public.accidents where entreprise_id = p_entreprise;
$$;
grant execute on function public.stats_entreprise(uuid) to anon, authenticated;
alter publication supabase_realtime add table public.accidents;
