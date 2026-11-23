create view public.v_mesures_recentes as select patient_id, tension, glycemie from public.mesures order by id desc limit 100;
create or replace function public.get_mesures(p_patient uuid) returns setof public.mesures language sql security definer as $$
  select * from public.mesures where patient_id = p_patient
$$;
grant execute on function public.get_mesures(uuid) to authenticated;
