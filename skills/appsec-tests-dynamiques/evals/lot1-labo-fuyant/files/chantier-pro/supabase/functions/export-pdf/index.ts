import { createClient } from "npm:@supabase/supabase-js@2"
Deno.serve(async (req) => {
  const { entreprise_id } = await req.json()
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!)
  const { data } = await admin.from("accidents").select("*").eq("entreprise_id", entreprise_id)
  return new Response(JSON.stringify(data), { headers: { "Access-Control-Allow-Origin": "*" } })
})
