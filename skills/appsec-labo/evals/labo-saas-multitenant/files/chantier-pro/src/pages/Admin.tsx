import { useUser } from '../lib/useUser'
export default function Admin() {
  const { profile } = useUser()
  if (profile?.role !== 'admin') return null   // garde côté client uniquement
  return <div>Administration des entreprises</div>
}
