export function Rapport({ resumeIa }: { resumeIa: string }) {
  return <section dangerouslySetInnerHTML={{ __html: resumeIa }} />
}
