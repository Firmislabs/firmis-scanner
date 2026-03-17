import { calculateRiskLevel } from '../types/index.js'
import type { PlatformScanResult } from '../types/index.js'

/**
 * Remove duplicate threats that appear across multiple platforms for the
 * same (ruleId, file, line) triple. Platforms are processed in array order;
 * the first occurrence wins and subsequent duplicates are dropped.
 *
 * Also deduplicates within each component: only one finding per ruleId
 * per component is kept (the first match, which typically has the highest weight).
 */
export function deduplicateCrossPlatformThreats(
  results: PlatformScanResult[]
): PlatformScanResult[] {
  const seen = new Set<string>()

  return results.map(platformResult => {
    const dedupedComponents = platformResult.components.map(component => {
      // First: deduplicate within component — one finding per ruleId
      const seenRulesInComponent = new Set<string>()
      const componentDeduped = component.threats.filter(threat => {
        const ruleKey = threat.ruleId
        if (seenRulesInComponent.has(ruleKey)) return false
        seenRulesInComponent.add(ruleKey)
        return true
      })

      // Then: cross-platform dedup by (ruleId, file, line)
      const dedupedThreats = componentDeduped.filter(threat => {
        const key = `${threat.ruleId}::${threat.location.file}::${threat.location.line}`
        if (seen.has(key)) return false
        seen.add(key)
        return true
      })

      return {
        ...component,
        threats: dedupedThreats,
        riskLevel: calculateRiskLevel(dedupedThreats),
      }
    })

    const platformThreats = dedupedComponents.flatMap(c => c.threats)

    return {
      ...platformResult,
      components: dedupedComponents,
      threats: platformThreats,
    }
  })
}
