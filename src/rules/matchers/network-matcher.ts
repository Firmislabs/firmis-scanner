import type { PatternMatch } from '../../types/index.js'
import { matchRegex } from './regex-matcher.js'

const NETWORK_APIS = ['fetch', 'axios', 'http.request', 'https.request', 'XMLHttpRequest']

export function matchNetwork(
  pattern: string,
  content: string,
  _ast: unknown,
  description: string,
  weight: number
): PatternMatch[] {
  // Only match the URL pattern — don't flag every fetch/axios call independently.
  // The network APIs list is used to NARROW matches: require both a network API
  // call AND the suspicious pattern (e.g., suspicious TLD) to fire.
  if (!pattern) return []

  const patternMatches = matchRegex(pattern, content, description, weight)

  // If no pattern matches, don't fire — a bare fetch() is not exfiltration
  if (patternMatches.length === 0) return []

  // Check if any network API is present in the file (context confirmation)
  const hasNetworkAPI = NETWORK_APIS.some((api) => content.includes(api))

  // Return pattern matches, boosting weight if network APIs are also present
  if (hasNetworkAPI) {
    return patternMatches.map((m) => ({
      ...m,
      weight: Math.min(m.weight + 5, 100),
    }))
  }

  return patternMatches
}
