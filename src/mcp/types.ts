import type { PlatformType } from '../types/config.js'

export interface ScanToolInput {
  path?: string
  platform?: PlatformType
  severity?: 'low' | 'medium' | 'high' | 'critical'
}

export interface DiscoverToolInput {
  path?: string
}

export interface ReportToolInput {
  path?: string
  platform?: PlatformType
  severity?: 'low' | 'medium' | 'high' | 'critical'
  outputPath?: string
}

export interface ScanToolOutput {
  grade: string
  threatsFound: number
  platformsScanned: number
  componentsScanned: number
  threats: Array<{
    ruleId: string
    category: string
    severity: string
    message: string
    location: string
    confidence: number
  }>
}

export interface DiscoverToolOutput {
  platforms: Array<{
    name: string
    type: PlatformType
    componentsFound: number
    components: string[]
  }>
}

export interface ReportToolOutput {
  grade: string
  summary: string
  reportPath: string
}
