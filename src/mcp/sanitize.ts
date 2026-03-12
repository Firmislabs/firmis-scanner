const MAX_OUTPUT_LENGTH = 10_000

const PROMPT_MARKERS = /\b(SYSTEM|ASSISTANT|HUMAN|User|Assistant)\s*:/gi
const INSTRUCTION_TAGS = /<\/?(instructions|system|prompt|command|tool_code|thinking)[^>]*>/gi

export function sanitizeMcpOutput(input: string): string {
  let output = input
  output = output.replace(PROMPT_MARKERS, '[REDACTED]:')
  output = output.replace(INSTRUCTION_TAGS, '[REDACTED]')

  if (output.length > MAX_OUTPUT_LENGTH) {
    output = output.slice(0, MAX_OUTPUT_LENGTH) + '\n...[truncated]'
  }

  return output
}
