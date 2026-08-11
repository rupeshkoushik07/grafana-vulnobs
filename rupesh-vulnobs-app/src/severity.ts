import { BadgeColor } from '@grafana/ui';

export const SEVERITY_COLOR: Record<string, BadgeColor> = {
  CRITICAL: 'red',
  HIGH: 'orange',
  MODERATE: 'purple',
  LOW: 'blue',
  UNKNOWN: 'darkgrey',
};

// Highest severity first — used for summary rows and table ordering.
export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'];

export function severityColor(severity: string): BadgeColor {
  return SEVERITY_COLOR[severity] ?? 'darkgrey';
}
