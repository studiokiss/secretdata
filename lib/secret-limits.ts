// View and label limits, shared by the API, the storage and the creation form
export const MAX_VIEWS = 10;
export const MAX_LABEL_LENGTH = 100;

// maxViews null means unlimited: the secret lives until it expires
export function computeRemainingViews(maxViews: number | null, views: number): number | null {
  return maxViews === null ? null : Math.max(0, maxViews - views);
}
