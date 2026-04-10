import { analyzeDomain } from './riskScorer';

/**
 * PhishGuard Background Classifier Worker
 * Handles heavy multi-threaded domain analysis to prevent UI freezing.
 */
self.onmessage = async (e) => {
  const { domains, type } = e.data;

  if (type === 'START_ANALYSIS') {
    const total = domains.length;
    const results = [];
    
    // Process in chunks to give progress feedback
    const CHUNK_SIZE = 100;
    
    for (let i = 0; i < total; i += CHUNK_SIZE) {
      const chunk = domains.slice(i, i + CHUNK_SIZE);
      const processed = chunk.map(d => analyzeDomain(d));
      results.push(...processed);
      
      // Update progress
      self.postMessage({
        type: 'PROGRESS',
        progress: Math.floor((i / total) * 100),
        analyzed: Math.min(i + CHUNK_SIZE, total),
        total
      });
    }

    self.postMessage({
      type: 'COMPLETE',
      results
    });
  }
};
