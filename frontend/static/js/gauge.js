/**
 * Renders the signature "posture gauge" — a radial dial with tick marks
 * (like an instrument gauge) rather than a generic circular progress ring.
 * A one-time sweep animation draws the arc on load; respects
 * prefers-reduced-motion via the CSS layer.
 */
function renderGauge(container, score, grade) {
  const gradeColors = { A: '#15803d', B: '#4d7c0f', C: '#d9a441', D: '#b45309', F: '#b91c1c' };
  const color = gradeColors[grade] || '#667085';

  const size = 220;
  const cx = size / 2;
  const cy = size / 2;
  const r = 92;
  const circumference = 2 * Math.PI * r;
  // Gauge sweeps 270 degrees (like a real analog instrument), starting at
  // -225deg and ending at +45deg, leaving a gap at the bottom.
  const sweepFraction = 0.75;
  const arcLength = circumference * sweepFraction;
  const scoreFraction = Math.max(0, Math.min(100, score)) / 100;
  const offset = arcLength - (arcLength * scoreFraction);

  // Tick marks around the dial
  let ticks = '';
  const tickCount = 27;
  for (let i = 0; i <= tickCount; i++) {
    const angle = -225 + (270 * (i / tickCount));
    const rad = (angle * Math.PI) / 180;
    const inner = r + 8;
    const outer = r + (i % 3 === 0 ? 15 : 11);
    const x1 = cx + inner * Math.cos(rad);
    const y1 = cy + inner * Math.sin(rad);
    const x2 = cx + outer * Math.cos(rad);
    const y2 = cy + outer * Math.sin(rad);
    ticks += `<line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}" stroke="var(--border)" stroke-width="1.5"/>`;
  }

  container.style.setProperty('--gauge-circumference', arcLength.toFixed(1));
  container.style.setProperty('--gauge-offset', offset.toFixed(1));

  container.innerHTML = `
    <svg viewBox="0 0 ${size} ${size}">
      <g>${ticks}</g>
      <circle cx="${cx}" cy="${cy}" r="${r}"
        fill="none" stroke="var(--bg-inset)" stroke-width="10"
        stroke-dasharray="${arcLength} ${circumference}"
        stroke-dashoffset="0"
        stroke-linecap="round"
        transform="rotate(135 ${cx} ${cy})" />
      <circle class="gauge__sweep" cx="${cx}" cy="${cy}" r="${r}"
        fill="none" stroke="${color}" stroke-width="10"
        stroke-dasharray="${arcLength} ${circumference}"
        stroke-dashoffset="${offset}"
        stroke-linecap="round"
        transform="rotate(135 ${cx} ${cy})" />
    </svg>
    <div class="gauge__center">
      <div class="gauge__score" style="color:${color}">${score}</div>
      <div class="gauge__grade">GRADE ${grade} · /100</div>
    </div>
  `;
}
