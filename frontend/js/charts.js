/* Minimal dependency-free canvas charts (line, bar, doughnut, heatmap).
 * Self-contained so the dashboard works offline (no CDN needed).
 * Colours are read from CSS custom properties so light/dark themes apply. */
(function (global) {
  "use strict";

  function css(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return (v && v.trim()) || fallback;
  }
  const PALETTE = () => [
    css("--c1", "#4f8cff"), css("--c2", "#30d0b6"), css("--c3", "#f7b955"),
    css("--c4", "#ff6b6b"), css("--c5", "#a78bfa"), css("--c6", "#f472b6"),
  ];
  const AXIS = () => css("--chart-axis", "#64748b");
  const GRID = () => css("--chart-grid", "rgba(148,163,184,.15)");
  const TEXT = () => css("--chart-text", "#cbd5e1");

  function setup(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const w = rect.width || canvas.width || 300;
    const h = rect.height || canvas.height || 150;
    canvas.width = w * dpr; canvas.height = h * dpr;
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    return { ctx, w, h };
  }

  function tick(v, max) {
    return max < 10 ? (Math.round(v * 100) / 100).toString() : Math.round(v).toLocaleString();
  }
  function niceMax(v) {
    if (v <= 0) return 1;
    const mag = Math.pow(10, Math.floor(Math.log10(v)));
    const n = v / mag;
    const step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
    return step * mag;
  }

  function lineChart(canvas, series, opts) {
    opts = opts || {};
    const { ctx, w, h } = setup(canvas);
    const colors = PALETTE();
    let max = 0, len = 0;
    series.forEach(s => { len = Math.max(len, s.data.length); s.data.forEach(v => max = Math.max(max, v)); });
    max = niceMax(max || 1);
    ctx.font = "10px system-ui, sans-serif";
    const padL = Math.max(30, ctx.measureText(tick(max, max)).width + 14);
    const padB = 22, padT = opts.legend ? 18 : 10, padR = 10;
    const plotW = w - padL - padR, plotH = h - padT - padB;
    ctx.strokeStyle = GRID(); ctx.fillStyle = TEXT(); ctx.lineWidth = 1;
    ctx.font = "10px system-ui, sans-serif"; ctx.textAlign = "right"; ctx.textBaseline = "middle";
    for (let i = 0; i <= 4; i++) {
      const y = padT + plotH * i / 4;
      ctx.globalAlpha = 0.5; ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y); ctx.stroke(); ctx.globalAlpha = 1;
      ctx.fillText(tick(max * (1 - i / 4), max), padL - 6, y);
    }
    const xo = len > 1 ? plotW / (len - 1) : plotW;
    series.forEach((s, si) => {
      const col = s.color || colors[si % colors.length];
      ctx.strokeStyle = col; ctx.lineWidth = 2; ctx.beginPath();
      s.data.forEach((v, i) => {
        const x = padL + i * xo, y = padT + plotH * (1 - v / max);
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      });
      ctx.stroke();
      if (opts.fill) {
        const g = ctx.createLinearGradient(0, padT, 0, padT + plotH);
        g.addColorStop(0, col + "44"); g.addColorStop(1, col + "00");
        ctx.lineTo(padL + (s.data.length - 1) * xo, padT + plotH); ctx.lineTo(padL, padT + plotH);
        ctx.closePath(); ctx.fillStyle = g; ctx.fill();
      }
    });
    if (opts.legend && series.length > 1) {
      ctx.textAlign = "left"; let lx = padL;
      series.forEach((s, si) => {
        const col = s.color || colors[si % colors.length];
        ctx.fillStyle = col; ctx.fillRect(lx, 2, 10, 6); ctx.fillStyle = TEXT();
        ctx.fillText(s.label, lx + 14, 6); lx += 22 + ctx.measureText(s.label).width;
      });
    }
  }

  function barChart(canvas, labels, values, opts) {
    opts = opts || {};
    const { ctx, w, h } = setup(canvas);
    const colors = PALETTE();
    const max = niceMax(Math.max(1, ...values));
    ctx.font = "10px system-ui, sans-serif";
    const padL = Math.max(30, ctx.measureText(tick(max, max)).width + 14);
    const padB = opts.rotate ? 58 : 30, padT = 10, padR = 8;
    const plotW = w - padL - padR, plotH = h - padT - padB;
    ctx.font = "10px system-ui, sans-serif";
    ctx.strokeStyle = GRID(); ctx.fillStyle = TEXT(); ctx.textAlign = "right"; ctx.textBaseline = "middle";
    for (let i = 0; i <= 4; i++) {
      const y = padT + plotH * i / 4;
      ctx.globalAlpha = .5; ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y); ctx.stroke(); ctx.globalAlpha = 1;
      ctx.fillText(tick(max * (1 - i / 4), max), padL - 6, y);
    }
    const n = values.length || 1, bw = plotW / n * 0.62, gap = plotW / n;
    values.forEach((v, i) => {
      const x = padL + i * gap + (gap - bw) / 2, bh = plotH * v / max, y = padT + plotH - bh;
      ctx.fillStyle = opts.colors ? opts.colors[i % opts.colors.length]
        : opts.colorByIndex ? colors[i % colors.length] : (opts.color || colors[0]);
      roundRect(ctx, x, y, bw, bh, 3); ctx.fill();
      ctx.fillStyle = TEXT(); ctx.save();
      const cx = padL + i * gap + gap / 2;
      if (opts.rotate) {
        ctx.translate(cx, h - padB + 6); ctx.rotate(-Math.PI / 4.5); ctx.textAlign = "right"; ctx.fillText(labels[i], 0, 0);
      } else { ctx.textAlign = "center"; ctx.textBaseline = "top"; ctx.fillText(labels[i], cx, h - padB + 5); }
      ctx.restore();
    });
  }

  function doughnut(canvas, labels, values, opts) {
    opts = opts || {};
    const { ctx, w, h } = setup(canvas);
    const colors = opts.colors || PALETTE();
    const total = values.reduce((a, b) => a + b, 0) || 1;
    const cx = w * 0.40, cy = h / 2, r = Math.min(w * 0.40, h / 2) - 6, ir = r * 0.6;
    let a0 = -Math.PI / 2;
    values.forEach((v, i) => {
      const a1 = a0 + (v / total) * Math.PI * 2;
      ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, r, a0, a1); ctx.closePath();
      ctx.fillStyle = colors[i % colors.length]; ctx.fill(); a0 = a1;
    });
    ctx.globalCompositeOperation = "destination-out";
    ctx.beginPath(); ctx.arc(cx, cy, ir, 0, Math.PI * 2); ctx.fill();
    ctx.globalCompositeOperation = "source-over";
    ctx.fillStyle = TEXT(); ctx.font = "11px system-ui, sans-serif"; ctx.textAlign = "left"; ctx.textBaseline = "middle";
    let ly = cy - (labels.length * 15) / 2 + 6;
    labels.forEach((l, i) => {
      if (ly > h - 6) return;
      ctx.fillStyle = colors[i % colors.length]; roundRect(ctx, w * 0.66, ly - 5, 10, 10, 2); ctx.fill();
      ctx.fillStyle = TEXT();
      const pct = Math.round((values[i] / total) * 100);
      ctx.fillText(`${l} ${pct}%`, w * 0.66 + 16, ly); ly += 16;
    });
  }

  function heatmap(canvas, matrix, labels, opts) {
    opts = opts || {};
    const { ctx, w, h } = setup(canvas);
    const n = labels.length, padL = 60, padT = 10, padB = 54, padR = 10;
    const cw = (w - padL - padR) / n, ch = (h - padT - padB) / n;
    let max = 0; matrix.forEach(r => r.forEach(v => max = Math.max(max, v)));
    const base = PALETTE()[0];
    ctx.font = "9px system-ui, sans-serif";
    for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) {
      const v = matrix[i][j], alpha = max ? 0.12 + 0.88 * (v / max) : 0.12;
      ctx.fillStyle = hexA(i === j ? PALETTE()[1] : base, v ? alpha : 0.05);
      ctx.fillRect(padL + j * cw, padT + i * ch, cw - 1, ch - 1);
      if (v) { ctx.fillStyle = (v / max > 0.5) ? "#0b1020" : TEXT(); ctx.textAlign = "center"; ctx.textBaseline = "middle";
        ctx.fillText(v, padL + j * cw + cw / 2, padT + i * ch + ch / 2); }
    }
    ctx.fillStyle = TEXT();
    for (let i = 0; i < n; i++) {
      ctx.textAlign = "right"; ctx.textBaseline = "middle"; ctx.fillText(labels[i], padL - 5, padT + i * ch + ch / 2);
      ctx.save(); ctx.translate(padL + i * cw + cw / 2, h - padB + 6); ctx.rotate(-Math.PI / 4); ctx.textAlign = "right"; ctx.fillText(labels[i], 0, 0); ctx.restore();
    }
  }

  function roundRect(ctx, x, y, w, h, r) {
    r = Math.min(r, w / 2, h / 2); if (h < 0) { y += h; h = -h; }
    ctx.beginPath(); ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }
  function hexA(hex, a) {
    hex = hex.trim(); if (hex[0] !== "#") return hex;
    const n = parseInt(hex.slice(1), 16);
    return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
  }

  global.Charts = { lineChart, barChart, doughnut, heatmap };
})(window);
