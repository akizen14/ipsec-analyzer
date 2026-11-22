const artwork = [
  "      ____                       ____",
  "     /___/|     .-----------.   /___/|",
  "    | [ ]||=====|-----------|==| [ ]||",
  "    |  : ||     |           |  |  : ||",
  "    | [ ]||=====|-----------|==| [ ]||",
  "    |____|/     '-----------'  |____|/",
];
const width = Math.max(...artwork.map((line) => line.length));
const duration = { ready: 22, running: 52 };
const frameLength = 1000 / 12;

function drawFrame(state, frame) {
  const rows = artwork.map(() => Array(width).fill(" "));
  function draw(row, column, glyphs) {
    Array.from(glyphs).forEach((glyph, offset) => {
      rows[row][column + offset] = glyph;
    });
  }
  if (state === "ready") {
    const column = frame >= duration.ready ? 21 : 14 + frame % 13;
    for (const row of [2, 3, 4]) draw(row, column, "|");
  } else if (frame >= duration.running) {
    draw(2, 16, "..>");
    draw(4, 24, "<..");
  } else {
    const sweep = 15 + frame % 12;
    for (const row of [2, 3, 4]) draw(row, sweep, "|");
    for (const offset of [0, 6, 13]) {
      const step = (frame + offset) % 21;
      if (step < 16) draw(2, 13 + step, "..>");
    }
    for (const offset of [4, 11]) {
      const step = (frame + offset) % 21;
      if (step < 16) draw(4, 27 - step, "<..");
    }
    draw(3, frame % 14 < 7 ? 7 : 34, "*");
  }
  return rows.map((row) => row.join("")).join("\n");
}

export function createTunnel(panel, chassis, signal) {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  let activeState = "ready";
  let timer;
  chassis.textContent = artwork.join("\n");

  function show(state) {
    activeState = state;
    clearTimeout(timer);
    panel.dataset.motion = state;
    const finalFrame = duration[state];
    if (reduced.matches) {
      panel.dataset.motion = "static";
      signal.textContent = drawFrame(state, finalFrame);
      return;
    }
    const start = performance.now();
    function paint() {
      const elapsed = performance.now() - start;
      const frame = Math.min(finalFrame, Math.floor(elapsed / frameLength));
      signal.textContent = drawFrame(state, frame);
      if (frame < finalFrame) timer = setTimeout(paint, (frame + 1) * frameLength - elapsed);
      else panel.dataset.motion = "static";
    }
    paint();
  }

  reduced.addEventListener("change", () => show(activeState));
  show("ready");
  return show;
}
