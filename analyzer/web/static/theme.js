(() => {
  const modes = new Set(["system", "light", "dark"]);
  const system = matchMedia("(prefers-color-scheme: dark)");
  let mode = "system";
  try {
    const saved = localStorage.getItem("ipsec-theme");
    if (modes.has(saved)) mode = saved;
  } catch {
    // The system theme also works with browser storage disabled.
  }
  function applyTheme() {
    document.documentElement.dataset.theme = mode === "system"
      ? (system.matches ? "dark" : "light")
      : mode;
  }
  applyTheme();
  system.addEventListener("change", applyTheme);
  document.addEventListener("DOMContentLoaded", () => {
    const control = document.getElementById("theme");
    control.value = mode;
    control.addEventListener("change", () => {
      mode = control.value;
      applyTheme();
      try {
        localStorage.setItem("ipsec-theme", mode);
      } catch {
        // The current page still reflects the selected theme.
      }
    });
  });
})();
