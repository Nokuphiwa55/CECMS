document.addEventListener("click", (event) => {
  const toggle = event.target.closest("[data-password-toggle]");
  if (!toggle) return;

  const input = toggle.closest(".password-input").querySelector("input");
  const visible = input.type === "password";
  input.type = visible ? "text" : "password";
  toggle.classList.toggle("is-visible", visible);
  toggle.setAttribute("aria-pressed", String(visible));
  toggle.setAttribute("aria-label", `${visible ? "Hide" : "Show"} password`);
  toggle.title = `${visible ? "Hide" : "Show"} password`;
});