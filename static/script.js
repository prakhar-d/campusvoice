// Ask before deleting
document.querySelectorAll("form.confirm").forEach(f => f.addEventListener("submit", e => {
  if (!confirm(f.dataset.msg || "Are you sure?")) e.preventDefault(); }));
// Final warning before submitting feedback (it cannot be edited later)
document.querySelectorAll("form.confirm-submit").forEach(f => f.addEventListener("submit", e => {
  if (!confirm("Submit this feedback? You will not be able to edit it later.")) e.preventDefault(); }));
// Live comment counter
document.querySelectorAll("textarea[maxlength]").forEach(t => {
  const c = t.closest("form").querySelector(".cnt");
  if (c) t.addEventListener("input", () => c.textContent = t.value.length); });
// Hide messages after a few seconds
setTimeout(() => document.querySelectorAll(".flash").forEach(f => f.style.display = "none"), 6000);

// Live search for name lists
document.querySelectorAll("[data-filter]").forEach(i => i.addEventListener("input", () => {
  const v = i.value.toLowerCase();
  document.querySelectorAll(i.dataset.filter).forEach(r => { if (r.dataset.name !== undefined) r.style.display = r.dataset.name.includes(v) ? "" : "none"; }); }));

// Answered counter on feedback forms
document.querySelectorAll("form[data-qs]").forEach(f => {
  const total = +f.dataset.qs, out = f.querySelector(".answered"), bar = f.querySelector(".fillbar");
  f.addEventListener("change", () => {
    const n = new Set([...f.querySelectorAll("input[type=radio]:checked")].map(i => i.name)).size;
    out.textContent = n; bar.style.width = (n / total * 100) + "%"; });
});