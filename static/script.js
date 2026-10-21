// --- CUSTOM AUTOCOMPLETE FOR REGISTRATION ---
document.addEventListener("DOMContentLoaded", () => {
    const searchInput = document.getElementById("student-search");
    const hiddenIdInput = document.getElementById("student-id");
    const suggestionsList = document.getElementById("suggestions-list");
    const submitBtn = document.getElementById("submit-btn");
    const registerForm = document.getElementById("register-form");

    // Only run if we are on the register page
    if (!searchInput || !hiddenIdInput || !suggestionsList) return;

    // Make sure form doesn't submit without a valid selection
    registerForm.addEventListener("submit", (e) => {
        if (!hiddenIdInput.value) {
            e.preventDefault();
            alert("Please select a valid name from the dropdown list.");
        }
    });

    searchInput.addEventListener("input", () => {
        // Clear the hidden ID if they start typing again
        hiddenIdInput.value = "";
        const query = searchInput.value.toLowerCase();
        suggestionsList.innerHTML = "";
        
        if (query.length === 0) {
            suggestionsList.style.display = "none";
            return;
        }

        // Filter the list based on what they typed
        const filtered = allStudents.filter(s => s.name.toLowerCase().includes(query));

        if (filtered.length === 0) {
            suggestionsList.style.display = "none";
            return;
        }

        // Build the dropdown items
        filtered.forEach(student => {
            const li = document.createElement("li");
            
            // Check if they are already registered
            if (student.user_id !== null) {
                li.innerHTML = `<span>${student.name}</span> <small style="color: #ef4444;">(Already registered)</small>`;
                li.style.color = "#94a3b8";
                li.style.cursor = "not-allowed";
                li.style.backgroundColor = "#f8fafc";
            } else {
                li.textContent = student.name;
                // When they click a valid name, fill the input and hidden ID
                li.addEventListener("click", () => {
                    searchInput.value = student.name;
                    hiddenIdInput.value = student.id;
                    suggestionsList.style.display = "none";
                });
            }
            suggestionsList.appendChild(li);
        });

        suggestionsList.style.display = "block";
    });

    // Hide dropdown if clicking outside
    document.addEventListener("click", (e) => {
        if (!searchInput.contains(e.target) && !suggestionsList.contains(e.target)) {
            suggestionsList.style.display = "none";
        }
    });
});

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