
document.getElementById("analyze").addEventListener("click", () => {
  const msg = document.getElementById("message").value;

  fetch("http://localhost:5000/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: msg })
  })
  .then(res => res.json())
  .then(data => {
    document.getElementById("result").textContent = 
      data.threat ? "⚠️ Threat Detected!" : "✅ Message is Safe";
  })
  .catch(err => {
    document.getElementById("result").textContent = "❌ Error contacting server";
  });
});
