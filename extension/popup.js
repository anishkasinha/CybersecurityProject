document.getElementById("analyze").addEventListener("click", () => {
  const message = document.getElementById("message").value.toLowerCase();
  const dot = document.getElementById("threat-indicator");
  const desc = document.getElementById("description");

  // Simple fake logic for threat detection
  if (message.includes("click here") || message.includes("verify") || message.includes("urgent")) {
    dot.style.marginLeft = "130px"; // High Threat
    desc.value = "⚠️ High Threat: This email contains suspicious language such as 'click here', 'verify', or 'urgent'.";
  } else if (message.includes("meeting") || message.includes("schedule") || message.includes("lunch")) {
    dot.style.marginLeft = "0px"; // Low Threat
    desc.value = "✅ Low Threat: This email appears to contain everyday communication.";
  } else if (message.trim() === "") {
    dot.style.marginLeft = "65px";
    desc.value = "Please enter or paste an email to analyze.";
  } else {
    dot.style.marginLeft = "65px"; // Medium Threat
    desc.value = "⚠️ Medium Threat: This email contains unknown or ambiguous content.";
  }
});


