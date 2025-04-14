document.getElementById("emailForm").addEventListener("submit", function(event) {
    event.preventDefault();

    let emailText = document.getElementById("email_text").value;

    fetch("/predict", {
        method: "POST",
        body: new URLSearchParams({ "email_text": emailText }),
        headers: { "Content-Type": "application/x-www-form-urlencoded" }
    })
    .then(response => response.json())
    .then(data => {
        let resultText = `Prediction: ${data.prediction} (Probability: ${data.probability.toFixed(2)})`;
        document.getElementById("result").innerText = resultText;
        document.getElementById("result").style.color = data.prediction === "Spam" ? "red" : "green";
    })
    .catch(error => console.error("Error:", error));
});
