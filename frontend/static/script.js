document
  .getElementById("login-form")
  .addEventListener("submit", async (event) => {
    event.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    const response = await fetch("/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
    });

    if (response.ok) {
      // Si la respuesta es exitosa, guarda el token
      const data = await response.json();
      //localStorage.setItem("access_token", data.access_token); // Guardar el token

      // Redirige al dashboard
      window.location.href = "/dashboard";
    } else {
      // Si hay un error en la autenticación, muestra el error
      const data = await response.json();
      alert(data.detail || "Error desconocido");
    }
  });
