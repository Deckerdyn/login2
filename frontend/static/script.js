document
  .getElementById("login-form")
  .addEventListener("submit", async (event) => {
    event.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    // Obtener CSRF Token de la cookie
    function getCookie(name) {
      const cookies = document.cookie.split("; ");
      for (const cookie of cookies) {
        const [key, value] = cookie.split("=");
        if (key === name) {
          return value;
        }
      }
      return null;
    }

    const csrfToken = getCookie("csrf_token");

    const response = await fetch("/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken, // 🔹 Enviamos el CSRF Token en el header
      },
      body: JSON.stringify({ email, password }),
      credentials: "include", // 🔹 IMPORTANTE: Permite que el navegador maneje la cookie de sesión
    });

    if (response.ok) {
      // 🔹 Ya no guardamos el token manualmente, la cookie lo maneja automáticamente
      window.location.href = "/dashboard"; // Redirige al dashboard
    } else {
      // 🔹 Manejo de errores si la autenticación falla
      const data = await response.json();
      alert(data.detail || "Error desconocido");
    }
  });
