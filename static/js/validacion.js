function validar_formulario() {
    let username = document.formRegistro.username;
    let email = document.formRegistro.correo;
    let password = document.formRegistro.password;
  
    let username_len = username.value.length;
    if (username_len == 0 || username_len < 8) {
      alert("Debes ingresar un username con min. 8 caracteres");
      passid.focus();
      return false;
    }
  
    let formato_email = /^\w+([\.-]?\w+)@\w+([\.-]?\w+)(\.\w{2,3})+$/;
    if (!email.value.match(formato_email)) {
      alert("Debes ingresar un email electronico valido!");
      email.focus();
      return false;
    }
  
    let passid_len = password.value.length;
    if (passid_len == 0 || passid_len < 8) {
      alert("Debes ingresar una password con mas de 8 caracteres");
      passid.focus();
    }
}

function mostrarPassword() {
  let obj = document.getElementById('password');
  obj.type = "text";  
}

function ocultarPassword() {
  let obj = document.getElementById('password');
  obj.type = "password";  
} 