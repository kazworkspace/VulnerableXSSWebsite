(function () {
  if (localStorage.getItem('sessionToken')) return;

  function randHex(bytes) {
    return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
      .map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  localStorage.setItem('sessionToken',  randHex(16));
  localStorage.setItem('csrfToken',     randHex(8));
  localStorage.setItem('userId',        String(Math.floor(Math.random() * 9000) + 1000));
  localStorage.setItem('username',      'john_doe');
  localStorage.setItem('email',         'john.doe@corp-internal.com');
  localStorage.setItem('role',          'admin');
  localStorage.setItem('lastLogin',     new Date().toISOString());
})();
