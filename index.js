const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const db = require('./db');
const app = express();

app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'tajneheslo', resave: false, saveUninitialized: true }));

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/views/index.html');
});

app.post('/register', (req, res) => {
  const { username, name, email, password } = req.body;
  if (!username || !name || !email || !password)
    return res.redirect('/?error=Vyplň+všechna+pole');

  const hashedPassword = bcrypt.hashSync(password, 8);
  db.run(`INSERT INTO users (username, name, email, password) VALUES (?, ?, ?, ?)`,
    [username, name, email, hashedPassword],
    function (err) {
      if (err) return res.redirect('/?error=Uživatel+nebo+email+už+existuje');
      res.redirect('/?success=Registrace+úspěšná');
    });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.redirect('/?error=Špatné+přihlašovací+údaje');
    }
    req.session.user = user;
    res.redirect('/');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/?success=Odhlášení+proběhlo+úspěšně');
  });
});


app.get('/session', (req, res) => {
    if (req.session.user) {
      res.json({ loggedIn: true, user: req.session.user });
    } else {
      res.json({ loggedIn: false });
    }
  });
  

app.post('/update', (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Nejste+přihlášen');

  const { name, email } = req.body;
  db.run(`UPDATE users SET name = ?, email = ? WHERE id = ?`,
    [name, email, req.session.user.id],
    function (err) {
      if (err) return res.redirect('/?error=Chyba+při+úpravě');
      req.session.user.name = name;
      req.session.user.email = email;
      res.redirect('/?success=Údaje+upraveny');
    });
});

app.listen(3000, () => console.log('Server běží na http://localhost:3000'));
