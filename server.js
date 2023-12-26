const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const express = require('express');
const glob = require('glob');
const app = express();

const secretKey = 'defsehfuiefhie';
const saltRounds = 10;

const storage = multer.memoryStorage();
const upload = multer({ storage });

const events = [];

server.use(middlewares);
server.use(bodyParser.json());

server.use('/uploads', express.static('uploads'));

server.post('/register', async (req, res) => {
  const { email, password, login } = req.body;

  if (!email || !password || !login) {
    return res.status(400).json({ error: 'Всі поля повинні бути заповнені.' });
  }

  try {
    const existingUser = router.db.get('users').find({ email: email.toLowerCase() }).value();
    if (existingUser) {
      return res.status(400).json({ error: 'Користувач з таким email вже існує.' });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = { id: Date.now(), email, password: hashedPassword, login };
    router.db.get('users').push(newUser).write();

    const token = jwt.sign({ userId: newUser.id }, secretKey, { expiresIn: '1h' });

    res.status(201).json({ message: 'Користувач успішно зареєстрований', token });
  } catch (error) {
    console.error('Помилка при хешуванні паролю:', error);
    res.status(500).json({ error: 'Внутрішня помилка сервера.' });
  }
});


server.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Всі поля повинні бути заповнені.' });
  }

  const user = router.db.get('users').find({ email }).value();

  if (!user) {
    return res.status(401).json({ error: 'Невірний email або пароль.' });
  }

  let token; 

  try {
    const match = await bcrypt.compare(password, user.password);

    if (match) {
      const token = jwt.sign({ userId: user.id, role: user.role }, secretKey, { expiresIn: '24h' });
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Невірний email або пароль.' });
    }
  } catch (error) {
    console.error('Помилка при порівнянні паролів:', error);
    res.status(500).json({ error: 'Внутрішня помилка сервера.' });
  }
});

server.post('/logout', (req, res) => {
  res.header('Authorization', '');
  res.status(200).json({ message: 'Successfully logged out' });
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({ error: 'Unauthorized: Token not provided' });
  }

  const token = authHeader.split(' ')[1]; 

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      console.error('Error decoding token:', err);
      return res.status(403).json({ error: 'Forbidden: Invalid token' });
    }
    req.user = user;
    next();
  });
};

server.post('/addRole', authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  if (!userId) {
    return res.status(400).json({ error: 'Не вказано userId.' });
  }

  try {
    const user = router.db.get('users').find({ id: userId }).value();

    if (!user) {
      return res.status(404).json({ error: 'Користувача з вказаним userId не знайдено.' });
    }

    console.log(`Do you want to add the role "Organizer" to the user with userId ${userId}? Type 'yes' to confirm:`);

    const confirmation = await promptConfirmation();

    if (confirmation !== 'yes') {
      return res.status(404).json({ message: 'Роль не була додана. Користувач не підтвердив.' });
    }

    router.db.get('users').find({ id: userId }).assign({ role: 'Organizer' }).write();

    res.status(200).json({ message: 'Роль успішно додана користувачу.' });
  } catch (error) {
    console.error('Помилка при додаванні ролі:', error);
    res.status(500).json({ error: 'Внутрішня помилка сервера.' });
  }
});

function promptConfirmation() {
  return new Promise((resolve) => {
    process.stdin.once('data', (data) => {
      const input = data.toString().trim().toLowerCase();
      resolve(input);
    });

    process.stdin.setEncoding('utf-8');
    process.stdin.resume();
  });
}

server.get('/userData', authenticateToken, (req, res) => {
  const userId = req.user.userId;

  if (!userId) {
    return res.status(400).json({ error: 'User ID not provided.' });
  }

  try {
    const user = router.db.get('users').find({ id: userId }).value();

    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const userData = {
      login: user.login,
      email: user.email,
    };

    res.status(200).json(userData);
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

server.post('/addEvent', (req, res) => {
  const eventData = req.body;

  if (
    !eventData.EventTitle ||
    !eventData.EventCategory ||
    !eventData.Venue ||
    !eventData.Date ||
    !eventData.Time ||
    !eventData.TicketPrice ||
    !eventData.Image
  ) {
    return res.status(400).json({ error: 'Заповніть всі поля!' });
  }
  
  router.db.get('events').push(eventData).write();

  res.status(201).json({ message: 'Event created successfully' });
});


/*function deleteAdsAfterDays() {
  const ads = router.db.get('ads').value();

  ads.forEach((ad) => {
    const currentDate = new Date();
    const expirationTime = parseInt(ad.expirationDateAds) * 60 * 1000;
    const adDate = new Date(ad.createdAt);

    if (currentDate - adDate >= expirationTime) {
      const eventTitleToDelete = ad.eventTitle;

      router.db.get('ads').remove({ eventTitle: eventTitleToDelete }).write();

      console.log(`Ads with eventTitle "${eventTitleToDelete}" have been deleted.`);
    }
  });
}

setInterval(deleteAdsAfterDays, 60 * 1000);

deleteAdsAfterDays();*/
function deleteAdsAfterMinutes() {
  const ads = router.db.get('ads').value();

  ads.forEach((ad) => {
    const currentDate = new Date();
    const expirationTime = parseInt(ad.expirationDateAds) * 60 * 1000; 
    const adDate = new Date(ad.createdAt);

    if (currentDate - adDate >= expirationTime) {
      const eventTitleToDelete = ad.eventTitle;

      router.db.get('ads').remove({ eventTitle: eventTitleToDelete }).write();

      console.log(`Ads with eventTitle "${eventTitleToDelete}" have been deleted.`);
    }
  });
}

setInterval(deleteAdsAfterMinutes, 60 * 1000);
deleteAdsAfterMinutes();


server.post('/createAds', authenticateToken, upload.single('image'), async (req, res) => {
  const { eventTitle, expirationDateAds, imageUrl } = req.body;

  if (!eventTitle || !expirationDateAds || !imageUrl) {
    return res.status(400).json({ error: 'Всі поля повинні бути заповнені.' });
  }

  try {
    const existingEvent = router.db.get('events').find({ EventTitle: eventTitle }).value();

    if (!existingEvent) {
      return res.status(404).json({ error: 'Подія з вказаним заголовком не знайдена.' });
    }

    const userId = req.user.userId;
    const user = router.db.get('users').find({ id: userId }).value();

    if (!user) {
      return res.status(404).json({ error: 'Користувача не знайдено.' });
    }

    const createdAt = new Date().toISOString();

    const adsData = {
      eventTitle,
      expirationDateAds,
      imageUrl,
      advertiser: user.login,
      createdAt, 
    };

    router.db.get('ads').push(adsData).write();

    res.status(201).json({ message: 'Реклама успішно створена.' });
  } catch (error) {
    console.error('Помилка при створенні реклами:', error);
    res.status(500).json({ error: 'Внутрішня помилка сервера.' });
  }
});

server.get('/getAllImageUrls', (req, res) => {
  try {
    const imageUrls = router.db.get('ads').map('imageUrl').value();

    if (!imageUrls || imageUrls.length === 0) {
      return res.status(404).json({ error: 'ImageUrls не знайдено.' });
    }

    res.status(200).json({ imageUrls });
  } catch (error) {
    console.error('Помилка при отриманні imageUrl з бази даних:', error);
    res.status(500).json({ error: 'Внутрішня помилка сервера.' });
  }
});

server.post('/uploadImage', upload.single('image'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    const eventId = req.body.eventId;
    if (!eventId) {
      return res.status(400).json({ error: 'eventId is required.' });
    }

    const imagePath = `uploads/${eventId}_${req.file.originalname}`;

    if (fs.existsSync(imagePath)) {
      fs.unlinkSync(imagePath);
    }

    fs.writeFileSync(imagePath, req.file.buffer);

    const imageUrl = `http://ec2-51-20-95-148.eu-north-1.compute.amazonaws.com:3002/${imagePath}`;
    res.status(201).json({ imageUrl });
  } catch (error) {
    console.error('Error uploading image:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

server.post('/uploadImageAds', upload.single('image'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    const imagePath = `uploads/${req.file.originalname}`;

    if (fs.existsSync(imagePath)) {
      fs.unlinkSync(imagePath);
    }

    fs.writeFileSync(imagePath, req.file.buffer);

    const imageUrl = `http://ec2-51-20-95-148.eu-north-1.compute.amazonaws.com:3002/${imagePath}`;
    res.status(201).json({ imageUrl });
  } catch (error) {
    console.error('Error uploading image:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

server.put('/editEvent', (req, res) => {
  const eventData = req.body;
  const eventId = req.header('eventId');

  if (!eventId) {
    return res.status(400).json({ error: 'Event ID is required.' });
  }

  try {
    const existingEvent = router.db.get('events').find({ eventId: parseInt(eventId) }).value();

    if (!existingEvent) {
      return res.status(404).json({ error: 'Event not found.' });
    }

    router.db.get('events').find({ eventId: parseInt(eventId) }).assign(eventData).write();

    res.status(200).json({ message: 'Event updated successfully' });
  } catch (error) {
    console.error('Error updating event:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

server.delete('/deleteEvent/:eventId', (req, res) => {
  const eventId = parseInt(req.params.eventId);

  if (!eventId) {
    return res.status(400).json({ error: 'Event ID is required.' });
  }

  try {
    const existingEvent = router.db.get('events').find({ eventId }).value();

    if (!existingEvent) {
      return res.status(404).json({ error: 'Event not found.' });
    }

    router.db.get('events').remove({ eventId }).write();

    const imagePath = `uploads/${eventId}_*`;

    const matchingFiles = glob.sync(imagePath);

    matchingFiles.forEach(file => fs.unlinkSync(file));

    res.status(200).json({ message: 'Event deleted successfully' });
  } catch (error) {
    console.error('Error deleting event:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

server.get('/events/:eventId?', (req, res) => {
  try {
    const eventId = req.params.eventId;

    if (eventId) {
      const event = router.db.get('events').find({ eventId: parseInt(eventId) }).value();

      if (event) {
        res.status(200).json({ ...event });
      } else {
        res.status(404).json({ error: 'Event not found' });
      }
    } else {
      const allEvents = router.db.get('events').value();
      res.status(200).json(allEvents.map(event => ({ ...event })));
    }
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

server.use(router);

const port = 3002;
server.listen(port, () => {
  console.log(`JSON Server is running on port ${port}`);
});
