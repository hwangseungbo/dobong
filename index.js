const express = require('express');
const cors = require('cors');

// Express 애플리케이션을 생성합니다.
const app = express();
const ObjectId = require('mongodb').ObjectId;
// 환경변수
require('dotenv').config();

//RTSP 스트림
const Stream = require('node-rtsp-stream');

//인증을위한 라이브러리
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const mongoose = require('mongoose');
const Users = require('./models/users'); // 스키마 이용을 위한 선언
const Logs = require('./models/logs');
const MongoStore = require('connect-mongo');

//비밀번호 암호화를 위한 라이브러리
const bcrypt = require('bcrypt');

//socket.io
const http = require('http');
const socketIo = require('socket.io');
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*',
    credentials: true,
  },
}); // Socket.IO 서버 초기화

let clients = [];

//
const streams = [
  {
    // ir
    name: 'IR_CAMERA',
    streamUrl: process.env.IR_RTSP_Main,
    wsPort: process.env.IR_RTSP_Port,
    width: 1280,
    height: 720,
    ffmpegOptions: {
      '-s': '1280x720',
    },
  },
  {
    // CCD
    name: 'CCD_CAMERA',
    streamUrl: process.env.CCD_RTSP_Main,
    wsPort: process.env.CCD_RTSP_Port,
    width: 1280,
    height: 720,
    ffmpegOptions: {
      '-s': '1280x720',
    },
  },
];

streams.forEach((stream) => {
  new Stream(stream);
  console.log(`Connected to stream: ${stream.name}`);
});

mongoose
  .connect(process.env.DB_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('MONGOOSE CONNECTION OPEN!! 27017port');
  })
  .catch((err) => {
    console.log('OH NO ERROR!!!!');
    console.log(err);
  });

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
  console.log('Database connected');
});

// 로그 데이터 Mongoose 스키마 없이 데이터 저장
const logSchema = new mongoose.Schema({}, { strict: false });
const Log = mongoose.model('Log', logSchema); // logs 컬렉션에 저장

app.use(passport.initialize());
app.use(
  session({
    secret: process.env.Session_Secret, // 암호화에 쓸 비번
    resave: false, // 유저가 요청할 때마다 세션 갱신여부
    saveUninitialized: false, // 로그인 안해도 세션 만들지 여부
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 30, secure: false, httpOnly: true, sameSite: 'None' }, // 한달간 유지
    store: MongoStore.create({
      mongoUrl: process.env.DB_URL,
      dbName: 'user',
    }),
  })
);
app.use(passport.session());

const allowedOrigins = ['http://localhost:3000', 'http://192.168.0.15:3000'];
app.use(
  cors({
    origin: function (origin, callback) {
      // 허용된 도메인 목록에 있는지 확인
      if (!origin || allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true, // 쿠키를 포함한 요청을 허용
  })
);
//app.use(cors({ origin: '*', credentials: true })); // 모든 요청에 대해 CORS를 허용합니다.
app.use(express.json()); //클라이언트가 보낸 JSON 형식의 데이터를 자동으로 파싱
app.use(express.urlencoded({ extended: true })); // 클라이언트가 폼 데이터를 전송할 때 그 데이터를 req.body로 쉽게 접근할 수 있게 해줌

// 루트 경로에 대한 GET 요청을 처리합니다.
//app.get('/', async (req, res) => {
// let result = await Users.findOne({ _id: '66deb9c37d0b9e16c7d02a6c' });
// delete result.password;
// console.log(result);
//let hash = await bcrypt.hash('1234', 10);
//let result = await Users.findOneAndUpdate({ username: 'admin' }, { password: hash }).then((m) => console.log(m));

//res.send('서버열림');
//});

// 루트 경로에 대한 POST 요청을 처리합니다.
app.post('/', async (req, res) => {
  try {
    const newLog = new Log(req.body);
    await newLog.save();

    io.emit('result', JSON.stringify(req.body));
    res.json({ message: 'JSON data received successfully' });
  } catch (error) {
    console.log(error);
    res.json({ message: 'JSON data received Fail' });
  }
});

passport.use(
  new LocalStrategy(async (입력한아이디, 입력한비번, cb) => {
    try {
      let result = await Users.findOne({ username: 입력한아이디 });
      if (!result) {
        return cb(null, false, { message: 'DB에 아이디가 존재하지 않습니다.' });
      }
      //if (result.password == 입력한비번) {
      if (await bcrypt.compare(입력한비번, result.password)) {
        return cb(null, result);
      } else {
        return cb(null, false, { message: '비밀번호가 일치하지 않습니다.' });
      }
    } catch (error) {
      console.log(error);
    }
  })
);

passport.serializeUser((user, done) => {
  try {
    process.nextTick(() => {
      done(null, { id: user._id, username: user.username });
    });
  } catch (error) {
    console.log(error);
  }
});

passport.deserializeUser(async (user, done) => {
  try {
    let result = await Users.findOne({ _id: new ObjectId(user.id) });
    process.nextTick(() => {
      done(null, result);
    });
  } catch (error) {
    console.log(error);
  }
});

function checkLogin(req, res) {
  if (!req.user) {
    res.redirect('/');
  }
  next();
}

// API
app.post('/login', async (req, res, next) => {
  passport.authenticate('local', (error, user, info) => {
    if (error) return res.status(500).json(error);
    if (!user) return res.status(401).json(info.message);

    req.logIn(user, (err) => {
      console.log(user.username + '님이 로그인 하였습니다.');
      if (err) return next(err);
      //res.redirect('/dashboard'); //로그인 완료 시 이동하는 메인페이지!! 수정필
      //res.send('로그인성공');
      console.log(req.sessionID);
      return res.json({ sessionId: req.sessionID });
    });
  })(req, res, next);
});

//app.use(checkLogin);

app.get('/log/:num', async (req, res) => {
  try {
    // 최근 저장된 num개 데이터 가져오기
    const logs = await Log.find({})
      .sort({ time: -1 }) // 최신순으로 정렬
      .limit(req.params.num); // 최대 num개의 데이터만 가져오기
    res.send(logs); // 데이터를 JSON으로 응답
  } catch (err) {
    res.status(500).json({ message: 'Error fetching logs', error: err.message });
  }
});

app.get('/log/second', async (req, res) => {
  try {
    // // 최근 저장된 300개 데이터 가져오기
    // const logs = await Log.find({})
    //     .sort({ time: -1 }) // 최신순으로 정렬
    //     .limit(1000); // 최대 1000개의 데이터만 가져오기
    // res.send(logs); // 데이터를 JSON으로 응답

    // 1. 현재 날짜를 구합니다 (예: '24.09.11')
    const currentDate = new Date();
    const day = String(currentDate.getDate()).padStart(2, '0');
    const month = String(currentDate.getMonth() + 1).padStart(2, '0');
    const year = String(currentDate.getFullYear()).substring(2);
    const todayKey = `${year}.${month}.${day}`; // 오늘의 날짜 형식 ('YY.MM.DD')

    // 2. 당일의 데이터를 필터링하여 가져옵니다.
    const todaysLogs = await Log.find({
      time: { $regex: `^${todayKey}` }, // time 필드가 오늘 날짜로 시작하는 데이터를 필터링
    }).sort({ time: -1 }); // 최신순으로 정렬

    // 3. 초 단위로 중복된 데이터를 제거하고 저장
    const uniqueLogs = [];
    const secondSeen = new Set(); // 이미 처리한 초 단위 time 필드 값을 저장하는 Set

    for (const log of todaysLogs) {
      // time 필드에서 초 단위까지만 자름 (예: '24.09.11.16.32.20')
      const timeKey = log.time.substring(0, 17); // 초 단위까지만 사용 (밀리초 제외)

      // Set에 같은 초 단위가 없다면 uniqueLogs에 추가하고 secondSeen에 기록
      if (!secondSeen.has(timeKey)) {
        uniqueLogs.push(log);
        secondSeen.add(timeKey); // 해당 초 단위를 기록
      }
    }

    // 4. uniqueLogs 배열을 응답으로 전송 (중복 제거된 모든 데이터를 포함)
    res.json(uniqueLogs); // 중복된 초를 제외한 모든 데이터를 반환
  } catch (err) {
    res.status(500).json({ message: 'Error fetching logs', error: err.message });
  }
});

app.get('/log/minute', async (req, res) => {
  try {
    // 1. 현재 날짜를 구합니다 (예: '24.09.11')
    const currentDate = new Date();
    const day = String(currentDate.getDate()).padStart(2, '0');
    const month = String(currentDate.getMonth() + 1).padStart(2, '0');
    const year = String(currentDate.getFullYear()).substring(2);
    const todayKey = `${year}.${month}.${day}`; // 오늘의 날짜 형식 ('YY.MM.DD')

    // 2. 당일의 데이터를 필터링하여 가져옵니다.
    const todaysLogs = await Log.find({
      time: { $regex: `^${todayKey}` }, // time 필드가 오늘 날짜로 시작하는 데이터를 필터링
    }).sort({ time: -1 }); // 최신순으로 정렬

    // 3. 분 단위로 중복된 데이터를 제거하고 저장
    const uniqueLogs = [];
    const minuteSeen = new Set(); // 이미 처리한 분 단위 time 필드 값을 저장하는 Set

    for (const log of todaysLogs) {
      // time 필드에서 분 단위까지만 자름 (예: '24.09.11.16.32')
      const timeKey = log.time.substring(0, 14); // 분 단위까지만 사용 (초와 밀리초 제외)

      // Set에 같은 분 단위가 없다면 uniqueLogs에 추가하고 minuteSeen에 기록
      if (!minuteSeen.has(timeKey)) {
        uniqueLogs.push(log);
        minuteSeen.add(timeKey); // 해당 분 단위를 기록
      }
    }

    // 4. uniqueLogs 배열을 응답으로 전송 (중복 제거된 모든 데이터를 포함)
    res.json(uniqueLogs); // 중복된 분을 제외한 모든 데이터를 반환
  } catch (err) {
    res.status(500).json({ message: 'Error fetching logs', error: err.message });
  }
});

app.get('/log/hour', async (req, res) => {
  try {
    // 1. 현재 날짜를 구합니다 (예: '24.09.11')
    const currentDate = new Date();
    const day = String(currentDate.getDate()).padStart(2, '0');
    const month = String(currentDate.getMonth() + 1).padStart(2, '0'); // 월은 0부터 시작하므로 +1
    const year = String(currentDate.getFullYear()).substring(2); // 연도의 마지막 두 자리 사용
    const todayKey = `${year}.${month}.${day}`; // 오늘의 날짜 형식 ('YY.MM.DD')

    // 2. 당일의 데이터를 필터링하여 가져옵니다.
    const todaysLogs = await Log.find({
      time: { $regex: `^${todayKey}` }, // time 필드가 오늘 날짜로 시작하는 데이터를 필터링
    }).sort({ time: -1 }); // 최신순으로 정렬

    // 3. 새로운 그룹을 만들어서 중복된 시간 단위의 데이터는 배제하고 추가
    const uniqueLogs = [];
    const hourSeen = new Set(); // 이미 처리한 시간 단위 time 필드 값을 저장하는 Set

    for (const log of todaysLogs) {
      // time 필드에서 시간 단위까지만 자름 (예: '24.09.11.16')
      const timeKey = log.time.substring(0, 11); // 시간 단위까지만 사용 (분, 초, 밀리초 제외)

      // Set에 같은 시간 단위가 없다면 uniqueLogs에 추가하고 hourSeen에 기록
      if (!hourSeen.has(timeKey)) {
        uniqueLogs.push(log);
        hourSeen.add(timeKey); // 해당 시간 단위를 기록
      }
    }

    // 4. uniqueLogs 배열을 응답으로 전송 (중복 제거된 모든 데이터를 포함)
    res.json(uniqueLogs); // 중복된 시간을 제외한 모든 데이터를 반환
  } catch (err) {
    res.status(500).json({ message: 'Error fetching logs', error: err.message });
  }
});

app.get('/warning', async (req, res) => {
  try {
    // 1. 클라이언트로부터 전달된 쿼리 파라미터를 변수에 저장
    let setACC = parseFloat(req.query.userAccSetValue); // accuracy 설정 값
    let setTemp = parseFloat(req.query.userTempSetValue); // temperature 설정 값

    // 2. 결과를 저장할 배열을 선언
    let results = [];

    // 3. MongoDB에서 최신 데이터를 cursor로 순차적으로 가져옴
    const cursor = Log.find({})
      .sort({ time: -1 }) // 최신순으로 정렬
      .cursor(); // cursor로 데이터를 순차적으로 가져옴

    // 4. cursor를 순회하며 조건에 맞는 데이터를 배열에 추가
    for await (let log of cursor) {
      // CCDResult.location이 배열이므로 각 location의 accuracy와 비교
      for (let location of log.CCDResult.location) {
        const accCondition = parseFloat(location.accuracy) > setACC;
        const tempCondition = log.CCDResult.temperature > setTemp;

        // 두 조건 중 하나만 만족하는 경우 (XOR 연산: !==)
        if (accCondition !== tempCondition) {
          results.push(log); // 조건을 만족하는 경우 배열에 추가
          break; // 해당 log는 추가되었으므로 다음 로그로 이동
        }
      }

      // 5. 배열에 1000개의 데이터가 채워지면 반복문 종료
      if (results.length >= 1000) {
        break;
      }
    }

    // 6. 조건에 맞는 데이터를 클라이언트에게 전달
    res.json(results);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching logs', error: err.message });
  }
});
app.get('/alarm', async (req, res) => {
  try {
    // 1. 클라이언트로부터 전달된 쿼리 파라미터를 변수에 저장
    let setACC = parseFloat(req.query.userAccSetValue); // accuracy 설정 값
    let setTemp = parseFloat(req.query.userTempSetValue); // temperature 설정 값

    // 2. 결과를 저장할 배열을 선언
    let results = [];

    // 3. MongoDB에서 최신 데이터를 cursor로 순차적으로 가져옴
    const cursor = Log.find({})
      .sort({ time: -1 }) // 최신순으로 정렬
      .cursor(); // cursor로 데이터를 순차적으로 가져옴

    // 4. cursor를 순회하며 조건에 맞는 데이터를 배열에 추가
    for await (let log of cursor) {
      // CCDResult.location이 배열이므로 각 location의 accuracy와 비교
      for (let location of log.CCDResult.location) {
        // 두 조건 모두 만족하는 경우에만 배열에 추가 (&& 연산)
        if (parseFloat(location.accuracy) > setACC && log.CCDResult.temperature > setTemp) {
          results.push(log); // 조건을 만족하는 경우 배열에 추가
          break; // 해당 log는 추가되었으므로 다음 로그로 이동
        }
      }

      // 5. 배열에 1000개의 데이터가 채워지면 반복문 종료
      if (results.length >= 1000) {
        break;
      }
    }

    // 6. 조건에 맞는 데이터를 클라이언트에게 전달
    res.json(results);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching logs', error: err.message });
  }
});
app.get('/alarmwarning', async (req, res) => {
  try {
    // 1. 클라이언트로부터 전달된 쿼리 파라미터를 변수에 저장
    let setACC = parseFloat(req.query.userAccSetValue);
    let setTemp = parseFloat(req.query.userTempSetValue);

    // 2. 결과를 저장할 배열을 선언
    let results = [];

    // 3. MongoDB에서 최신 데이터를 cursor로 순차적으로 가져옴
    const cursor = Log.find({})
      .sort({ time: -1 }) // 최신순으로 정렬
      .cursor(); // cursor로 데이터를 순차적으로 가져옴

    // 4. cursor를 순회하며 조건에 맞는 데이터를 배열에 추가
    for await (let log of cursor) {
      // CCDResult.location이 배열이므로 각 location의 accuracy와 비교
      for (let location of log.CCDResult.location) {
        if (parseFloat(location.accuracy) > setACC || log.CCDResult.temperature > setTemp) {
          results.push(log); // 조건을 만족하는 경우 배열에 추가
          break; // 해당 log는 추가되었으므로 다음 로그로 이동
        }
      }

      // 5. 배열에 1000개의 데이터가 채워지면 반복문 종료
      if (results.length >= 1000) {
        break;
      }
    }

    // 6. 조건에 맞는 데이터를 클라이언트에게 전달
    res.json(results);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching logs', error: err.message });
  }
});

// 서버를 지정된 포트에서 실행합니다.
// 서버가 실행 중임을 로그에 출력합니다.
const backEndPort = process.env.Backend_Port;
app.listen(backEndPort, '0.0.0.0', () => {
  console.log(`서버가 http://localhost:${backEndPort} 에서 실행 중입니다.`);
});

// 클라이언트가 소켓에 연결될 때 실행
io.on('connect', (socket) => {
  //console.log('New client connected');

  clients.push(socket);

  // 연결이 끊어졌을 때 처리
  socket.on('disconnect', () => {
    //console.log('Client disconnected');
    clients = clients.filter((client) => client !== socket);
  });
});

// 서버 시작
const socketIoPort = process.env.Socket_IO_Port;
server.listen(socketIoPort, () => {
  console.log(`서버가 http://localhost:${socketIoPort} 에서 실행 중입니다.`);
});
