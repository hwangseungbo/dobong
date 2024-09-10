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
        cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 }, // 한달간 유지
        store: MongoStore.create({
            mongoUrl: process.env.DB_URL,
            dbName: 'user',
        }),
    })
);
app.use(passport.session());

app.use(cors({ origin: '*', credentials: true })); // 모든 요청에 대해 CORS를 허용합니다.
app.use(express.json()); //클라이언트가 보낸 JSON 형식의 데이터를 자동으로 파싱
app.use(express.urlencoded({ extended: true })); // 클라이언트가 폼 데이터를 전송할 때 그 데이터를 req.body로 쉽게 접근할 수 있게 해줌

// 루트 경로에 대한 GET 요청을 처리합니다.
app.get('/', async (req, res) => {
    // let result = await Users.findOne({ _id: '66deb9c37d0b9e16c7d02a6c' });
    // delete result.password;
    // console.log(result);
    //let hash = await bcrypt.hash('1234', 10);
    //let result = await Users.findOneAndUpdate({ username: 'admin' }, { password: hash }).then((m) => console.log(m));

    res.send('서버열림');
});

// 루트 경로에 대한 POST 요청을 처리합니다.
app.post('/', async (req, res) => {
    try {
        //console.log(JSON.stringify(req.body));
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
    console.log(user);
    process.nextTick(() => {
        done(null, { id: user._id, username: user.username });
    });
});

passport.deserializeUser(async (user, done) => {
    let result = await Users.findOne({ _id: new ObjectId(user.id) });
    delete result.password;
    process.nextTick(() => {
        done(null, result);
    });
});

// API
app.post('/login', async (req, res, next) => {
    console.log(req.body);
    passport.authenticate('local', (error, user, info) => {
        if (error) return res.status(500).json(error);
        if (!user) return res.status(401).json(info.message);
        req.logIn(user, (err) => {
            if (err) return next(err);
            res.redirect('/dashboard'); //로그인 완료 시 이동하는 메인페이지!! 수정필
        });
    })(req, res, next);
});

app.get('/log', async (req, res) => {
    try {
        // 최근 저장된 300개 데이터 가져오기
        const logs = await Log.find({})
            .sort({ createdAt: -1 }) // 최신순으로 정렬
            .limit(300); // 최대 300개의 데이터만 가져오기

        res.send(logs); // 데이터를 JSON으로 응답
    } catch (err) {
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
    console.log('New client connected');

    clients.push(socket);

    // 연결이 끊어졌을 때 처리
    socket.on('disconnect', () => {
        console.log('Client disconnected');
        clients = clients.filter((client) => client !== socket);
    });
});

// 서버 시작
const socketIoPort = process.env.Socket_IO_Port;
server.listen(socketIoPort, () => {
    console.log(`서버가 http://localhost:${socketIoPort} 에서 실행 중입니다.`);
});
