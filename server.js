const jwt = require('jsonwebtoken');
const { expressjwt: expressJwt } = require('express-jwt');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, './.env') });
console.log("JWT_SECRET:", process.env.JWT_SECRET);
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const corsOptions = {
    exposedHeaders: ['Authorization'],
    allowedHeaders: ['Authorization', 'Content-Type']
};

const pgp = require('pg-promise')();
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs-extra');
const app = express();
const PORT = 5000;
const session = require('express-session');
const sanitizeFilename = require('sanitize-filename');
const cookieParser = require('cookie-parser');

function ensureDirectoryExists(directory) {
    if (!fs.existsSync(directory)) {
        fs.ensureDirSync(directory, { recursive: true });
    }

}
app.use(session({
    secret: '3d6f93e25a163c3a84d5534c9e0c6a21a42fabc7f9664bf2872ce31b0153c1d8',
    resave: false,
    saveUninitialized: true
}));

app.use(cookieParser());


// Middleware setup
app.use(bodyParser.json());
app.use(cors(corsOptions));
app.use(express.static('public'));
app.use('/history', (req, res, next) => {
    console.log("Received headers:", req.headers);
    next();
});
app.use('/history', (req, res, next) => {
    console.log("Received token in request:", req.headers.authorization);
    next();
});


// JWT error handling middleware
/*
app.use(expressJwt({
    secret: process.env.JWT_SECRET,
    algorithms: ['HS256'],
    getToken: function fromHeaderOrQuerystring(req) {
        if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
            return req.headers.authorization.split(' ')[1];
        } else if (req.query && req.query.token) {
            return req.query.token;
        }
        return null;
    }
}).unless({ path: [/^\/(?!history).] }));*/



// db connection setup
const db = pgp({
    host: 'localhost',
    port: 5433,
    database: 'emissionscalculation',
    user: 'postgres',
    password: 'Nofearwejj12..'
});


const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const userDirectory = path.join('./uploads', req.session.userEmail);
        console.log("Checking directory:", userDirectory);
        if (!fs.existsSync(userDirectory)) {
            fs.ensureDirSync(userDirectory);
        }
        cb(null, userDirectory);
    },
    filename: function (req, file, cb) {
        let projectTitle = req.projectTitle || "default";  // Changed from req.body.projectTitle
        let sanitizedTitle = sanitizeFilename(projectTitle);
        let timestamp = Date.now();
        let finalFilename = `${sanitizedTitle}-${timestamp}${path.extname(file.originalname)}`;
        cb(null, finalFilename);
    }
});


const upload = multer({ storage: storage });

app.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/home.html'));
});
app.get('/emissionpath', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/emissionpath.html'));
});
app.get('/energypath', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/energypath.html'));
});
app.get('/hydrogenone', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/hydrogenone.html'));
});
app.get('/emission', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/emission.html'));
});
app.get('/energy', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/energy.html'));
});
app.get('/hydro', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/index.html'));
});


app.post('/store-excel', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).send("No file uploaded");
    }

    let projectTitle = req.body.projectTitle || "default";
    let sanitizedTitle = sanitizeFilename(projectTitle);
    let timestamp = Date.now();
    let finalFilename = `${sanitizedTitle}-${timestamp}${path.extname(req.file.originalname)}`;

    // Construct old (current) path
    const oldPath = path.join(__dirname, 'uploads', req.session.userEmail, req.file.filename);

    // Construct new path
    const newPath = path.join(__dirname, 'uploads', req.session.userEmail, finalFilename);

    // Rename the file
    fs.renameSync(oldPath, newPath);

    console.log(`Stored ${finalFilename}`);
    res.send("File stored successfully");
});



app.get('/verify', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/verify.html'));
});
app.post('/verify', (req, res) => {
    const token = req.body.token; // Token sent from the HTML page

    console.log("Received token:", token);

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error(err);
            return res.status(401).send('Unauthorized');
        }
        // Token is valid, you can grant authorization here
        console.log("Token verified. User:", decoded.email);
        req.session.userEmail = decoded.email;
        res.status(200).send('Token received and verified');
    });
});






app.get('/history', (req, res) => {
    if (req.session && req.session.userEmail) {
        res.sendFile(path.join(__dirname, 'public/history.html'));
    } else {
        res.status(401).send('Please verify your identity first.');
    }
});

app.use((req, res, next) => {
    console.log("Accessing:", req.path);
    console.log("Session:", req.session);
    next();
});


app.get('/history-files', (req, res) => {
    // Extract the token from the Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, message: 'Authorization header missing' });
    }

    const token = authHeader.split(' ')[1]; // Bearer <token>

    // Verify the token
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error(err);
            return res.status(401).json({ success: false, message: 'Invalid token' });
        }

        // Token is valid; extract the user's email
        const userEmail = decoded.email;

        // Define the directory path
        const userDirectory = path.join(__dirname, 'uploads', userEmail);

        // Check if the directory exists
        if (!fs.existsSync(userDirectory)) {
            return res.json({ success: true, files: [], message: 'No files generated yet' });
        }

        // If the directory exists, list the files
        const files = fs.readdirSync(userDirectory);
        return res.json({ success: true, files });
    });
});






app.get('/download/:filename', (req, res) => {
    const userEmailDir = req.session.userEmail;
    const file = path.join(__dirname, 'uploads', userEmailDir, req.params.filename);
    res.download(file);
});


app.get('/signin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/signin.html'));
});

app.post('/validate-token', (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ valid: false });
    }

    try {
        jwt.verify(token, process.env.JWT_SECRET);
        return res.status(200).json({ valid: true });
    } catch (error) {
        return res.status(400).json({ valid: false });
    }
});


app.post('/signin', async (req, res) => {
    const { login, password } = req.body;

    // Check if user exists
    const user = await db.oneOrNone('SELECT password, email FROM users WHERE email = $1', [login]);

    if (!user) {
        return res.status(400).json({ success: false, message: 'Email not found.' });
    }

    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
        return res.status(400).json({ success: false, message: 'Incorrect password.' });
    }

    // Set session userEmail
    req.session.userEmail = user.email;

    console.log('User email after setting session:', req.session.userEmail); // Add this line
    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, {
        expiresIn: '24h'  // token will expire in 30 days
    });

    // Return the token
    return res.status(200).json({ success: true, token: token, message: 'Signin successful!' });
});


app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/signup.html'));
});

app.post('/signup', async (req, res) => {
    const { firstName, lastName, email, password } = req.body;

    // Check if user already exists
    const userExists = await db.oneOrNone('SELECT email FROM users WHERE email = $1', [email]);
    if (userExists) {
        return res.json({ success: false, message: 'Email already registered.' });
    }

    try {
        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Save user with hashed password to the database
        await db.none('INSERT INTO users(first_name, last_name, email, password) VALUES($1, $2, $3, $4)',
            [firstName, lastName, email, hashedPassword]);

        return res.json({ success: true, message: 'Signup successful!' });
    } catch (error) {
        console.error("Error:", error);
        return res.json({ success: false, message: 'Error signing up. Please try again.' });
    }
});
app.get('/logout', (req, res) => {
    console.log('Logging out user:', req.session.userEmail);

    // Log the session data before destroying it
    console.log('Session data before logout:', req.session);

    // Destroy the user's session
    req.session.destroy((err) => {
        if (err) {
            console.error("Error during logout:", err);
            return res.status(500).send("Error during logout");
        }

        // Clear the JWT token cookie if it exists
        if (req.cookies.token) {
            res.clearCookie('token');
        }

        // Redirect the user to the login page after logout
        res.redirect('/signin');
    });
});




app.use((err, req, res, next) => {
    if (err.name === 'UnauthorizedError') {
        res.status(401).send('Invalid or no token provided.');
    } else {
        next(err);
    }
});




////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////PART1//////////////////////////////////////////////////////////////



app.get('/Hcalcul', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/H-203.html'));
});

app.post('/Hcalcul', async (req, res, next) => {

    const {
        volumeflow, HHV, carbondioxide, methane, tin, v, pcon,
        ethane, propane, butane, pentane,
        hexane, heptane, octane, hydrogensulfide, Temperature, Pressure, ExcessAir, RelativeHumidity, Nitrogen, LHV, tair, tstack, loss, projecttitle, date,
        isCustomComposition,
        c1,
        c2,
        c3,
        ic4,
        nc4,
        ic5,
        nc5,
        nc6,
        nc7,
        nc8,
        nc9,
        nc10,
        nc11,
        nc12,
        nc13,
        nc14,
        nc15,
        nc16,
        nc17,
        nc18,
        nc19,
        nc20,
        nc21,
        nc22,
        nc23,
        nc24,
        nc25,
        nc26,
        nc27,
        nc28,
        nc29,
        nc30,
        benzene,
        toluene,
        oxylene,
        mxylene,
        m22propane,
        hydrosulfid,
        ox,
        nitrogene,
        ebenzene
    } = req.body;





    // Calculs
    let ch4 = (HHV * volumeflow * 9.696078431E-10) * 1000 / 16.05;
    let n2o = (HHV * volumeflow * 0.0000000000948) * 1000 / 44.02;
    let nox = (HHV * volumeflow * 4.196078431E-08) * 1000 / 30.01;
    let mwvoc = ((ethane / 100) * 30.07) + ((propane / 100) * 44.1) + ((butane / 100) * 58.12) + ((pentane / 100) * 72.5) + ((hexane / 100) * 86.18) + ((heptane / 100) * 100.21) + ((octane / 100) * 114.23);

    let voc = ((HHV * volumeflow * 2.318627451E-09) * 1000) / mwvoc;
    let co2 = (((carbondioxide / 100) * 1 + (methane / 100) * 1 + (ethane / 100) * 2 + (propane / 100) * 3 + (butane / 100) * 4 + (pentane / 100) * 5 + (hexane / 100) * 6 + (heptane / 100) * 7 + (octane / 100) * 8) * 44.01 * volumeflow * 1 / 1000000 * 42.22) * 1000 / 44.01;
    let so2 = ((hydrogensulfide) * volumeflow * 1.44114915367 * (64.06 / 34.08) / 100000) * 1000 / 64.06;
    let MolecularWeightfuel = ((carbondioxide / 100) * 44.01) + ((Nitrogen / 100) * 28.02) + ((methane / 100) * 16.05) + ((ethane / 100) * 30.07) + ((propane / 100) * 44.1) + ((butane / 100) * 58.12) + ((pentane / 100) * 72.5) + ((hexane / 100) * 86.18) + ((heptane / 100) * 100.21) + ((octane / 100) * 114.23) + ((hydrogensulfide / 100) * 34.08);



    function PR_mixture_density(Tc, Pc, omega, y, T, P, M) {
        const R = 8.314;
        const n = Tc.length;

        let a_values = Array(n).fill(0);
        let b_values = Array(n).fill(0);

        // PR EOS Parameters for each component
        for (let i = 0; i < n; i++) {
            const kappa = 0.37464 + 1.54226 * omega[i] - 0.26992 * omega[i] ** 2;
            const alpha = (1 + kappa * (1 - Math.sqrt(T / Tc[i]))) ** 2;
            a_values[i] = 0.45724 * R ** 2 * Tc[i] ** 2 / Pc[i] * alpha;
            b_values[i] = 0.07780 * R * Tc[i] / Pc[i];
        }

        // Calculate mixture a and b
        let a_mix = 0;
        const b_mix = y.reduce((acc, curr, idx) => acc + curr * b_values[idx], 0);

        for (let i = 0; i < n; i++) {
            for (let j = 0; j < n; j++) {
                const a_ij = Math.sqrt(a_values[i] * a_values[j]);  // Assuming k_ij = 0
                a_mix += y[i] * y[j] * a_ij;
            }
        }

        const A = Number(P);
        const B = Number(-R * T - P * b_mix);
        const C = Number(a_mix - P * b_mix ** 2 - R * T * b_mix);
        const D = Number(-a_mix * b_mix);

        function cubicRoots(coefficients) {
            let [A, B, C, D] = coefficients;

            let p = (3 * A * C - B ** 2) / (3 * A ** 2);
            let q = (2 * B ** 3 - 9 * A * B * C + 27 * A ** 2 * D) / (27 * A ** 3);

            let discriminant = 4 * p ** 3 + 27 * q ** 2;

            console.log("p:", p, "q:", q, "Discriminant:", discriminant);  // Debug print

            let roots = [];

            if (discriminant < 0) {
                let r = Math.sqrt((-p) ** 3 / 27);
                let theta = Math.acos(-q / (2 * r)) / 3;
                let x1 = 2 * Math.cbrt(r) * Math.cos(theta);
                let x2 = 2 * Math.cbrt(r) * Math.cos(theta + (2 * Math.PI / 3));
                let x3 = 2 * Math.cbrt(r) * Math.cos(theta - (2 * Math.PI / 3));

                roots = [x1, x2, x3];
            } else if (discriminant > 0) {
                let u = Math.cbrt(-q / 2 + Math.sqrt(discriminant / 27));
                let v = Math.cbrt(-q / 2 - Math.sqrt(discriminant / 27));

                roots = [u + v];

            } else {

                let u = Math.cbrt(-q / 2);
                let x1 = 2 * u;
                let x2 = -u;
                roots = [x1, x2, x2];
            }

            return roots.map(root => root - B / (3 * A));
        }


        const roots = cubicRoots([A, B, C, D]);
        console.log("Roots:", roots);

        const V = Math.max(...roots);
        const M_mixture = y.reduce((acc, curr, idx) => acc + curr * M[idx], 0);

        console.log("M_mixture:", M_mixture);
        console.log("V:", V);
        return M_mixture / V;
    }

    const Tc = [30.95, -146.95, 100.45, -82.45, 32.28, 96.75, 151.975, 196.6, 234.75, 267.01, 295.45].map(val => val + 273.15);
    const Pc = [7370, 3394.37, 9007.79, 4640.68, 4883.85, 4256.66, 3796, 3367.5, 3031.62, 2736.78, 2496.62].map(val => val * 1e3);
    const omega = [0.23894, 0.03999, 0.081, 0.0114984, 0.0986, 0.1524, 0.201, 0.251, 0.3007, 0.34979, 0.4018];
    const y = [
        carbondioxide / 100,
        Nitrogen / 100,
        hydrogensulfide / 100,
        methane / 100,
        ethane / 100,
        propane / 100,
        butane / 100,
        pentane / 100,
        hexane / 100,
        heptane / 100,
        octane / 100,


    ];
    const M = [44.01, 28.01, 34.08, 16.04, 30.07, 44.10, 58.12, 58.12, 72.15, 72.15, 86.18, 100.21, 114.22].map(val => val / 1000);

    let Tv = Temperature + 273.15;
    let P = Pressure * 1e5;

    console.log("Tv:", Tv, "P:", P);
    let density = PR_mixture_density(Tc, Pc, omega, y, Tv, P, M);
    console.log("density:", density);




    let fuelflowrateKmol = (volumeflow * density) / MolecularWeightfuel;
    let totaloxygen = (((methane / 100) * 2) + ((ethane / 100) * 3.5) + ((propane / 100) * 5) + ((butane / 100) * 6.5) + ((pentane / 100) * 8) + ((hexane / 100) * 9.5) + ((heptane / 100) * 11) + ((octane / 100) * 12.5) + ((hydrogensulfide / 100) * 1.5)) * fuelflowrateKmol;
    let AirflowrateKmol = (totaloxygen / 0.21) * (1 + (ExcessAir / 100));
    let N2 = AirflowrateKmol * 0.79;
    let O2 = ((AirflowrateKmol * 0.21) / (1 + (ExcessAir / 100))) * (ExcessAir / 100);
    let H2O = (((methane / 100) * 2) + ((ethane / 100) * 3) + ((propane / 100) * 4) + ((butane / 100) * 5) + ((pentane / 100) * 6) + ((hexane / 100) * 7) + ((heptane / 100) * 8) + ((octane / 100) * 9) + ((hydrogensulfide / 100) * 2)) * fuelflowrateKmol;
    let flowrategases = H2O + O2 + N2 + so2 + voc + n2o + ch4 + nox + co2;
    let yh2o = H2O / flowrategases;
    let yn2o = n2o / flowrategases;
    let ynox = nox / flowrategases;
    let yvoc = voc / flowrategases;
    let ych4 = ch4 / flowrategases;
    let yso2 = so2 / flowrategases;
    let yco2 = co2 / flowrategases;
    let yo2 = O2 / flowrategases;
    let yN2 = N2 / flowrategases;
    let ncv = MolecularWeightfuel * (LHV / density) * 1000;






    function calculateCp(component, T) {
        switch (component) {
            case "hydrogensulfide":
                return 26.88412 + 18.7 * (T / 1000) + 3.43 * Math.pow(T / 1000, 2) - 3.38 * Math.pow(T / 1000, 3) + 0.135882 / Math.pow(T / 1000, 2);
            case "N2":
                return 28.9 - 0.001571 * T + 0.000008081 * Math.pow(T, 2) - 0.000000002873 * Math.pow(T, 3);
            case "O2":
                return 25.48 + 0.0152 * T - 0.00000716 * Math.pow(T, 2) + 0.00000000131 * Math.pow(T, 3);
            case "Air":
                return 28.11 + 0.00197 * T + 0.0000048 * Math.pow(T, 2) - 0.00000000197 * Math.pow(T, 3);
            case "co2":
                return 22.26 + 0.05981 * T - 0.0000351 * Math.pow(T, 2) + 0.00000000747 * Math.pow(T, 3);
            case "H2O":
                return 32.24 + 0.00192 * T + 0.0000106 * Math.pow(T, 2) - 0.0000000036 * Math.pow(T, 3);
            case "nox":
                return 29.34 - 0.00094 * T + 0.00000975 * Math.pow(T, 2) - 0.00000000419 * Math.pow(T, 3);
            case "n2o":
                return 24.11 + 0.0586 * T - 0.0000356 * Math.pow(T, 2) + 0.0000000106 * Math.pow(T, 3);
            case "so2":
                return 25.78 + 0.058 * T - 0.0000381 * Math.pow(T, 2) + 0.00000000861 * Math.pow(T, 3);
            case "methane":
                return 19.89 + 0.0502 * T + 0.0000127 * Math.pow(T, 2) - 0.000000011 * Math.pow(T, 3);
            case "ethane":
                return 6.9 + 0.173 * T - 0.0000641 * Math.pow(T, 2) + 0.00000000729 * Math.pow(T, 3);
            case "propane":
                return -4.04 + 0.305 * T - 0.000157 * Math.pow(T, 2) + 0.0000000317 * Math.pow(T, 3);
            case "butane":
                return -7.913 + 0.416 * T - 0.00023 * Math.pow(T, 2) + 0.0000000499 * Math.pow(T, 3);
            case "pentane":
                return 6.774 + 0.454 * T - 0.000225 * Math.pow(T, 2) + 0.0000000423 * Math.pow(T, 3);
            case "hexane":
                return 6.93 + 0.552 * T - 0.000287 * Math.pow(T, 2) + 0.0000000577 * Math.pow(T, 3);
            default:
                return 0;  // Return 0 for any unhandled components
        }

    }

    let cpch4 = calculateCp("methane", Temperature + 273.15);
    let cpco2 = calculateCp("co2", Temperature + 273.15);
    let cpN2 = calculateCp("N2", Temperature + 273.15);
    let cpc2 = calculateCp("ethane", Temperature + 273.15);
    let cpc3 = calculateCp("propane", Temperature + 273.15);
    let cpc4 = calculateCp("butane", Temperature + 273.15);
    let cpc5 = calculateCp("pentane", Temperature + 273.15);
    let cpc6 = calculateCp("hexane", Temperature + 273.15);
    let cph2s = calculateCp("hydrogensulfide", Temperature + 273.15);

    let cpmix = (cpch4 * (methane / 100)) + (cpc2 * (ethane / 100)) + (cpc3 * (propane / 100)) + (cpc4 * (butane / 100)) + (cpc5 * (pentane / 100)) + (cpc6 * ((heptane + hexane + octane) / 100)) + (cpco2 * (carbondioxide / 100)) + (cpN2 * (Nitrogen / 100)) + (cph2s * (hydrogensulfide / 100));
    let Xh = 0.019;
    let minTemp = Math.min(tair, Temperature);
    let Td = minTemp - 5;
    let Qv = ncv * fuelflowrateKmol;
    let Qs = fuelflowrateKmol * cpmix * (Temperature - Td);
    let qf = Qv + Qs;
    let Tavrair = (tair + 273.15 + Td + 273.15) / 2;
    let cpair = 28.11 + 0.00197 * Tavrair + 0.0000048 * Math.pow(Tavrair, 2) - 0.00000000197 * Math.pow(Tavrair, 3);
    let Cphum = 34.42 + 6.281e-4 * Tavrair + 5.6106e-6 * Math.pow(Tavrair, 2);
    let ha = (((1 - Xh) * cpair) + (Xh * Cphum)) * (tair - Td);
    let Qair = AirflowrateKmol * ha;
    let T = ((339 + 273.15) + (30 + 273.15)) / 2;
    let cpO2 = 25.48 + 0.0152 * T - 0.00000716 * Math.pow(T, 2) + 0.00000000131 * Math.pow(T, 3);
    let cpNitro = 28.9 - 0.001571 * T + 0.000008081 * Math.pow(T, 2) - 0.000000002873 * Math.pow(T, 3);
    let cpCarb = 22.26 + 0.05981 * T - 0.0000351 * Math.pow(T, 2) + 0.00000000747 * Math.pow(T, 3);
    let cpNO = 29.34 - 0.00094 * T + 0.00000975 * Math.pow(T, 2) - 0.00000000419 * Math.pow(T, 3);
    let cpSo2 = 25.78 + 0.058 * T - 0.0000381 * Math.pow(T, 2) + 0.00000000861 * Math.pow(T, 3);
    let cpH2O = 32.24 + 0.00192 * T + 0.0000106 * Math.pow(T, 2) - 0.0000000036 * Math.pow(T, 3);
    let QO2 = yo2 * flowrategases * cpO2 * (tstack - Td);
    let QN2 = yN2 * flowrategases * cpNitro * (tstack - Td);
    let QCO2 = yco2 * flowrategases * cpCarb * (tstack - Td);
    let QNO = ynox * flowrategases * cpNO * (tstack - Td);
    let QSO2 = yso2 * flowrategases * cpSo2 * (tstack - Td);
    let QH2O = yh2o * flowrategases * cpH2O * (tstack - Td);
    let Qstack = QCO2 + QO2 + QN2 + QH2O + QSO2 + QNO;
    let Ql = (loss / 100) * fuelflowrateKmol * ncv;
    let Qin = qf + Qair;
    let Qout = Qstack + Ql;
    let Qu = Qin - Qout;
    let E = 100 * (Qu / Qin);

    let densitycon;
    let cpcon;

    function PR_mixture_liquid_density(Tc, Pc, omega, y, T, P, M) {
        const R = 8.314;
        const n = Tc.length;

        let a_values = Array(n).fill(0);
        let b_values = Array(n).fill(0);

        // PR EOS Parameters for each component
        for (let i = 0; i < n; i++) {
            const kappa = 0.37464 + 1.54226 * omega[i] - 0.26992 * omega[i] ** 2;
            const alpha = (1 + kappa * (1 - Math.sqrt(T / Tc[i]))) ** 2;
            a_values[i] = 0.45724 * R ** 2 * Tc[i] ** 2 / Pc[i] * alpha;
            b_values[i] = 0.07780 * R * Tc[i] / Pc[i];
        }

        // Calculate mixture a and b
        let a_mix = 0;
        const b_mix = y.reduce((acc, curr, idx) => acc + curr * b_values[idx], 0);

        for (let i = 0; i < n; i++) {
            for (let j = 0; j < n; j++) {
                const a_ij = Math.sqrt(a_values[i] * a_values[j]);  // Assuming k_ij = 0
                a_mix += y[i] * y[j] * a_ij;
            }
        }

        const A = Number(P);
        const B = Number(-R * T - P * b_mix);
        const C = Number(a_mix - P * b_mix ** 2 - R * T * b_mix);
        const D = Number(-a_mix * b_mix);

        function cubicRoots(coefficients) {
            let [A, B, C, D] = coefficients;

            let p = (3 * A * C - B ** 2) / (3 * A ** 2);
            let q = (2 * B ** 3 - 9 * A * B * C + 27 * A ** 2 * D) / (27 * A ** 3);

            let discriminant = 4 * p ** 3 + 27 * q ** 2;

            console.log("p:", p, "q:", q, "Discriminant:", discriminant);  // Debug print

            let roots = [];

            if (discriminant < 0) {
                let r = Math.sqrt((-p) ** 3 / 27);
                let theta = Math.acos(-q / (2 * r)) / 3;
                let x1 = 2 * Math.cbrt(r) * Math.cos(theta);
                let x2 = 2 * Math.cbrt(r) * Math.cos(theta + (2 * Math.PI / 3));
                let x3 = 2 * Math.cbrt(r) * Math.cos(theta - (2 * Math.PI / 3));

                roots = [x1, x2, x3];
            } else if (discriminant > 0) {
                let u = Math.cbrt(-q / 2 + Math.sqrt(discriminant / 27));
                let v = Math.cbrt(-q / 2 - Math.sqrt(discriminant / 27));

                roots = [u + v];

            } else {

                let u = Math.cbrt(-q / 2);
                let x1 = 2 * u;
                let x2 = -u;
                roots = [x1, x2, x2];
            }

            return roots.map(root => root - B / (3 * A));
        }


        const roots = cubicRoots([A, B, C, D]);
        console.log("Roots:", roots);

        const V = Math.min(...roots);
        const M_mixture = y.reduce((acc, curr, idx) => acc + curr * M[idx], 0);

        console.log("M_mixture:", M_mixture);
        console.log("V:", V);
        return M_mixture / V;
    }

    if (isCustomComposition) {

        const Tcc = [-82.45, 32.28, 96.75, 134.95, 152.05, 187.25, 196.45, 234.75, 267.01, 295.45, 321.45, 344.45, 365.15, 385.15, 402.65, 420.85, 433.85, 443.85, 460.22, 472.11, 482.78, 494.85, 504.85, 513.85, 522.85, 530.85, 538.85, 545.85, 552.85, 558.85, 564.85, 589.85, 288.95, 318.65, 357.22, 343.90, 160.63, 100.45, 30.95, -146.96, 343.95].map(val => val + 273.15);

        const Pcc = [4640.68, 4883.85, 4256.66, 3647.62, 3796.62, 3333.59, 3375.12, 3031.62, 2736.78, 2496.62, 2300.07, 2107.55, 1964.93, 1829.92, 1723.53, 1620.18, 1516.81, 1420.56, 1316.90, 1213.47, 1116.95, 1160.00, 1110.00, 1060.00, 1020.00, 980.00, 950.00, 910.00, 883.00, 850.00, 826.00, 868.00, 4924.39, 4100.04, 3732.81, 3541.12, 3198.82, 9007.79, 7370.00, 3394.37, 3607.12].map(val => val * 1e3);

        const omegac = [0.0115, 0.0986, 0.1524, 0.1848, 0.2010, 0.2222, 0.2539, 0.3007, 0.3498, 0.4018, 0.4455, 0.4885, 0.5350, 0.5620, 0.6230, 0.6790, 0.7060, 0.7650, 0.7700, 0.8000, 0.8270, 0.9069, 0.9420, 0.9722, 1.0262, 1.0710, 1.1053, 1.1544, 1.2136, 1.2375, 1.2653, 1.3072, 0.2150, 0.2596, 0.3023, 0.3260, 0.1964, 0.0810, 0.2389, 0.0400, 0.3010];
        const yc = [
            c1,
            c2,
            c3,
            ic4,
            nc4,
            ic5,
            nc5,
            nc6,
            nc7,
            nc8,
            nc9,
            nc10,
            nc11,
            nc12,
            nc13,
            nc14,
            nc15,
            nc16,
            nc17,
            nc18,
            nc19,
            nc20,
            nc21,
            nc22,
            nc23,
            nc24,
            nc25,
            nc26,
            nc27,
            nc28,
            nc29,
            nc30,
            benzene,
            toluene,
            oxylene,
            mxylene,
            m22propane,
            hydrosulfid,
            ox,
            nitrogene,
            ebenzene
        ];

        const Mc = [16.04, 30.07, 44.10, 58.12, 58.12, 72.15, 72.15, 86.18, 100.21, 114.23, 128.26, 142.29, 156.31, 170.34, 184.37, 198.38, 212.41, 226.43, 240.46, 254.48, 268.51, 282.54, 296.58, 310.59, 324.61, 338.64, 352.67, 366.69, 380.72, 394.74, 408.77, 422.80, 78.11, 92.14, 106.17, 106.17, 72.15, 34.08, 44.01, 28.01, 106.17].map(val => val / 1000);

        let Tcon = tin + 273.15;
        let Pcn = pcon * 1e5;

        //densitycon = PR_mixture_liquid_density(Tcc, Pcc, omegac, yc, Tcon, Pcn, Mc);
        densitycon = 431.830696587057;
        cpcon = 2.59031690533044;


    } else {
        densitycon = 431.830696587057;
        cpcon = 2.59031690533044;

    }

    let tout = tin + (Qu / (cpcon * densitycon * v));


    // After the completion of the calculations

    try {
        await db.none('INSERT INTO energyefficiency(cpcon, densitycon, pcon,c1, c2, c3, ic4, nc4,ic5, nc5, nc6, nc7, nc8, nc9, nc10, nc11, nc12, nc13, nc14, nc15, nc16, nc17, nc18, nc19, nc20, nc21, nc22, nc23, nc24, nc25, nc26, nc27, nc28, nc29, nc30, benzene, toluene, oxylene, mxylene, m22propane, hydrosulfid, ox, nitrogene, ebenzene,projecttitle, date, tin, v, volumeflow, density, HHV, carbondioxide, methane,ethane, propane, butane, pentane,hexane, heptane, octane, hydrogensulfide,Temperature,Pressure,ExcessAir,RelativeHumidity,Nitrogen,LHV,tair,tstack,loss,AirflowrateKmol,fuelflowrateKmol, MolecularWeightfuel, cpmix, ncv, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, ynox, yco2, yh2o, yN2, yso2,  yo2, Qv, Qs, Qair, Qstack, Ql, Qout, Qu, E, mwvoc, totaloxygen, ha, qf, ych4, yn2o, yvoc, tout) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50, $51, $52, $53, $54, $55, $56, $57, $58, $59, $60, $61, $62, $63, $64, $65, $66, $67, $68, $69, $70, $71, $72,$73, $74, $75, $76, $77, $78, $79, $80, $81, $82,$83, $84, $85, $86, $87, $88, $89, $90, $91, $92,$93, $94, $95, $96, $97, $98, $99, $100, $101, $102, $103, $104, $105, $106, $107)', [cpcon, densitycon, pcon, c1, c2, c3, ic4, nc4, ic5, nc5, nc6, nc7, nc8, nc9, nc10, nc11, nc12, nc13, nc14, nc15, nc16, nc17, nc18, nc19, nc20, nc21, nc22, nc23, nc24, nc25, nc26, nc27, nc28, nc29, nc30, benzene, toluene, oxylene, mxylene, m22propane, hydrosulfid, ox, nitrogene, ebenzene, projecttitle, date, tin, v, volumeflow, density, HHV, carbondioxide, methane, ethane, propane, butane, pentane, hexane, heptane, octane, hydrogensulfide, Temperature, Pressure, ExcessAir, RelativeHumidity, Nitrogen, LHV, tair, tstack, loss, AirflowrateKmol, fuelflowrateKmol, MolecularWeightfuel, cpmix, ncv, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, ynox, yco2, yh2o, yN2, yso2, yo2, Qv, Qs, Qair, Qstack, Ql, Qout, Qu, E, mwvoc, totaloxygen, ha, qf, ych4, yn2o, yvoc, tout]);
        console.log("Data saved successfully.");

        res.json({
            AirflowrateKmol, density, fuelflowrateKmol, MolecularWeightfuel, cpmix, ncv, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, Qv, Qs, Qair, Qstack, Ql, Qout, Qu, E, ynox, yco2, yh2o, yN2, yso2, yo2, mwvoc, totaloxygen, ha, qf, ych4, yn2o, yvoc, densitycon, cpcon, tout
        });
    } catch (error) {
        console.error("Error saving data:", error.message);
    }

});
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////PART2//////////////////////////////////////////////////////////////////


app.get('/Hturbine', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/Turbine.html'));
});

app.post('/Hturbine', async (req, res, next) => {

    const {
        volumeflow, HHV, carbondioxide, methane,
        ethane, propane, butane, pentane, pres,
        hexane, heptane, octane, hydrogensulfide, Temperature, Pressure, ExcessAir, Nitrogen, LHV, tair, projecttitle, date
    } = req.body;






    // Calculs
    let ch4 = (HHV * volumeflow * 3.700245446E-09) * 1000;
    let n2o = (HHV * volumeflow * 1.290297876E-09) * 1000;
    let nox = (HHV * volumeflow * 1.3746468314E-07) * 1000;

    let voc = (HHV * volumeflow * 9.02529105E-10) * 1000;
    let co2 = (((carbondioxide / 100) * 1 + (methane / 100) * 1 + (ethane / 100) * 2 + (propane / 100) * 3 + (butane / 100) * 4 + (pentane / 100) * 5 + (hexane / 100) * 6 + (heptane / 100) * 7 + (octane / 100) * 8) * 44.01 * volumeflow * 1 / 1000000 * 42.22) * 1000;
    let so2 = ((hydrogensulfide) * volumeflow * 1.44114915367 * (64.06 / 34.08) / 100000) * 1000;
    let MolecularWeightfuel = ((carbondioxide / 100) * 44.01) + ((Nitrogen / 100) * 28.02) + ((methane / 100) * 16.05) + ((ethane / 100) * 30.07) + ((propane / 100) * 44.1) + ((butane / 100) * 58.12) + ((pentane / 100) * 72.5) + ((hexane / 100) * 86.18) + ((heptane / 100) * 100.21) + ((octane / 100) * 114.23) + ((hydrogensulfide / 100) * 34.08);



    function PR_mixture_density(Tc, Pc, omega, y, T, P, M) {
        const R = 8.314;
        const n = Tc.length;

        let a_values = Array(n).fill(0);
        let b_values = Array(n).fill(0);

        // PR EOS Parameters for each component
        for (let i = 0; i < n; i++) {
            const kappa = 0.37464 + 1.54226 * omega[i] - 0.26992 * omega[i] ** 2;
            const alpha = (1 + kappa * (1 - Math.sqrt(T / Tc[i]))) ** 2;
            a_values[i] = 0.45724 * R ** 2 * Tc[i] ** 2 / Pc[i] * alpha;
            b_values[i] = 0.07780 * R * Tc[i] / Pc[i];
        }

        // Calculate mixture a and b
        let a_mix = 0;
        const b_mix = y.reduce((acc, curr, idx) => acc + curr * b_values[idx], 0);

        for (let i = 0; i < n; i++) {
            for (let j = 0; j < n; j++) {
                const a_ij = Math.sqrt(a_values[i] * a_values[j]);  // Assuming k_ij = 0
                a_mix += y[i] * y[j] * a_ij;
            }
        }

        const A = Number(P);
        const B = Number(-R * T - P * b_mix);
        const C = Number(a_mix - P * b_mix ** 2 - R * T * b_mix);
        const D = Number(-a_mix * b_mix);

        function cubicRoots(coefficients) {
            let [A, B, C, D] = coefficients;

            let p = (3 * A * C - B ** 2) / (3 * A ** 2);
            let q = (2 * B ** 3 - 9 * A * B * C + 27 * A ** 2 * D) / (27 * A ** 3);

            let discriminant = 4 * p ** 3 + 27 * q ** 2;

            console.log("p:", p, "q:", q, "Discriminant:", discriminant);  // Debug print

            let roots = [];

            if (discriminant < 0) {
                let r = Math.sqrt((-p) ** 3 / 27);
                let theta = Math.acos(-q / (2 * r)) / 3;
                let x1 = 2 * Math.cbrt(r) * Math.cos(theta);
                let x2 = 2 * Math.cbrt(r) * Math.cos(theta + (2 * Math.PI / 3));
                let x3 = 2 * Math.cbrt(r) * Math.cos(theta - (2 * Math.PI / 3));

                roots = [x1, x2, x3];
            } else if (discriminant > 0) {
                let u = Math.cbrt(-q / 2 + Math.sqrt(discriminant / 27));
                let v = Math.cbrt(-q / 2 - Math.sqrt(discriminant / 27));

                roots = [u + v];

            } else {

                let u = Math.cbrt(-q / 2);
                let x1 = 2 * u;
                let x2 = -u;
                roots = [x1, x2, x2];
            }

            return roots.map(root => root - B / (3 * A));
        }


        const roots = cubicRoots([A, B, C, D]);
        console.log("Roots:", roots);

        const V = Math.max(...roots);
        const M_mixture = y.reduce((acc, curr, idx) => acc + curr * M[idx], 0);

        console.log("M_mixture:", M_mixture);
        console.log("V:", V);
        return M_mixture / V;
    }

    const Tc = [30.95, -146.95, 100.45, -82.45, 32.28, 96.75, 151.975, 196.6, 234.75, 267.01, 295.45].map(val => val + 273.15);
    const Pc = [7370, 3394.37, 9007.79, 4640.68, 4883.85, 4256.66, 3796, 3367.5, 3031.62, 2736.78, 2496.62].map(val => val * 1e3);
    const omega = [0.23894, 0.03999, 0.081, 0.0114984, 0.0986, 0.1524, 0.201, 0.251, 0.3007, 0.34979, 0.4018];
    const y = [
        carbondioxide / 100,
        Nitrogen / 100,
        hydrogensulfide / 100,
        methane / 100,
        ethane / 100,
        propane / 100,
        butane / 100,
        pentane / 100,
        hexane / 100,
        heptane / 100,
        octane / 100,


    ];
    const M = [44.01, 28.01, 34.08, 16.04, 30.07, 44.10, 58.12, 58.12, 72.15, 72.15, 86.18, 100.21, 114.22].map(val => val / 1000);

    let Tv = Temperature + 273.15;
    let P = Pressure * 1e5;

    console.log("Tv:", Tv, "P:", P);
    let density = PR_mixture_density(Tc, Pc, omega, y, Tv, P, M);
    console.log("density:", density);




    let fuelflowrateKmol = volumeflow * density;
    let totaloxygen = (((methane / 100) * 2) + ((ethane / 100) * 3.5) + ((propane / 100) * 5) + ((butane / 100) * 6.5) + ((pentane / 100) * 8) + ((hexane / 100) * 9.5) + ((heptane / 100) * 11) + ((octane / 100) * 12.5) + ((hydrogensulfide / 100) * 1.5)) * fuelflowrateKmol;
    let AirflowrateKmol = (totaloxygen / 0.21) * (1 + (ExcessAir / 100));
    let N2 = AirflowrateKmol * 0.79;
    let O2 = ((AirflowrateKmol * 0.21) / (1 + (ExcessAir / 100))) * (ExcessAir / 100);
    let H2O = (((methane / 100) * 2) + ((ethane / 100) * 3) + ((propane / 100) * 4) + ((butane / 100) * 5) + ((pentane / 100) * 6) + ((hexane / 100) * 7) + ((heptane / 100) * 8) + ((octane / 100) * 9) + ((hydrogensulfide / 100) * 2)) * fuelflowrateKmol;
    let flowrategases = H2O + O2 + N2 + so2 + voc + n2o + ch4 + nox + co2;
    let yh2o = H2O / flowrategases;
    let yn2o = n2o / flowrategases;
    let ynox = nox / flowrategases;
    let yvoc = voc / flowrategases;
    let ych4 = ch4 / flowrategases;
    let yso2 = so2 / flowrategases;
    let yco2 = co2 / flowrategases;
    let yo2 = O2 / flowrategases;
    let yN2 = N2 / flowrategases;

    let cp1 = (28.11 + 0.00197 * (tair + 273.15) + 0.0000048 * Math.pow((tair + 273.15), 2) - 0.00000000197 * Math.pow((tair + 273.15), 3)) / 28.82;
    let r = 8.31;
    let gammai = (cp1 * 28.82) / ((cp1 * 28.82) - r);
    //COMPRESSOR
    let p2 = pres * 18.7;
    let t2is = (tair + 273.15) * Math.pow((p2 / pres), ((gammai - 1) / gammai));
    let t2 = (tair + 273.15) + ((t2is - (tair + 273.15)) / 0.89);
    let cp2 = (28.11 + 0.00197 * t2 + 0.0000048 * Math.pow(t2, 2) - 0.00000000197 * Math.pow(t2, 3)) / 28.82;
    let wc = ((cp2 * t2) - (cp1 * (tair + 273.15))) / 0.99;

    //COMBUSTION CHAMBER
    let qc = ((fuelflowrateKmol / AirflowrateKmol) * (LHV / density)) * 1000;
    //TURBINE 
    let p3 = p2 * (1 - 0.02);
    let t3 = 1493;
    let cpO2 = 25.48 + 0.0152 * t3 - 0.00000716 * Math.pow(t3, 2) + 0.00000000131 * Math.pow(t3, 3);
    let cpNitro = 28.9 - 0.001571 * t3 + 0.000008081 * Math.pow(t3, 2) - 0.000000002873 * Math.pow(t3, 3);
    let cpCarb = 22.26 + 0.05981 * t3 - 0.0000351 * Math.pow(t3, 2) + 0.00000000747 * Math.pow(t3, 3);
    let cpNO = 29.34 - 0.00094 * t3 + 0.00000975 * Math.pow(t3, 2) - 0.00000000419 * Math.pow(t3, 3);
    let cpSo2 = 25.78 + 0.058 * t3 - 0.0000381 * Math.pow(t3, 2) + 0.00000000861 * Math.pow(t3, 3);
    let cpH2O = 32.24 + 0.00192 * t3 + 0.0000106 * Math.pow(t3, 2) - 0.0000000036 * Math.pow(t3, 3);
    let cp3 = (yo2 * cpO2) + (yN2 * cpNitro) + (yco2 * cpCarb) + (ynox * cpNO) + (yso2 * cpSo2) + (yh2o * cpH2O);
    let mw = yo2 * 32.00 + yN2 * 28.02 + yco2 * 44.01 + ynox * 30.01 + yso2 * 64.07 + yh2o * 18.02;
    let gammao = cp3 / (cp3 - r);
    let p4 = 1.1617;
    let t4is = t3 * Math.pow((p4 / p3), ((gammao - 1) / gammao));
    let t4 = t3 - (t3 - t4is) * 0.89;
    let wt = cp3 * (t3 - t4) / mw;
    let wcyc = wt - wc;
    let e = (wcyc / qc) * 100;

    // After the completion of the calculations

    try {
        await db.none('INSERT INTO turbine(projecttitle, date, volumeflow, HHV, carbondioxide, methane,ethane, propane, butane, pentane,hexane, heptane, octane, hydrogensulfide,Temperature,Pressure,ExcessAir,Nitrogen,LHV,tair,AirflowrateKmol,fuelflowrateKmol, MolecularWeightfuel, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, ynox, yco2, yh2o, yN2, yso2,  yo2, e, totaloxygen, ych4, yn2o, yvoc, wc, wt, wcyc,qc, cp3, mw) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50)', [projecttitle, date, volumeflow, HHV, carbondioxide, methane, ethane, propane, butane, pentane, hexane, heptane, octane, hydrogensulfide, Temperature, Pressure, ExcessAir, Nitrogen, LHV, tair, AirflowrateKmol, fuelflowrateKmol, MolecularWeightfuel, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, ynox, yco2, yh2o, yN2, yso2, yo2, e, totaloxygen, ych4, yn2o, yvoc, wc, wt, wcyc, qc, cp3, mw]);
        console.log("Data saved successfully.");

        res.json({
            AirflowrateKmol, fuelflowrateKmol, flowrategases, wc, wt, wcyc, e, qc
        });
    } catch (error) {
        console.error("Error saving data:", error.message);
    }

});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////PART3////////////////////////////////////////////////////////////////////////////


app.get('/GHGturbine', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/ghgtur.html'));
});

app.post('/GHGturbine', async (req, res, next) => {

    const {
        volumeflow, hhv, carbondioxide, methane, excessair,
        ethane, propane, butane, pentane,
        hexane, heptane, octane, hydrogensulfide, nitrogen, lhv, projecttitle, date, pressure, temperature
    } = req.body;





    // Calculs
    let ch4 = (hhv * volumeflow * 3.700245446E-09);
    let n2o = (hhv * volumeflow * 1.290297876E-09);
    let nox = (hhv * volumeflow * 1.3746468314E-07);
    let voc = (hhv * volumeflow * 9.02529105E-10);
    let co2 = (((carbondioxide / 100) * 1 + (methane / 100) * 1 + (ethane / 100) * 2 + (propane / 100) * 3 + (butane / 100) * 4 + (pentane / 100) * 5 + (hexane / 100) * 6 + (heptane / 100) * 7 + (octane / 100) * 8) * 44.01 * volumeflow * 1 / 1000000 * 42.22);
    let so2 = ((hydrogensulfide) * volumeflow * 1.44114915367 * (64.06 / 34.08) / 100000);

    function PR_mixture_density(Tc, Pc, omega, y, T, P, M) {
        const R = 8.314;
        const n = Tc.length;

        let a_values = Array(n).fill(0);
        let b_values = Array(n).fill(0);

        // PR EOS Parameters for each component
        for (let i = 0; i < n; i++) {
            const kappa = 0.37464 + 1.54226 * omega[i] - 0.26992 * omega[i] ** 2;
            const alpha = (1 + kappa * (1 - Math.sqrt(T / Tc[i]))) ** 2;
            a_values[i] = 0.45724 * R ** 2 * Tc[i] ** 2 / Pc[i] * alpha;
            b_values[i] = 0.07780 * R * Tc[i] / Pc[i];
        }

        // Calculate mixture a and b
        let a_mix = 0;
        const b_mix = y.reduce((acc, curr, idx) => acc + curr * b_values[idx], 0);

        for (let i = 0; i < n; i++) {
            for (let j = 0; j < n; j++) {
                const a_ij = Math.sqrt(a_values[i] * a_values[j]);  // Assuming k_ij = 0
                a_mix += y[i] * y[j] * a_ij;
            }
        }

        const A = Number(P);
        const B = Number(-R * T - P * b_mix);
        const C = Number(a_mix - P * b_mix ** 2 - R * T * b_mix);
        const D = Number(-a_mix * b_mix);

        function cubicRoots(coefficients) {
            let [A, B, C, D] = coefficients;

            let p = (3 * A * C - B ** 2) / (3 * A ** 2);
            let q = (2 * B ** 3 - 9 * A * B * C + 27 * A ** 2 * D) / (27 * A ** 3);

            let discriminant = 4 * p ** 3 + 27 * q ** 2;

            console.log("p:", p, "q:", q, "Discriminant:", discriminant);  // Debug print

            let roots = [];

            if (discriminant < 0) {
                let r = Math.sqrt((-p) ** 3 / 27);
                let theta = Math.acos(-q / (2 * r)) / 3;
                let x1 = 2 * Math.cbrt(r) * Math.cos(theta);
                let x2 = 2 * Math.cbrt(r) * Math.cos(theta + (2 * Math.PI / 3));
                let x3 = 2 * Math.cbrt(r) * Math.cos(theta - (2 * Math.PI / 3));

                roots = [x1, x2, x3];
            } else if (discriminant > 0) {
                let u = Math.cbrt(-q / 2 + Math.sqrt(discriminant / 27));
                let v = Math.cbrt(-q / 2 - Math.sqrt(discriminant / 27));

                roots = [u + v];

            } else {

                let u = Math.cbrt(-q / 2);
                let x1 = 2 * u;
                let x2 = -u;
                roots = [x1, x2, x2];
            }

            return roots.map(root => root - B / (3 * A));
        }


        const roots = cubicRoots([A, B, C, D]);
        console.log("Roots:", roots);

        const V = Math.max(...roots);
        const M_mixture = y.reduce((acc, curr, idx) => acc + curr * M[idx], 0);

        console.log("M_mixture:", M_mixture);
        console.log("V:", V);
        return M_mixture / V;
    }

    const Tc = [30.95, -146.95, 100.45, -82.45, 32.28, 96.75, 151.975, 196.6, 234.75, 267.01, 295.45].map(val => val + 273.15);
    const Pc = [7370, 3394.37, 9007.79, 4640.68, 4883.85, 4256.66, 3796, 3367.5, 3031.62, 2736.78, 2496.62].map(val => val * 1e3);
    const omega = [0.23894, 0.03999, 0.081, 0.0114984, 0.0986, 0.1524, 0.201, 0.251, 0.3007, 0.34979, 0.4018];
    const y = [
        carbondioxide / 100,
        nitrogen / 100,
        hydrogensulfide / 100,
        methane / 100,
        ethane / 100,
        propane / 100,
        butane / 100,
        pentane / 100,
        hexane / 100,
        heptane / 100,
        octane / 100,


    ];
    const M = [44.01, 28.01, 34.08, 16.04, 30.07, 44.10, 58.12, 58.12, 72.15, 72.15, 86.18, 100.21, 114.22].map(val => val / 1000);

    let Tv = temperature + 273.15;
    let P = pressure * 1e5;

    console.log("Tv:", Tv, "P:", P);
    let density = PR_mixture_density(Tc, Pc, omega, y, Tv, P, M);
    console.log("density:", density);

    let fuelflowrate = (volumeflow * density) / 1000;
    let totaloxygen = (((methane / 100) * 2) + ((ethane / 100) * 3.5) + ((propane / 100) * 5) + ((butane / 100) * 6.5) + ((pentane / 100) * 8) + ((hexane / 100) * 9.5) + ((heptane / 100) * 11) + ((octane / 100) * 12.5) + ((hydrogensulfide / 100) * 1.5)) * fuelflowrate;
    let airflowrate = (totaloxygen / 0.21) * (1 + (excessair / 100));
    let N2 = airflowrate * 0.79;
    let O2 = ((airflowrate * 0.21) / (1 + (excessair / 100))) * (excessair / 100);
    let H2O = (((methane / 100) * 2) + ((ethane / 100) * 3) + ((propane / 100) * 4) + ((butane / 100) * 5) + ((pentane / 100) * 6) + ((hexane / 100) * 7) + ((heptane / 100) * 8) + ((octane / 100) * 9) + ((hydrogensulfide / 100) * 2)) * fuelflowrate;
    let flowrategases = H2O + O2 + N2 + so2 + voc + n2o + ch4 + nox + co2;
    let ghg = co2 + (ch4 * 28) + (n2o * 298)

    // After the completion of the calculations

    try {
        await db.none('INSERT INTO ghgturbine(projecttitle, pressure, temperature, date, volumeflow, hhv, carbondioxide, methane,ethane, propane, butane, pentane,hexane, heptane, octane, hydrogensulfide, nitrogen,lhv,airflowrate,fuelflowrate, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases,totaloxygen, ghg) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32)', [projecttitle, pressure, temperature, date, volumeflow, hhv, carbondioxide, methane, ethane, propane, butane, pentane, hexane, heptane, octane, hydrogensulfide, nitrogen, lhv, airflowrate, fuelflowrate, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, totaloxygen, ghg]);
        console.log("Data saved successfully.");

        res.json({
            airflowrate, fuelflowrate, flowrategases, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, ghg
        });
    } catch (error) {
        console.error("Error saving data:", error.message);
    }

});
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////part 4 ///////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get('/Flar', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/flare.html'));
});

app.post('/Flar', async (req, res, next) => {

    const {
        volumeflow, hhv, carbondioxide, methane, excessair,
        ethane, propane, butane, pentane,
        hexane, heptane, octane, hydrogensulfide, nitrogen, lhv, projecttitle, date, pressure, temperature
    } = req.body;





    // Calculs
    let ch4 = ((methane / 100) * volumeflow * 0.02 * 16 * 42.22) / 100000000;
    let n2o = (hhv * volumeflow * 9.48E-11);
    let nox = (hhv * volumeflow * 2.92E-08);
    let voc = ((ethane / 100) * 30 + (propane / 100) * 44 + (butane / 100) * 58 + (pentane / 100) * 72 + (hexane / 100) * 86 + (heptane / 100) * 100 + (octane / 100) * 114) * 100 * volumeflow * 1 / 1000000 * 42.22 * 0.02;
    let co2 = (((carbondioxide / 100) * 1 + 0.98 * ((methane / 100) * 1 + (ethane / 100) * 2 + (propane / 100) * 3 + (butane / 100) * 4 + (pentane / 100) * 5 + (hexane / 100) * 6 + (heptane / 100) * 7 + (octane / 100) * 8) * 44.01 * volumeflow * 1 / 1000000 * 42.22));
    let so2 = 0.98 * ((hydrogensulfide) * volumeflow * 1.44114915367 * (64.06 / 34.08) / 100000);
    function PR_mixture_density(Tc, Pc, omega, y, T, P, M) {
        const R = 8.314;
        const n = Tc.length;

        let a_values = Array(n).fill(0);
        let b_values = Array(n).fill(0);

        // PR EOS Parameters for each component
        for (let i = 0; i < n; i++) {
            const kappa = 0.37464 + 1.54226 * omega[i] - 0.26992 * omega[i] ** 2;
            const alpha = (1 + kappa * (1 - Math.sqrt(T / Tc[i]))) ** 2;
            a_values[i] = 0.45724 * R ** 2 * Tc[i] ** 2 / Pc[i] * alpha;
            b_values[i] = 0.07780 * R * Tc[i] / Pc[i];
        }

        // Calculate mixture a and b
        let a_mix = 0;
        const b_mix = y.reduce((acc, curr, idx) => acc + curr * b_values[idx], 0);

        for (let i = 0; i < n; i++) {
            for (let j = 0; j < n; j++) {
                const a_ij = Math.sqrt(a_values[i] * a_values[j]);  // Assuming k_ij = 0
                a_mix += y[i] * y[j] * a_ij;
            }
        }

        const A = Number(P);
        const B = Number(-R * T - P * b_mix);
        const C = Number(a_mix - P * b_mix ** 2 - R * T * b_mix);
        const D = Number(-a_mix * b_mix);

        function cubicRoots(coefficients) {
            let [A, B, C, D] = coefficients;

            let p = (3 * A * C - B ** 2) / (3 * A ** 2);
            let q = (2 * B ** 3 - 9 * A * B * C + 27 * A ** 2 * D) / (27 * A ** 3);

            let discriminant = 4 * p ** 3 + 27 * q ** 2;

            console.log("p:", p, "q:", q, "Discriminant:", discriminant);  // Debug print

            let roots = [];

            if (discriminant < 0) {
                let r = Math.sqrt((-p) ** 3 / 27);
                let theta = Math.acos(-q / (2 * r)) / 3;
                let x1 = 2 * Math.cbrt(r) * Math.cos(theta);
                let x2 = 2 * Math.cbrt(r) * Math.cos(theta + (2 * Math.PI / 3));
                let x3 = 2 * Math.cbrt(r) * Math.cos(theta - (2 * Math.PI / 3));

                roots = [x1, x2, x3];
            } else if (discriminant > 0) {
                let u = Math.cbrt(-q / 2 + Math.sqrt(discriminant / 27));
                let v = Math.cbrt(-q / 2 - Math.sqrt(discriminant / 27));

                roots = [u + v];

            } else {

                let u = Math.cbrt(-q / 2);
                let x1 = 2 * u;
                let x2 = -u;
                roots = [x1, x2, x2];
            }

            return roots.map(root => root - B / (3 * A));
        }


        const roots = cubicRoots([A, B, C, D]);
        console.log("Roots:", roots);

        const V = Math.max(...roots);
        const M_mixture = y.reduce((acc, curr, idx) => acc + curr * M[idx], 0);

        console.log("M_mixture:", M_mixture);
        console.log("V:", V);
        return M_mixture / V;
    }

    const Tc = [30.95, -146.95, 100.45, -82.45, 32.28, 96.75, 151.975, 196.6, 234.75, 267.01, 295.45].map(val => val + 273.15);
    const Pc = [7370, 3394.37, 9007.79, 4640.68, 4883.85, 4256.66, 3796, 3367.5, 3031.62, 2736.78, 2496.62].map(val => val * 1e3);
    const omega = [0.23894, 0.03999, 0.081, 0.0114984, 0.0986, 0.1524, 0.201, 0.251, 0.3007, 0.34979, 0.4018];
    const y = [
        carbondioxide / 100,
        nitrogen / 100,
        hydrogensulfide / 100,
        methane / 100,
        ethane / 100,
        propane / 100,
        butane / 100,
        pentane / 100,
        hexane / 100,
        heptane / 100,
        octane / 100,


    ];
    const M = [44.01, 28.01, 34.08, 16.04, 30.07, 44.10, 58.12, 58.12, 72.15, 72.15, 86.18, 100.21, 114.22].map(val => val / 1000);

    let Tv = temperature + 273.15;
    let P = pressure * 1e5;

    console.log("Tv:", Tv, "P:", P);
    let density = PR_mixture_density(Tc, Pc, omega, y, Tv, P, M);
    console.log("density:", density);

    let fuelflowrate = (volumeflow * density) / 1000;
    let totaloxygen = (((methane / 100) * 2) + ((ethane / 100) * 3.5) + ((propane / 100) * 5) + ((butane / 100) * 6.5) + ((pentane / 100) * 8) + ((hexane / 100) * 9.5) + ((heptane / 100) * 11) + ((octane / 100) * 12.5) + ((hydrogensulfide / 100) * 1.5)) * fuelflowrate;
    let airflowrate = (totaloxygen / 0.21) * (1 + (excessair / 100));
    let N2 = airflowrate * 0.79;
    let O2 = ((airflowrate * 0.21) / (1 + (excessair / 100))) * (excessair / 100);
    let H2O = (((methane / 100) * 2) + ((ethane / 100) * 3) + ((propane / 100) * 4) + ((butane / 100) * 5) + ((pentane / 100) * 6) + ((hexane / 100) * 7) + ((heptane / 100) * 8) + ((octane / 100) * 9) + ((hydrogensulfide / 100) * 2)) * fuelflowrate;
    let flowrategases = H2O + O2 + N2 + so2 + voc + n2o + ch4 + nox + co2;
    let ghg = co2 + (ch4 * 28) + (n2o * 298)
    let ch = ((ethane / 100) * 30 + (propane / 100) * 44 + (butane / 100) * 58 + (pentane / 100) * 72 + (hexane / 100) * 86 + (heptane / 100) * 100 + (octane / 100) * 114) * 100 * volumeflow * 1 / 1000000 * 42.22;







    // After the completion of the calculations

    try {
        await db.none('INSERT INTO flare(projecttitle, pressure, temperature, date, volumeflow, hhv, carbondioxide, methane,ethane, propane, butane, pentane,hexane, heptane, octane, hydrogensulfide, nitrogen,lhv,airflowrate,fuelflowrate, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases,totaloxygen, ghg, ch) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33)', [projecttitle, pressure, temperature, date, volumeflow, hhv, carbondioxide, methane, ethane, propane, butane, pentane, hexane, heptane, octane, hydrogensulfide, nitrogen, lhv, airflowrate, fuelflowrate, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, totaloxygen, ghg, ch]);
        console.log("Data saved successfully.");
        res.json({
            airflowrate, fuelflowrate, flowrategases, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, ghg, ch
        });
    } catch (error) {
        console.error("Error saving data:", error.message);
    }

});



/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////PART5/////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.get('/GHGincinerator', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/GHGincinerator.html'));
});

app.post('/GHGincinerator', async (req, res, next) => {

    const {
        volumeflow, hhv, carbondioxide, methane, excessair,
        ethane, propane, butane, pentane,
        hexane, heptane, octane, hydrogensulfide, nitrogen, lhv, projecttitle, date, pressure, temperature
    } = req.body;





    // Calculs
    let ch4 = (hhv * volumeflow * 9.696078431E-10);
    let n2o = (hhv * volumeflow * 0.0000000000948);
    let nox = (hhv * volumeflow * 4.196078431E-08);
    let voc = (hhv * volumeflow * 2.318627451E-09);
    let co2 = (((carbondioxide / 100) * 1 + (methane / 100) * 1 + (ethane / 100) * 2 + (propane / 100) * 3 + (butane / 100) * 4 + (pentane / 100) * 5 + (hexane / 100) * 6 + (heptane / 100) * 7 + (octane / 100) * 8) * 44.01 * volumeflow * 1 / 1000000 * 42.22);
    let so2 = ((hydrogensulfide) * volumeflow * 1.44114915367 * (64.06 / 34.08) / 100000);

    function PR_mixture_density(Tc, Pc, omega, y, T, P, M) {
        const R = 8.314;
        const n = Tc.length;

        let a_values = Array(n).fill(0);
        let b_values = Array(n).fill(0);

        // PR EOS Parameters for each component
        for (let i = 0; i < n; i++) {
            const kappa = 0.37464 + 1.54226 * omega[i] - 0.26992 * omega[i] ** 2;
            const alpha = (1 + kappa * (1 - Math.sqrt(T / Tc[i]))) ** 2;
            a_values[i] = 0.45724 * R ** 2 * Tc[i] ** 2 / Pc[i] * alpha;
            b_values[i] = 0.07780 * R * Tc[i] / Pc[i];
        }

        // Calculate mixture a and b
        let a_mix = 0;
        const b_mix = y.reduce((acc, curr, idx) => acc + curr * b_values[idx], 0);

        for (let i = 0; i < n; i++) {
            for (let j = 0; j < n; j++) {
                const a_ij = Math.sqrt(a_values[i] * a_values[j]);  // Assuming k_ij = 0
                a_mix += y[i] * y[j] * a_ij;
            }
        }

        const A = Number(P);
        const B = Number(-R * T - P * b_mix);
        const C = Number(a_mix - P * b_mix ** 2 - R * T * b_mix);
        const D = Number(-a_mix * b_mix);

        function cubicRoots(coefficients) {
            let [A, B, C, D] = coefficients;

            let p = (3 * A * C - B ** 2) / (3 * A ** 2);
            let q = (2 * B ** 3 - 9 * A * B * C + 27 * A ** 2 * D) / (27 * A ** 3);

            let discriminant = 4 * p ** 3 + 27 * q ** 2;

            console.log("p:", p, "q:", q, "Discriminant:", discriminant);  // Debug print

            let roots = [];

            if (discriminant < 0) {
                let r = Math.sqrt((-p) ** 3 / 27);
                let theta = Math.acos(-q / (2 * r)) / 3;
                let x1 = 2 * Math.cbrt(r) * Math.cos(theta);
                let x2 = 2 * Math.cbrt(r) * Math.cos(theta + (2 * Math.PI / 3));
                let x3 = 2 * Math.cbrt(r) * Math.cos(theta - (2 * Math.PI / 3));

                roots = [x1, x2, x3];
            } else if (discriminant > 0) {
                let u = Math.cbrt(-q / 2 + Math.sqrt(discriminant / 27));
                let v = Math.cbrt(-q / 2 - Math.sqrt(discriminant / 27));

                roots = [u + v];

            } else {

                let u = Math.cbrt(-q / 2);
                let x1 = 2 * u;
                let x2 = -u;
                roots = [x1, x2, x2];
            }

            return roots.map(root => root - B / (3 * A));
        }


        const roots = cubicRoots([A, B, C, D]);
        console.log("Roots:", roots);

        const V = Math.max(...roots);
        const M_mixture = y.reduce((acc, curr, idx) => acc + curr * M[idx], 0);

        console.log("M_mixture:", M_mixture);
        console.log("V:", V);
        return M_mixture / V;
    }

    const Tc = [30.95, -146.95, 100.45, -82.45, 32.28, 96.75, 151.975, 196.6, 234.75, 267.01, 295.45].map(val => val + 273.15);
    const Pc = [7370, 3394.37, 9007.79, 4640.68, 4883.85, 4256.66, 3796, 3367.5, 3031.62, 2736.78, 2496.62].map(val => val * 1e3);
    const omega = [0.23894, 0.03999, 0.081, 0.0114984, 0.0986, 0.1524, 0.201, 0.251, 0.3007, 0.34979, 0.4018];
    const y = [
        carbondioxide / 100,
        nitrogen / 100,
        hydrogensulfide / 100,
        methane / 100,
        ethane / 100,
        propane / 100,
        butane / 100,
        pentane / 100,
        hexane / 100,
        heptane / 100,
        octane / 100,


    ];
    const M = [44.01, 28.01, 34.08, 16.04, 30.07, 44.10, 58.12, 58.12, 72.15, 72.15, 86.18, 100.21, 114.22].map(val => val / 1000);

    let Tv = temperature + 273.15;
    let P = pressure * 1e5;

    console.log("Tv:", Tv, "P:", P);
    let density = PR_mixture_density(Tc, Pc, omega, y, Tv, P, M);
    console.log("density:", density);

    let fuelflowrate = (volumeflow * density) / 1000;
    let totaloxygen = (((methane / 100) * 2) + ((ethane / 100) * 3.5) + ((propane / 100) * 5) + ((butane / 100) * 6.5) + ((pentane / 100) * 8) + ((hexane / 100) * 9.5) + ((heptane / 100) * 11) + ((octane / 100) * 12.5) + ((hydrogensulfide / 100) * 1.5)) * fuelflowrate;
    let airflowrate = (totaloxygen / 0.21) * (1 + (excessair / 100));
    let N2 = airflowrate * 0.79;
    let O2 = ((airflowrate * 0.21) / (1 + (excessair / 100))) * (excessair / 100);
    let H2O = (((methane / 100) * 2) + ((ethane / 100) * 3) + ((propane / 100) * 4) + ((butane / 100) * 5) + ((pentane / 100) * 6) + ((hexane / 100) * 7) + ((heptane / 100) * 8) + ((octane / 100) * 9) + ((hydrogensulfide / 100) * 2)) * fuelflowrate;
    let flowrategases = H2O + O2 + N2 + so2 + voc + n2o + ch4 + nox + co2;
    let ghg = co2 + (ch4 * 28) + (n2o * 298)

    // After the completion of the calculations

    try {
        await db.none('INSERT INTO incineratorr(projecttitle, pressure, temperature, date, volumeflow, hhv, carbondioxide, methane,ethane, propane, butane, pentane,hexane, heptane, octane, hydrogensulfide, nitrogen,lhv,airflowrate,fuelflowrate, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases,totaloxygen, ghg) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32)', [projecttitle, pressure, temperature, date, volumeflow, hhv, carbondioxide, methane, ethane, propane, butane, pentane, hexane, heptane, octane, hydrogensulfide, nitrogen, lhv, airflowrate, fuelflowrate, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, totaloxygen, ghg]);
        console.log("Data saved successfully.");

        res.json({
            airflowrate, fuelflowrate, flowrategases, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, ghg
        });
    } catch (error) {
        console.error("Error saving data:", error.message);
    }

});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////PART6//////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////


app.get('/H301', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/H-301.html'));
});

app.post('/H301', async (req, res, next) => {

    const {
        volumeflow, HHV, carbondioxide, methane, tin, v,
        ethane, propane, butane, pentane,
        hexane, heptane, octane, hydrogensulfide, Temperature, Pressure, ExcessAir, RelativeHumidity, Nitrogen, LHV, tair, tstack, loss, projecttitle, date,
        isCustomComposition, vsst, tsst

    } = req.body;


    // Calculs
    let ch4 = (HHV * volumeflow * 9.696078431E-10) * 1000 / 16.05;
    let n2o = (HHV * volumeflow * 0.0000000000948) * 1000 / 44.02;
    let nox = (HHV * volumeflow * 4.196078431E-08) * 1000 / 30.01;
    let mwvoc = ((ethane / 100) * 30.07) + ((propane / 100) * 44.1) + ((butane / 100) * 58.12) + ((pentane / 100) * 72.5) + ((hexane / 100) * 86.18) + ((heptane / 100) * 100.21) + ((octane / 100) * 114.23);

    let voc = ((HHV * volumeflow * 2.318627451E-09) * 1000) / mwvoc;
    let co2 = (((carbondioxide / 100) * 1 + (methane / 100) * 1 + (ethane / 100) * 2 + (propane / 100) * 3 + (butane / 100) * 4 + (pentane / 100) * 5 + (hexane / 100) * 6 + (heptane / 100) * 7 + (octane / 100) * 8) * 44.01 * volumeflow * 1 / 1000000 * 42.22) * 1000 / 44.01;
    let so2 = ((hydrogensulfide) * volumeflow * 1.44114915367 * (64.06 / 34.08) / 100000) * 1000 / 64.06;
    let MolecularWeightfuel = ((carbondioxide / 100) * 44.01) + ((Nitrogen / 100) * 28.02) + ((methane / 100) * 16.05) + ((ethane / 100) * 30.07) + ((propane / 100) * 44.1) + ((butane / 100) * 58.12) + ((pentane / 100) * 72.5) + ((hexane / 100) * 86.18) + ((heptane / 100) * 100.21) + ((octane / 100) * 114.23) + ((hydrogensulfide / 100) * 34.08);



    function PR_mixture_density(Tc, Pc, omega, y, T, P, M) {
        const R = 8.314;
        const n = Tc.length;

        let a_values = Array(n).fill(0);
        let b_values = Array(n).fill(0);

        // PR EOS Parameters for each component
        for (let i = 0; i < n; i++) {
            const kappa = 0.37464 + 1.54226 * omega[i] - 0.26992 * omega[i] ** 2;
            const alpha = (1 + kappa * (1 - Math.sqrt(T / Tc[i]))) ** 2;
            a_values[i] = 0.45724 * R ** 2 * Tc[i] ** 2 / Pc[i] * alpha;
            b_values[i] = 0.07780 * R * Tc[i] / Pc[i];
        }

        // Calculate mixture a and b
        let a_mix = 0;
        const b_mix = y.reduce((acc, curr, idx) => acc + curr * b_values[idx], 0);

        for (let i = 0; i < n; i++) {
            for (let j = 0; j < n; j++) {
                const a_ij = Math.sqrt(a_values[i] * a_values[j]);  // Assuming k_ij = 0
                a_mix += y[i] * y[j] * a_ij;
            }
        }

        const A = Number(P);
        const B = Number(-R * T - P * b_mix);
        const C = Number(a_mix - P * b_mix ** 2 - R * T * b_mix);
        const D = Number(-a_mix * b_mix);

        function cubicRoots(coefficients) {
            let [A, B, C, D] = coefficients;

            let p = (3 * A * C - B ** 2) / (3 * A ** 2);
            let q = (2 * B ** 3 - 9 * A * B * C + 27 * A ** 2 * D) / (27 * A ** 3);

            let discriminant = 4 * p ** 3 + 27 * q ** 2;

            console.log("p:", p, "q:", q, "Discriminant:", discriminant);  // Debug print

            let roots = [];

            if (discriminant < 0) {
                let r = Math.sqrt((-p) ** 3 / 27);
                let theta = Math.acos(-q / (2 * r)) / 3;
                let x1 = 2 * Math.cbrt(r) * Math.cos(theta);
                let x2 = 2 * Math.cbrt(r) * Math.cos(theta + (2 * Math.PI / 3));
                let x3 = 2 * Math.cbrt(r) * Math.cos(theta - (2 * Math.PI / 3));

                roots = [x1, x2, x3];
            } else if (discriminant > 0) {
                let u = Math.cbrt(-q / 2 + Math.sqrt(discriminant / 27));
                let v = Math.cbrt(-q / 2 - Math.sqrt(discriminant / 27));

                roots = [u + v];

            } else {

                let u = Math.cbrt(-q / 2);
                let x1 = 2 * u;
                let x2 = -u;
                roots = [x1, x2, x2];
            }

            return roots.map(root => root - B / (3 * A));
        }


        const roots = cubicRoots([A, B, C, D]);
        console.log("Roots:", roots);

        const V = Math.max(...roots);
        const M_mixture = y.reduce((acc, curr, idx) => acc + curr * M[idx], 0);

        console.log("M_mixture:", M_mixture);
        console.log("V:", V);
        return M_mixture / V;
    }

    const Tc = [30.95, -146.95, 100.45, -82.45, 32.28, 96.75, 151.975, 196.6, 234.75, 267.01, 295.45].map(val => val + 273.15);
    const Pc = [7370, 3394.37, 9007.79, 4640.68, 4883.85, 4256.66, 3796, 3367.5, 3031.62, 2736.78, 2496.62].map(val => val * 1e3);
    const omega = [0.23894, 0.03999, 0.081, 0.0114984, 0.0986, 0.1524, 0.201, 0.251, 0.3007, 0.34979, 0.4018];
    const y = [
        carbondioxide / 100,
        Nitrogen / 100,
        hydrogensulfide / 100,
        methane / 100,
        ethane / 100,
        propane / 100,
        butane / 100,
        pentane / 100,
        hexane / 100,
        heptane / 100,
        octane / 100,


    ];
    const M = [44.01, 28.01, 34.08, 16.04, 30.07, 44.10, 58.12, 58.12, 72.15, 72.15, 86.18, 100.21, 114.22].map(val => val / 1000);

    let Tv = Temperature + 273.15;
    let P = Pressure * 1e5;

    console.log("Tv:", Tv, "P:", P);
    let density = PR_mixture_density(Tc, Pc, omega, y, Tv, P, M);
    console.log("density:", density);




    let fuelflowrateKmol = (volumeflow * density) / MolecularWeightfuel;
    let totaloxygen = (((methane / 100) * 2) + ((ethane / 100) * 3.5) + ((propane / 100) * 5) + ((butane / 100) * 6.5) + ((pentane / 100) * 8) + ((hexane / 100) * 9.5) + ((heptane / 100) * 11) + ((octane / 100) * 12.5) + ((hydrogensulfide / 100) * 1.5)) * fuelflowrateKmol;
    let AirflowrateKmol = (totaloxygen / 0.21) * (1 + (ExcessAir / 100));
    let N2 = AirflowrateKmol * 0.79;
    let O2 = ((AirflowrateKmol * 0.21) / (1 + (ExcessAir / 100))) * (ExcessAir / 100);
    let H2O = (((methane / 100) * 2) + ((ethane / 100) * 3) + ((propane / 100) * 4) + ((butane / 100) * 5) + ((pentane / 100) * 6) + ((hexane / 100) * 7) + ((heptane / 100) * 8) + ((octane / 100) * 9) + ((hydrogensulfide / 100) * 2)) * fuelflowrateKmol;
    let flowrategases = H2O + O2 + N2 + so2 + voc + n2o + ch4 + nox + co2;
    let yh2o = H2O / flowrategases;
    let yn2o = n2o / flowrategases;
    let ynox = nox / flowrategases;
    let yvoc = voc / flowrategases;
    let ych4 = ch4 / flowrategases;
    let yso2 = so2 / flowrategases;
    let yco2 = co2 / flowrategases;
    let yo2 = O2 / flowrategases;
    let yN2 = N2 / flowrategases;
    let ncv = MolecularWeightfuel * (LHV / density) * 1000;






    function calculateCp(component, T) {
        switch (component) {
            case "hydrogensulfide":
                return 26.88412 + 18.7 * (T / 1000) + 3.43 * Math.pow(T / 1000, 2) - 3.38 * Math.pow(T / 1000, 3) + 0.135882 / Math.pow(T / 1000, 2);
            case "N2":
                return 28.9 - 0.001571 * T + 0.000008081 * Math.pow(T, 2) - 0.000000002873 * Math.pow(T, 3);
            case "O2":
                return 25.48 + 0.0152 * T - 0.00000716 * Math.pow(T, 2) + 0.00000000131 * Math.pow(T, 3);
            case "Air":
                return 28.11 + 0.00197 * T + 0.0000048 * Math.pow(T, 2) - 0.00000000197 * Math.pow(T, 3);
            case "co2":
                return 22.26 + 0.05981 * T - 0.0000351 * Math.pow(T, 2) + 0.00000000747 * Math.pow(T, 3);
            case "H2O":
                return 32.24 + 0.00192 * T + 0.0000106 * Math.pow(T, 2) - 0.0000000036 * Math.pow(T, 3);
            case "nox":
                return 29.34 - 0.00094 * T + 0.00000975 * Math.pow(T, 2) - 0.00000000419 * Math.pow(T, 3);
            case "n2o":
                return 24.11 + 0.0586 * T - 0.0000356 * Math.pow(T, 2) + 0.0000000106 * Math.pow(T, 3);
            case "so2":
                return 25.78 + 0.058 * T - 0.0000381 * Math.pow(T, 2) + 0.00000000861 * Math.pow(T, 3);
            case "methane":
                return 19.89 + 0.0502 * T + 0.0000127 * Math.pow(T, 2) - 0.000000011 * Math.pow(T, 3);
            case "ethane":
                return 6.9 + 0.173 * T - 0.0000641 * Math.pow(T, 2) + 0.00000000729 * Math.pow(T, 3);
            case "propane":
                return -4.04 + 0.305 * T - 0.000157 * Math.pow(T, 2) + 0.0000000317 * Math.pow(T, 3);
            case "butane":
                return -7.913 + 0.416 * T - 0.00023 * Math.pow(T, 2) + 0.0000000499 * Math.pow(T, 3);
            case "pentane":
                return 6.774 + 0.454 * T - 0.000225 * Math.pow(T, 2) + 0.0000000423 * Math.pow(T, 3);
            case "hexane":
                return 6.93 + 0.552 * T - 0.000287 * Math.pow(T, 2) + 0.0000000577 * Math.pow(T, 3);
            default:
                return 0;  // Return 0 for any unhandled components
        }

    }

    let cpch4 = calculateCp("methane", Temperature + 273.15);
    let cpco2 = calculateCp("co2", Temperature + 273.15);
    let cpN2 = calculateCp("N2", Temperature + 273.15);
    let cpc2 = calculateCp("ethane", Temperature + 273.15);
    let cpc3 = calculateCp("propane", Temperature + 273.15);
    let cpc4 = calculateCp("butane", Temperature + 273.15);
    let cpc5 = calculateCp("pentane", Temperature + 273.15);
    let cpc6 = calculateCp("hexane", Temperature + 273.15);
    let cph2s = calculateCp("hydrogensulfide", Temperature + 273.15);

    let cpmix = (cpch4 * (methane / 100)) + (cpc2 * (ethane / 100)) + (cpc3 * (propane / 100)) + (cpc4 * (butane / 100)) + (cpc5 * (pentane / 100)) + (cpc6 * ((heptane + hexane + octane) / 100)) + (cpco2 * (carbondioxide / 100)) + (cpN2 * (Nitrogen / 100)) + (cph2s * (hydrogensulfide / 100));
    let Xh = 0.019;
    let minTemp = Math.min(tair, Temperature);
    let Td = minTemp - 5;
    let Qv = ncv * fuelflowrateKmol;
    let Qs = fuelflowrateKmol * cpmix * (Temperature - Td);
    let qf = Qv + Qs;
    let Tavrair = (tair + 273.15 + Td + 273.15) / 2;
    let cpair = 28.11 + 0.00197 * Tavrair + 0.0000048 * Math.pow(Tavrair, 2) - 0.00000000197 * Math.pow(Tavrair, 3);
    let Cphum = 34.42 + 6.281e-4 * Tavrair + 5.6106e-6 * Math.pow(Tavrair, 2);
    let ha = (((1 - Xh) * cpair) + (Xh * Cphum)) * (tair - Td);
    let Qair = AirflowrateKmol * ha;
    let T = ((339 + 273.15) + (30 + 273.15)) / 2;
    let cpO2 = 25.48 + 0.0152 * T - 0.00000716 * Math.pow(T, 2) + 0.00000000131 * Math.pow(T, 3);
    let cpNitro = 28.9 - 0.001571 * T + 0.000008081 * Math.pow(T, 2) - 0.000000002873 * Math.pow(T, 3);
    let cpCarb = 22.26 + 0.05981 * T - 0.0000351 * Math.pow(T, 2) + 0.00000000747 * Math.pow(T, 3);
    let cpNO = 29.34 - 0.00094 * T + 0.00000975 * Math.pow(T, 2) - 0.00000000419 * Math.pow(T, 3);
    let cpSo2 = 25.78 + 0.058 * T - 0.0000381 * Math.pow(T, 2) + 0.00000000861 * Math.pow(T, 3);
    let cpH2O = 32.24 + 0.00192 * T + 0.0000106 * Math.pow(T, 2) - 0.0000000036 * Math.pow(T, 3);
    let QO2 = yo2 * flowrategases * cpO2 * (tstack - Td);
    let QN2 = yN2 * flowrategases * cpNitro * (tstack - Td);
    let QCO2 = yco2 * flowrategases * cpCarb * (tstack - Td);
    let QNO = ynox * flowrategases * cpNO * (tstack - Td);
    let QSO2 = yso2 * flowrategases * cpSo2 * (tstack - Td);
    let QH2O = yh2o * flowrategases * cpH2O * (tstack - Td);
    let Qstack = QCO2 + QO2 + QN2 + QH2O + QSO2 + QNO;
    let Qst;
    let qadd;
    if (isCustomComposition) {
        //qadd = (vsst) * 36.897 * 28.9 * (tsst - tstack) * 0.7;
        //Qst = vsst * 36.897 * 28.9 * (tstack - Td)*0.9;
        qadd = 0;
        Qst = 0;
    } else {
        qadd = 0;
        Qst = 0;
    }
    let Qin = qf + Qair + qadd;
    let Ql = (loss / 100) * Qin;
    let Qout = Qstack + Ql + Qst;
    let Qu = Qin - Qout;
    let E = 100 * (Qu / Qin);

    let cpAMINE = 4.5;
    let densityAMINE = 1220;

    let tout = tin + (Qu / (cpAMINE * densityAMINE * v));


    // After the completion of the calculations

    try {
        await db.none('INSERT INTO h301(projecttitle, date, tin, v, volumeflow, density, HHV, carbondioxide, methane,ethane, propane, butane, pentane,hexane, heptane, octane, hydrogensulfide,Temperature,Pressure,ExcessAir,RelativeHumidity,Nitrogen,LHV,tair,tstack,loss,AirflowrateKmol,fuelflowrateKmol, MolecularWeightfuel, cpmix, ncv, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, ynox, yco2, yh2o, yN2, yso2,  yo2, Qv, Qs, Qair, Qstack, Ql, Qout, Qu, E, mwvoc, totaloxygen, ha, qf, ych4, yn2o, yvoc, tout) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50, $51, $52, $53, $54, $55, $56, $57, $58, $59, $60, $61, $62, $63)', [projecttitle, date, tin, v, volumeflow, density, HHV, carbondioxide, methane, ethane, propane, butane, pentane, hexane, heptane, octane, hydrogensulfide, Temperature, Pressure, ExcessAir, RelativeHumidity, Nitrogen, LHV, tair, tstack, loss, AirflowrateKmol, fuelflowrateKmol, MolecularWeightfuel, cpmix, ncv, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, ynox, yco2, yh2o, yN2, yso2, yo2, Qv, Qs, Qair, Qstack, Ql, Qout, Qu, E, mwvoc, totaloxygen, ha, qf, ych4, yn2o, yvoc, tout]);
        console.log("Data saved successfully.");

        res.json({
            AirflowrateKmol, fuelflowrateKmol, MolecularWeightfuel, cpmix, ncv, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, Qv, Qs, Qair, Qstack, Ql, Qout, Qu, E, ynox, yco2, yh2o, yN2, yso2, yo2, mwvoc, totaloxygen, ha, qf, ych4, yn2o, yvoc, tout
        });
    } catch (error) {
        console.error("Error saving data:", error.message);
    }

});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////PART7//////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////


app.get('/H501', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/H-501.html'));
});

app.post('/H501', async (req, res, next) => {

    const {
        volumeflow, HHV, carbondioxide, methane, tin, v,
        ethane, propane, butane, pentane,
        hexane, heptane, octane, hydrogensulfide, Temperature, Pressure, ExcessAir, RelativeHumidity, Nitrogen, LHV, tair, tstack, loss, projecttitle, date

    } = req.body;


    // Calculs
    let ch4 = (HHV * volumeflow * 9.696078431E-10) * 1000 / 16.05;
    let n2o = (HHV * volumeflow * 0.0000000000948) * 1000 / 44.02;
    let nox = (HHV * volumeflow * 4.196078431E-08) * 1000 / 30.01;
    let mwvoc = ((ethane / 100) * 30.07) + ((propane / 100) * 44.1) + ((butane / 100) * 58.12) + ((pentane / 100) * 72.5) + ((hexane / 100) * 86.18) + ((heptane / 100) * 100.21) + ((octane / 100) * 114.23);

    let voc = ((HHV * volumeflow * 2.318627451E-09) * 1000) / mwvoc;
    let co2 = (((carbondioxide / 100) * 1 + (methane / 100) * 1 + (ethane / 100) * 2 + (propane / 100) * 3 + (butane / 100) * 4 + (pentane / 100) * 5 + (hexane / 100) * 6 + (heptane / 100) * 7 + (octane / 100) * 8) * 44.01 * volumeflow * 1 / 1000000 * 42.22) * 1000 / 44.01;
    let so2 = ((hydrogensulfide) * volumeflow * 1.44114915367 * (64.06 / 34.08) / 100000) * 1000 / 64.06;
    let MolecularWeightfuel = ((carbondioxide / 100) * 44.01) + ((Nitrogen / 100) * 28.02) + ((methane / 100) * 16.05) + ((ethane / 100) * 30.07) + ((propane / 100) * 44.1) + ((butane / 100) * 58.12) + ((pentane / 100) * 72.5) + ((hexane / 100) * 86.18) + ((heptane / 100) * 100.21) + ((octane / 100) * 114.23) + ((hydrogensulfide / 100) * 34.08);



    function PR_mixture_density(Tc, Pc, omega, y, T, P, M) {
        const R = 8.314;
        const n = Tc.length;

        let a_values = Array(n).fill(0);
        let b_values = Array(n).fill(0);

        // PR EOS Parameters for each component
        for (let i = 0; i < n; i++) {
            const kappa = 0.37464 + 1.54226 * omega[i] - 0.26992 * omega[i] ** 2;
            const alpha = (1 + kappa * (1 - Math.sqrt(T / Tc[i]))) ** 2;
            a_values[i] = 0.45724 * R ** 2 * Tc[i] ** 2 / Pc[i] * alpha;
            b_values[i] = 0.07780 * R * Tc[i] / Pc[i];
        }

        // Calculate mixture a and b
        let a_mix = 0;
        const b_mix = y.reduce((acc, curr, idx) => acc + curr * b_values[idx], 0);

        for (let i = 0; i < n; i++) {
            for (let j = 0; j < n; j++) {
                const a_ij = Math.sqrt(a_values[i] * a_values[j]);  // Assuming k_ij = 0
                a_mix += y[i] * y[j] * a_ij;
            }
        }

        const A = Number(P);
        const B = Number(-R * T - P * b_mix);
        const C = Number(a_mix - P * b_mix ** 2 - R * T * b_mix);
        const D = Number(-a_mix * b_mix);

        function cubicRoots(coefficients) {
            let [A, B, C, D] = coefficients;

            let p = (3 * A * C - B ** 2) / (3 * A ** 2);
            let q = (2 * B ** 3 - 9 * A * B * C + 27 * A ** 2 * D) / (27 * A ** 3);

            let discriminant = 4 * p ** 3 + 27 * q ** 2;

            console.log("p:", p, "q:", q, "Discriminant:", discriminant);  // Debug print

            let roots = [];

            if (discriminant < 0) {
                let r = Math.sqrt((-p) ** 3 / 27);
                let theta = Math.acos(-q / (2 * r)) / 3;
                let x1 = 2 * Math.cbrt(r) * Math.cos(theta);
                let x2 = 2 * Math.cbrt(r) * Math.cos(theta + (2 * Math.PI / 3));
                let x3 = 2 * Math.cbrt(r) * Math.cos(theta - (2 * Math.PI / 3));

                roots = [x1, x2, x3];
            } else if (discriminant > 0) {
                let u = Math.cbrt(-q / 2 + Math.sqrt(discriminant / 27));
                let v = Math.cbrt(-q / 2 - Math.sqrt(discriminant / 27));

                roots = [u + v];

            } else {

                let u = Math.cbrt(-q / 2);
                let x1 = 2 * u;
                let x2 = -u;
                roots = [x1, x2, x2];
            }

            return roots.map(root => root - B / (3 * A));
        }


        const roots = cubicRoots([A, B, C, D]);
        console.log("Roots:", roots);

        const V = Math.max(...roots);
        const M_mixture = y.reduce((acc, curr, idx) => acc + curr * M[idx], 0);

        console.log("M_mixture:", M_mixture);
        console.log("V:", V);
        return M_mixture / V;
    }

    const Tc = [30.95, -146.95, 100.45, -82.45, 32.28, 96.75, 151.975, 196.6, 234.75, 267.01, 295.45].map(val => val + 273.15);
    const Pc = [7370, 3394.37, 9007.79, 4640.68, 4883.85, 4256.66, 3796, 3367.5, 3031.62, 2736.78, 2496.62].map(val => val * 1e3);
    const omega = [0.23894, 0.03999, 0.081, 0.0114984, 0.0986, 0.1524, 0.201, 0.251, 0.3007, 0.34979, 0.4018];
    const y = [
        carbondioxide / 100,
        Nitrogen / 100,
        hydrogensulfide / 100,
        methane / 100,
        ethane / 100,
        propane / 100,
        butane / 100,
        pentane / 100,
        hexane / 100,
        heptane / 100,
        octane / 100,


    ];
    const M = [44.01, 28.01, 34.08, 16.04, 30.07, 44.10, 58.12, 58.12, 72.15, 72.15, 86.18, 100.21, 114.22].map(val => val / 1000);

    let Tv = Temperature + 273.15;
    let P = Pressure * 1e5;

    console.log("Tv:", Tv, "P:", P);
    let density = PR_mixture_density(Tc, Pc, omega, y, Tv, P, M);
    console.log("density:", density);




    let fuelflowrateKmol = (volumeflow * density) / MolecularWeightfuel;
    let totaloxygen = (((methane / 100) * 2) + ((ethane / 100) * 3.5) + ((propane / 100) * 5) + ((butane / 100) * 6.5) + ((pentane / 100) * 8) + ((hexane / 100) * 9.5) + ((heptane / 100) * 11) + ((octane / 100) * 12.5) + ((hydrogensulfide / 100) * 1.5)) * fuelflowrateKmol;
    let AirflowrateKmol = (totaloxygen / 0.21) * (1 + (ExcessAir / 100));
    let N2 = AirflowrateKmol * 0.79;
    let O2 = ((AirflowrateKmol * 0.21) / (1 + (ExcessAir / 100))) * (ExcessAir / 100);
    let H2O = (((methane / 100) * 2) + ((ethane / 100) * 3) + ((propane / 100) * 4) + ((butane / 100) * 5) + ((pentane / 100) * 6) + ((hexane / 100) * 7) + ((heptane / 100) * 8) + ((octane / 100) * 9) + ((hydrogensulfide / 100) * 2)) * fuelflowrateKmol;
    let flowrategases = H2O + O2 + N2 + so2 + voc + n2o + ch4 + nox + co2;
    let yh2o = H2O / flowrategases;
    let yn2o = n2o / flowrategases;
    let ynox = nox / flowrategases;
    let yvoc = voc / flowrategases;
    let ych4 = ch4 / flowrategases;
    let yso2 = so2 / flowrategases;
    let yco2 = co2 / flowrategases;
    let yo2 = O2 / flowrategases;
    let yN2 = N2 / flowrategases;
    let ncv = MolecularWeightfuel * (LHV / density) * 1000;






    function calculateCp(component, T) {
        switch (component) {
            case "hydrogensulfide":
                return 26.88412 + 18.7 * (T / 1000) + 3.43 * Math.pow(T / 1000, 2) - 3.38 * Math.pow(T / 1000, 3) + 0.135882 / Math.pow(T / 1000, 2);
            case "N2":
                return 28.9 - 0.001571 * T + 0.000008081 * Math.pow(T, 2) - 0.000000002873 * Math.pow(T, 3);
            case "O2":
                return 25.48 + 0.0152 * T - 0.00000716 * Math.pow(T, 2) + 0.00000000131 * Math.pow(T, 3);
            case "Air":
                return 28.11 + 0.00197 * T + 0.0000048 * Math.pow(T, 2) - 0.00000000197 * Math.pow(T, 3);
            case "co2":
                return 22.26 + 0.05981 * T - 0.0000351 * Math.pow(T, 2) + 0.00000000747 * Math.pow(T, 3);
            case "H2O":
                return 32.24 + 0.00192 * T + 0.0000106 * Math.pow(T, 2) - 0.0000000036 * Math.pow(T, 3);
            case "nox":
                return 29.34 - 0.00094 * T + 0.00000975 * Math.pow(T, 2) - 0.00000000419 * Math.pow(T, 3);
            case "n2o":
                return 24.11 + 0.0586 * T - 0.0000356 * Math.pow(T, 2) + 0.0000000106 * Math.pow(T, 3);
            case "so2":
                return 25.78 + 0.058 * T - 0.0000381 * Math.pow(T, 2) + 0.00000000861 * Math.pow(T, 3);
            case "methane":
                return 19.89 + 0.0502 * T + 0.0000127 * Math.pow(T, 2) - 0.000000011 * Math.pow(T, 3);
            case "ethane":
                return 6.9 + 0.173 * T - 0.0000641 * Math.pow(T, 2) + 0.00000000729 * Math.pow(T, 3);
            case "propane":
                return -4.04 + 0.305 * T - 0.000157 * Math.pow(T, 2) + 0.0000000317 * Math.pow(T, 3);
            case "butane":
                return -7.913 + 0.416 * T - 0.00023 * Math.pow(T, 2) + 0.0000000499 * Math.pow(T, 3);
            case "pentane":
                return 6.774 + 0.454 * T - 0.000225 * Math.pow(T, 2) + 0.0000000423 * Math.pow(T, 3);
            case "hexane":
                return 6.93 + 0.552 * T - 0.000287 * Math.pow(T, 2) + 0.0000000577 * Math.pow(T, 3);
            default:
                return 0;  // Return 0 for any unhandled components
        }

    }

    let cpch4 = calculateCp("methane", Temperature + 273.15);
    let cpco2 = calculateCp("co2", Temperature + 273.15);
    let cpN2 = calculateCp("N2", Temperature + 273.15);
    let cpc2 = calculateCp("ethane", Temperature + 273.15);
    let cpc3 = calculateCp("propane", Temperature + 273.15);
    let cpc4 = calculateCp("butane", Temperature + 273.15);
    let cpc5 = calculateCp("pentane", Temperature + 273.15);
    let cpc6 = calculateCp("hexane", Temperature + 273.15);
    let cph2s = calculateCp("hydrogensulfide", Temperature + 273.15);

    let cpmix = (cpch4 * (methane / 100)) + (cpc2 * (ethane / 100)) + (cpc3 * (propane / 100)) + (cpc4 * (butane / 100)) + (cpc5 * (pentane / 100)) + (cpc6 * ((heptane + hexane + octane) / 100)) + (cpco2 * (carbondioxide / 100)) + (cpN2 * (Nitrogen / 100)) + (cph2s * (hydrogensulfide / 100));
    let Xh = 0.019;
    let minTemp = Math.min(tair, Temperature);
    let Td = minTemp - 5;
    let Qv = ncv * fuelflowrateKmol;
    let Qs = fuelflowrateKmol * cpmix * (Temperature - Td);
    let qf = Qv + Qs;
    let Tavrair = (tair + 273.15 + Td + 273.15) / 2;
    let cpair = 28.11 + 0.00197 * Tavrair + 0.0000048 * Math.pow(Tavrair, 2) - 0.00000000197 * Math.pow(Tavrair, 3);
    let Cphum = 34.42 + 6.281e-4 * Tavrair + 5.6106e-6 * Math.pow(Tavrair, 2);
    let ha = (((1 - Xh) * cpair) + (Xh * Cphum)) * (tair - Td);
    let Qair = AirflowrateKmol * ha;
    let T = ((339 + 273.15) + (30 + 273.15)) / 2;
    let cpO2 = 25.48 + 0.0152 * T - 0.00000716 * Math.pow(T, 2) + 0.00000000131 * Math.pow(T, 3);
    let cpNitro = 28.9 - 0.001571 * T + 0.000008081 * Math.pow(T, 2) - 0.000000002873 * Math.pow(T, 3);
    let cpCarb = 22.26 + 0.05981 * T - 0.0000351 * Math.pow(T, 2) + 0.00000000747 * Math.pow(T, 3);
    let cpNO = 29.34 - 0.00094 * T + 0.00000975 * Math.pow(T, 2) - 0.00000000419 * Math.pow(T, 3);
    let cpSo2 = 25.78 + 0.058 * T - 0.0000381 * Math.pow(T, 2) + 0.00000000861 * Math.pow(T, 3);
    let cpH2O = 32.24 + 0.00192 * T + 0.0000106 * Math.pow(T, 2) - 0.0000000036 * Math.pow(T, 3);
    let QO2 = yo2 * flowrategases * cpO2 * (tstack - Td);
    let QN2 = yN2 * flowrategases * cpNitro * (tstack - Td);
    let QCO2 = yco2 * flowrategases * cpCarb * (tstack - Td);
    let QNO = ynox * flowrategases * cpNO * (tstack - Td);
    let QSO2 = yso2 * flowrategases * cpSo2 * (tstack - Td);
    let QH2O = yh2o * flowrategases * cpH2O * (tstack - Td);
    let Qstack = QCO2 + QO2 + QN2 + QH2O + QSO2 + QNO;

    let Qin = qf + Qair;
    let Ql = (loss / 100) * Qin;
    let Qout = Qstack + Ql;
    let Qu = Qin - Qout;
    let E = 100 * (Qu / Qin);

    let cpGlycol = 2.8;
    let densityGLYCOL = 1125;

    let tout = tin + (Qu / (cpGlycol * densityGLYCOL * v));


    // After the completion of the calculations

    try {
        await db.none('INSERT INTO h501(projecttitle, date, tin, v, volumeflow, density, HHV, carbondioxide, methane,ethane, propane, butane, pentane,hexane, heptane, octane, hydrogensulfide,Temperature,Pressure,ExcessAir,RelativeHumidity,Nitrogen,LHV,tair,tstack,loss,AirflowrateKmol,fuelflowrateKmol, MolecularWeightfuel, cpmix, ncv, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, ynox, yco2, yh2o, yN2, yso2,  yo2, Qv, Qs, Qair, Qstack, Ql, Qout, Qu, E, mwvoc, totaloxygen, ha, qf, ych4, yn2o, yvoc, tout) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50, $51, $52, $53, $54, $55, $56, $57, $58, $59, $60, $61, $62, $63)', [projecttitle, date, tin, v, volumeflow, density, HHV, carbondioxide, methane, ethane, propane, butane, pentane, hexane, heptane, octane, hydrogensulfide, Temperature, Pressure, ExcessAir, RelativeHumidity, Nitrogen, LHV, tair, tstack, loss, AirflowrateKmol, fuelflowrateKmol, MolecularWeightfuel, cpmix, ncv, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, ynox, yco2, yh2o, yN2, yso2, yo2, Qv, Qs, Qair, Qstack, Ql, Qout, Qu, E, mwvoc, totaloxygen, ha, qf, ych4, yn2o, yvoc, tout]);
        console.log("Data saved successfully.");

        res.json({
            AirflowrateKmol, fuelflowrateKmol, MolecularWeightfuel, cpmix, ncv, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, Qv, Qs, Qair, Qstack, Ql, Qout, Qu, E, ynox, yco2, yh2o, yN2, yso2, yo2, mwvoc, totaloxygen, ha, qf, ych4, yn2o, yvoc, tout
        });
    } catch (error) {
        console.error("Error saving data:", error.message);
    }

});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////PART8//////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////


app.get('/H602', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/H-602.html'));
});

app.post('/H602', async (req, res, next) => {

    const {
        volumeflow, HHV, carbondioxide, methane, tin, v,
        ethane, propane, butane, pentane,
        hexane, heptane, octane, hydrogensulfide, Temperature, Pressure, ExcessAir, RelativeHumidity, Nitrogen, LHV, tair, tstack, loss, projecttitle, date

    } = req.body;


    // Calculs
    let ch4 = (HHV * volumeflow * 9.696078431E-10) * 1000 / 16.05;
    let n2o = (HHV * volumeflow * 0.0000000000948) * 1000 / 44.02;
    let nox = (HHV * volumeflow * 4.196078431E-08) * 1000 / 30.01;
    let mwvoc = ((ethane / 100) * 30.07) + ((propane / 100) * 44.1) + ((butane / 100) * 58.12) + ((pentane / 100) * 72.5) + ((hexane / 100) * 86.18) + ((heptane / 100) * 100.21) + ((octane / 100) * 114.23);

    let voc = ((HHV * volumeflow * 2.318627451E-09) * 1000) / mwvoc;
    let co2 = (((carbondioxide / 100) * 1 + (methane / 100) * 1 + (ethane / 100) * 2 + (propane / 100) * 3 + (butane / 100) * 4 + (pentane / 100) * 5 + (hexane / 100) * 6 + (heptane / 100) * 7 + (octane / 100) * 8) * 44.01 * volumeflow * 1 / 1000000 * 42.22) * 1000 / 44.01;
    let so2 = ((hydrogensulfide) * volumeflow * 1.44114915367 * (64.06 / 34.08) / 100000) * 1000 / 64.06;
    let MolecularWeightfuel = ((carbondioxide / 100) * 44.01) + ((Nitrogen / 100) * 28.02) + ((methane / 100) * 16.05) + ((ethane / 100) * 30.07) + ((propane / 100) * 44.1) + ((butane / 100) * 58.12) + ((pentane / 100) * 72.5) + ((hexane / 100) * 86.18) + ((heptane / 100) * 100.21) + ((octane / 100) * 114.23) + ((hydrogensulfide / 100) * 34.08);



    function PR_mixture_density(Tc, Pc, omega, y, T, P, M) {
        const R = 8.314;
        const n = Tc.length;

        let a_values = Array(n).fill(0);
        let b_values = Array(n).fill(0);

        // PR EOS Parameters for each component
        for (let i = 0; i < n; i++) {
            const kappa = 0.37464 + 1.54226 * omega[i] - 0.26992 * omega[i] ** 2;
            const alpha = (1 + kappa * (1 - Math.sqrt(T / Tc[i]))) ** 2;
            a_values[i] = 0.45724 * R ** 2 * Tc[i] ** 2 / Pc[i] * alpha;
            b_values[i] = 0.07780 * R * Tc[i] / Pc[i];
        }

        // Calculate mixture a and b
        let a_mix = 0;
        const b_mix = y.reduce((acc, curr, idx) => acc + curr * b_values[idx], 0);

        for (let i = 0; i < n; i++) {
            for (let j = 0; j < n; j++) {
                const a_ij = Math.sqrt(a_values[i] * a_values[j]);  // Assuming k_ij = 0
                a_mix += y[i] * y[j] * a_ij;
            }
        }

        const A = Number(P);
        const B = Number(-R * T - P * b_mix);
        const C = Number(a_mix - P * b_mix ** 2 - R * T * b_mix);
        const D = Number(-a_mix * b_mix);

        function cubicRoots(coefficients) {
            let [A, B, C, D] = coefficients;

            let p = (3 * A * C - B ** 2) / (3 * A ** 2);
            let q = (2 * B ** 3 - 9 * A * B * C + 27 * A ** 2 * D) / (27 * A ** 3);

            let discriminant = 4 * p ** 3 + 27 * q ** 2;

            console.log("p:", p, "q:", q, "Discriminant:", discriminant);  // Debug print

            let roots = [];

            if (discriminant < 0) {
                let r = Math.sqrt((-p) ** 3 / 27);
                let theta = Math.acos(-q / (2 * r)) / 3;
                let x1 = 2 * Math.cbrt(r) * Math.cos(theta);
                let x2 = 2 * Math.cbrt(r) * Math.cos(theta + (2 * Math.PI / 3));
                let x3 = 2 * Math.cbrt(r) * Math.cos(theta - (2 * Math.PI / 3));

                roots = [x1, x2, x3];
            } else if (discriminant > 0) {
                let u = Math.cbrt(-q / 2 + Math.sqrt(discriminant / 27));
                let v = Math.cbrt(-q / 2 - Math.sqrt(discriminant / 27));

                roots = [u + v];

            } else {

                let u = Math.cbrt(-q / 2);
                let x1 = 2 * u;
                let x2 = -u;
                roots = [x1, x2, x2];
            }

            return roots.map(root => root - B / (3 * A));
        }


        const roots = cubicRoots([A, B, C, D]);
        console.log("Roots:", roots);

        const V = Math.max(...roots);
        const M_mixture = y.reduce((acc, curr, idx) => acc + curr * M[idx], 0);

        console.log("M_mixture:", M_mixture);
        console.log("V:", V);
        return M_mixture / V;
    }

    const Tc = [30.95, -146.95, 100.45, -82.45, 32.28, 96.75, 151.975, 196.6, 234.75, 267.01, 295.45].map(val => val + 273.15);
    const Pc = [7370, 3394.37, 9007.79, 4640.68, 4883.85, 4256.66, 3796, 3367.5, 3031.62, 2736.78, 2496.62].map(val => val * 1e3);
    const omega = [0.23894, 0.03999, 0.081, 0.0114984, 0.0986, 0.1524, 0.201, 0.251, 0.3007, 0.34979, 0.4018];
    const y = [
        carbondioxide / 100,
        Nitrogen / 100,
        hydrogensulfide / 100,
        methane / 100,
        ethane / 100,
        propane / 100,
        butane / 100,
        pentane / 100,
        hexane / 100,
        heptane / 100,
        octane / 100,


    ];
    const M = [44.01, 28.01, 34.08, 16.04, 30.07, 44.10, 58.12, 58.12, 72.15, 72.15, 86.18, 100.21, 114.22].map(val => val / 1000);

    let Tv = Temperature + 273.15;
    let P = Pressure * 1e5;

    console.log("Tv:", Tv, "P:", P);
    let density = PR_mixture_density(Tc, Pc, omega, y, Tv, P, M);
    console.log("density:", density);




    let fuelflowrateKmol = (volumeflow * density) / MolecularWeightfuel;
    let totaloxygen = (((methane / 100) * 2) + ((ethane / 100) * 3.5) + ((propane / 100) * 5) + ((butane / 100) * 6.5) + ((pentane / 100) * 8) + ((hexane / 100) * 9.5) + ((heptane / 100) * 11) + ((octane / 100) * 12.5) + ((hydrogensulfide / 100) * 1.5)) * fuelflowrateKmol;
    let AirflowrateKmol = (totaloxygen / 0.21) * (1 + (ExcessAir / 100));
    let N2 = AirflowrateKmol * 0.79;
    let O2 = ((AirflowrateKmol * 0.21) / (1 + (ExcessAir / 100))) * (ExcessAir / 100);
    let H2O = (((methane / 100) * 2) + ((ethane / 100) * 3) + ((propane / 100) * 4) + ((butane / 100) * 5) + ((pentane / 100) * 6) + ((hexane / 100) * 7) + ((heptane / 100) * 8) + ((octane / 100) * 9) + ((hydrogensulfide / 100) * 2)) * fuelflowrateKmol;
    let flowrategases = H2O + O2 + N2 + so2 + voc + n2o + ch4 + nox + co2;
    let yh2o = H2O / flowrategases;
    let yn2o = n2o / flowrategases;
    let ynox = nox / flowrategases;
    let yvoc = voc / flowrategases;
    let ych4 = ch4 / flowrategases;
    let yso2 = so2 / flowrategases;
    let yco2 = co2 / flowrategases;
    let yo2 = O2 / flowrategases;
    let yN2 = N2 / flowrategases;
    let ncv = MolecularWeightfuel * (LHV / density) * 1000;






    function calculateCp(component, T) {
        switch (component) {
            case "hydrogensulfide":
                return 26.88412 + 18.7 * (T / 1000) + 3.43 * Math.pow(T / 1000, 2) - 3.38 * Math.pow(T / 1000, 3) + 0.135882 / Math.pow(T / 1000, 2);
            case "N2":
                return 28.9 - 0.001571 * T + 0.000008081 * Math.pow(T, 2) - 0.000000002873 * Math.pow(T, 3);
            case "O2":
                return 25.48 + 0.0152 * T - 0.00000716 * Math.pow(T, 2) + 0.00000000131 * Math.pow(T, 3);
            case "Air":
                return 28.11 + 0.00197 * T + 0.0000048 * Math.pow(T, 2) - 0.00000000197 * Math.pow(T, 3);
            case "co2":
                return 22.26 + 0.05981 * T - 0.0000351 * Math.pow(T, 2) + 0.00000000747 * Math.pow(T, 3);
            case "H2O":
                return 32.24 + 0.00192 * T + 0.0000106 * Math.pow(T, 2) - 0.0000000036 * Math.pow(T, 3);
            case "nox":
                return 29.34 - 0.00094 * T + 0.00000975 * Math.pow(T, 2) - 0.00000000419 * Math.pow(T, 3);
            case "n2o":
                return 24.11 + 0.0586 * T - 0.0000356 * Math.pow(T, 2) + 0.0000000106 * Math.pow(T, 3);
            case "so2":
                return 25.78 + 0.058 * T - 0.0000381 * Math.pow(T, 2) + 0.00000000861 * Math.pow(T, 3);
            case "methane":
                return 19.89 + 0.0502 * T + 0.0000127 * Math.pow(T, 2) - 0.000000011 * Math.pow(T, 3);
            case "ethane":
                return 6.9 + 0.173 * T - 0.0000641 * Math.pow(T, 2) + 0.00000000729 * Math.pow(T, 3);
            case "propane":
                return -4.04 + 0.305 * T - 0.000157 * Math.pow(T, 2) + 0.0000000317 * Math.pow(T, 3);
            case "butane":
                return -7.913 + 0.416 * T - 0.00023 * Math.pow(T, 2) + 0.0000000499 * Math.pow(T, 3);
            case "pentane":
                return 6.774 + 0.454 * T - 0.000225 * Math.pow(T, 2) + 0.0000000423 * Math.pow(T, 3);
            case "hexane":
                return 6.93 + 0.552 * T - 0.000287 * Math.pow(T, 2) + 0.0000000577 * Math.pow(T, 3);
            default:
                return 0;  // Return 0 for any unhandled components
        }

    }

    let cpch4 = calculateCp("methane", Temperature + 273.15);
    let cpco2 = calculateCp("co2", Temperature + 273.15);
    let cpN2 = calculateCp("N2", Temperature + 273.15);
    let cpc2 = calculateCp("ethane", Temperature + 273.15);
    let cpc3 = calculateCp("propane", Temperature + 273.15);
    let cpc4 = calculateCp("butane", Temperature + 273.15);
    let cpc5 = calculateCp("pentane", Temperature + 273.15);
    let cpc6 = calculateCp("hexane", Temperature + 273.15);
    let cph2s = calculateCp("hydrogensulfide", Temperature + 273.15);

    let cpmix = (cpch4 * (methane / 100)) + (cpc2 * (ethane / 100)) + (cpc3 * (propane / 100)) + (cpc4 * (butane / 100)) + (cpc5 * (pentane / 100)) + (cpc6 * ((heptane + hexane + octane) / 100)) + (cpco2 * (carbondioxide / 100)) + (cpN2 * (Nitrogen / 100)) + (cph2s * (hydrogensulfide / 100));
    let Xh = 0.019;
    let minTemp = Math.min(tair, Temperature);
    let Td = minTemp - 5;
    let Qv = ncv * fuelflowrateKmol;
    let Qs = fuelflowrateKmol * cpmix * (Temperature - Td);
    let qf = Qv + Qs;
    let Tavrair = (tair + 273.15 + Td + 273.15) / 2;
    let cpair = 28.11 + 0.00197 * Tavrair + 0.0000048 * Math.pow(Tavrair, 2) - 0.00000000197 * Math.pow(Tavrair, 3);
    let Cphum = 34.42 + 6.281e-4 * Tavrair + 5.6106e-6 * Math.pow(Tavrair, 2);
    let ha = (((1 - Xh) * cpair) + (Xh * Cphum)) * (tair - Td);
    let Qair = AirflowrateKmol * ha;
    let T = ((339 + 273.15) + (30 + 273.15)) / 2;
    let cpO2 = 25.48 + 0.0152 * T - 0.00000716 * Math.pow(T, 2) + 0.00000000131 * Math.pow(T, 3);
    let cpNitro = 28.9 - 0.001571 * T + 0.000008081 * Math.pow(T, 2) - 0.000000002873 * Math.pow(T, 3);
    let cpCarb = 22.26 + 0.05981 * T - 0.0000351 * Math.pow(T, 2) + 0.00000000747 * Math.pow(T, 3);
    let cpNO = 29.34 - 0.00094 * T + 0.00000975 * Math.pow(T, 2) - 0.00000000419 * Math.pow(T, 3);
    let cpSo2 = 25.78 + 0.058 * T - 0.0000381 * Math.pow(T, 2) + 0.00000000861 * Math.pow(T, 3);
    let cpH2O = 32.24 + 0.00192 * T + 0.0000106 * Math.pow(T, 2) - 0.0000000036 * Math.pow(T, 3);
    let QO2 = yo2 * flowrategases * cpO2 * (tstack - Td);
    let QN2 = yN2 * flowrategases * cpNitro * (tstack - Td);
    let QCO2 = yco2 * flowrategases * cpCarb * (tstack - Td);
    let QNO = ynox * flowrategases * cpNO * (tstack - Td);
    let QSO2 = yso2 * flowrategases * cpSo2 * (tstack - Td);
    let QH2O = yh2o * flowrategases * cpH2O * (tstack - Td);
    let Qstack = QCO2 + QO2 + QN2 + QH2O + QSO2 + QNO;

    let Qin = qf + Qair;
    let Ql = (loss / 100) * Qin;
    let Qout = Qstack + Ql;
    let Qu = Qin - Qout;
    let E = 100 * (Qu / Qin);

    let cpGlycol = 2.25;
    let densityGLYCOL = 0.0003636;

    let tout = tin + (Qu / (cpGlycol * densityGLYCOL * v));


    // After the completion of the calculations

    try {
        await db.none('INSERT INTO h602(projecttitle, date, tin, v, volumeflow, density, HHV, carbondioxide, methane,ethane, propane, butane, pentane,hexane, heptane, octane, hydrogensulfide,Temperature,Pressure,ExcessAir,RelativeHumidity,Nitrogen,LHV,tair,tstack,loss,AirflowrateKmol,fuelflowrateKmol, MolecularWeightfuel, cpmix, ncv, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, ynox, yco2, yh2o, yN2, yso2,  yo2, Qv, Qs, Qair, Qstack, Ql, Qout, Qu, E, mwvoc, totaloxygen, ha, qf, ych4, yn2o, yvoc, tout) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50, $51, $52, $53, $54, $55, $56, $57, $58, $59, $60, $61, $62, $63)', [projecttitle, date, tin, v, volumeflow, density, HHV, carbondioxide, methane, ethane, propane, butane, pentane, hexane, heptane, octane, hydrogensulfide, Temperature, Pressure, ExcessAir, RelativeHumidity, Nitrogen, LHV, tair, tstack, loss, AirflowrateKmol, fuelflowrateKmol, MolecularWeightfuel, cpmix, ncv, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, ynox, yco2, yh2o, yN2, yso2, yo2, Qv, Qs, Qair, Qstack, Ql, Qout, Qu, E, mwvoc, totaloxygen, ha, qf, ych4, yn2o, yvoc, tout]);
        console.log("Data saved successfully.");

        res.json({
            AirflowrateKmol, fuelflowrateKmol, MolecularWeightfuel, cpmix, ncv, co2, so2, ch4, nox, n2o, voc, N2, O2, H2O, flowrategases, Qv, Qs, Qair, Qstack, Ql, Qout, Qu, E, ynox, yco2, yh2o, yN2, yso2, yo2, mwvoc, totaloxygen, ha, qf, ych4, yn2o, yvoc, tout
        });
    } catch (error) {
        console.error("Error saving data:", error.message);
    }

});

app.use((err, req, res, next) => {
    if (err.name === 'UnauthorizedError') {
        console.error("JWT error:", err);
        res.status(401).send('Invalid or no token provided.');
    } else {
        console.error("General error:", err);
        next(err);
    }
});

app.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
});
