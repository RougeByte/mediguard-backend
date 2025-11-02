// --- IMPORTS ---
const express = require('express');
const axios = require('axios');
// Load environment variables from .env file
require('dotenv').config(); 
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');

// --- 1. CONFIGURATION (UPDATED TO USE process.env) ---

// MUST BE UPDATED - Reads from MONGODB_URI in .env
const MONGODB_URI = process.env.MONGODB_URI; 
// Reads from JWT_SECRET in .env
const JWT_SECRET = process.env.JWT_SECRET;

// Path to your downloaded Firebase Service Account JSON file - Reads from .env
const FIREBASE_SERVICE_ACCOUNT_PATH = process.env.FIREBASE_SERVICE_ACCOUNT_PATH; 

// FIX: Points to your AI service - Reads from AI_MODEL_ENDPOINT in .env
const AI_MODEL_ENDPOINT = process.env.AI_MODEL_ENDPOINT; 

const PORT = process.env.PORT || 3000;
const app = express();

// --- 2. MIDDLEWARE (FIX FOR MISSING FIELDS) ---
app.use(express.json());
app.use(require('cors')()); 


// --- 3. FIREBASE ADMIN SETUP (FIXED: Checks for required path variable) ---
let isFirebaseInitialized = false;
try {
    // FIREBASE_SERVICE_ACCOUNT_PATH must be set in the .env file for local runs
    if (!FIREBASE_SERVICE_ACCOUNT_PATH) {
        throw new Error("FIREBASE_SERVICE_ACCOUNT_PATH is not defined in .env");
    }
    const serviceAccount = require(FIREBASE_SERVICE_ACCOUNT_PATH);
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    isFirebaseInitialized = true;
    console.log('Firebase Admin SDK initialized successfully.');
} catch (error) {
    console.error(`ERROR: Could not initialize Firebase Admin SDK. 
    Check if '${FIREBASE_SERVICE_ACCOUNT_PATH || 'path variable'}' exists and is valid. 
    Notifications will be disabled. Error: ${error.message}`);
}

// Function to send FCM notification
const sendFCMNotification = async (fcmToken, title, body) => {
    if (!isFirebaseInitialized) return; 

    const message = {
        notification: { title, body },
        token: fcmToken,
    };

    try {
        // Using send() instead of sendMulticast for a single token, as per best practice
        await admin.messaging().send(message); 
        console.log('FCM message sent successfully to token:', fcmToken);
    } catch (error) {
        console.error('Error sending FCM message:', error.message);
    }
};

// --- 4. MONGODB CONNECTION ---
mongoose.connect(MONGODB_URI)
    .then(() => console.log('MongoDB connected successfully.'))
    .catch(err => console.error('MongoDB connection error:', err));


// --- 5. MONGOOSE SCHEMAS AND MODELS ---

const interactionSchema = new mongoose.Schema({
    severity: { type: String, enum: ['low', 'medium', 'high'], default: 'low' },
    sideEffects: [String],
    recommendations: [String],
    // ADDED: List of specific drugs that interacted
    interactingMedicines: [String], 
}, { _id: false });

// NEW SCHEMA: For logging manual DDI checks
const manualInteractionHistorySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    drugA: { type: String, required: true },
    drugB: { type: String, required: true },
    checkedAt: { type: Date, default: Date.now },
    result: interactionSchema // Stores the full DDI result object
});

const medicineSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    dosage: { type: String, required: true },
    frequency: { type: String, required: true },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    status: { type: String, enum: ['ongoing', 'completed'], default: 'ongoing' },
    interactionResult: interactionSchema
});

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true }, // Used for login (e.g., email)
    name: { type: String, required: true }, // Required for display
    password: { type: String, required: true },
    role: { type: String, enum: ['patient', 'doctor', 'caretaker'], required: true },
    assignedDoctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, 
    // NEW: Field to link a Patient to their Caretaker
    assignedCaretakerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, 
    fcmToken: { type: String, default: null } 
});

const User = mongoose.model('User', userSchema);
const Medicine = mongoose.model('Medicine', medicineSchema);
const ManualInteractionHistory = mongoose.model('ManualInteractionHistory', manualInteractionHistorySchema);


// --- 6. UTILITY FUNCTIONS ---

// Middleware to protect routes with JWT
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ message: 'Authorization token required' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Bearer token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user; 
        next();
    });
};

// Function to call the external AI model
const runInteractionCheck = async (drugA, drugB) => {
    // Defensive check for empty strings before sending to Flask
    if (!drugA || !drugB) {
        console.error('AI Interaction Check Skipped: One or both drug names are empty.');
        return {
            severity: 'low',
            sideEffects: ['Input error: Drug name missing.'],
            recommendations: ['Ensure two valid drug names are provided.'],
            interactingMedicines: [drugA, drugB]
        };
    }

    try {
        const payload = {
            drugA: drugA, 
            drugB: drugB,
        };
        
        // --- REAL AXIOS CALL TO PYTHON SERVICE ---
        console.log(`Calling AI service: ${AI_MODEL_ENDPOINT} with ${drugA} vs ${drugB}`);
        const response = await axios.post(AI_MODEL_ENDPOINT, payload);
        const result = response.data;
        // --- END REAL AXIOS CALL ---

        return result;
    } catch (error) {
        // Log the error message from the Flask response (if available)
        const flaskErrorMessage = error.response && error.response.data && error.response.data.message
            ? error.response.data.message
            : error.message;

        console.error('AI Interaction Check Failed (using fallback):', flaskErrorMessage);
        
        // Return a safe, low-severity default if the AI endpoint is down or returns a 400/500
        return {
            severity: 'low',
            sideEffects: [`AI service failed: ${flaskErrorMessage}.`],
            recommendations: ['Consult a physician.', 'Please restart the AI service.'],
            interactingMedicines: [drugA, drugB]
        };
    }
};

// REMOVED: scheduleReminder function

// --- 7. AUTHENTICATION ROUTES (Routes remain the same) ---

app.post('/api/auth/signup', async (req, res) => {
    try {
        const { username, password, role, name, assignedDoctorId } = req.body;

        if (!username || !password || !role || !name) {
            return res.status(400).json({ message: 'Missing required fields: username, password, role, and name.' });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ message: 'User already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const isDoctor = role.toLowerCase() === 'doctor';
        const isCaretaker = role.toLowerCase() === 'caretaker';
        
        // 1. Start building the user object with common fields
        const userData = {
            username, 
            name,
            password: hashedPassword, 
            role: role.toLowerCase(),
            assignedCaretakerId: null, // Always null on signup initially
        };

        // 2. Handle assignedDoctorId based on role
        if (isDoctor) {
            userData.assignedDoctorId = null; 
        } else {
            // Patient and Caretaker are treated the same for doctor assignment for now
            userData.assignedDoctorId = assignedDoctorId || null;
        }
        
        const newUser = new User(userData);
        await newUser.save();

        const token = jwt.sign(
            { userId: newUser._id, username: newUser.username, role: newUser.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: 'User created successfully.',
            token,
            userId: newUser._id,
            username: newUser.username,
            role: newUser.role,
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error during signup.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }
        
        // NEW FIX: Caretaker login check
        if (user.role === 'caretaker') {
            const assignedPatients = await User.find({ assignedCaretakerId: user._id });
            // A caretaker must be assigned to AT LEAST ONE patient to log in
            if (assignedPatients.length === 0) {
                 return res.status(403).json({ message: 'Caretaker access denied. Must be assigned by a patient first.' });
            }
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        const token = jwt.sign(
            { userId: user._id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(200).json({
            message: 'Login successful.',
            token,
            userId: user._id,
            username: user.username,
            role: user.role,
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.post('/api/auth/fcm-token', authMiddleware, async (req, res) => {
    try {
        const { userId, fcmToken } = req.body;
        
        if (!fcmToken) {
            return res.status(400).json({ message: 'FCM token is required.' });
        }

        await User.findByIdAndUpdate(userId, { fcmToken });
        
        res.status(200).json({ message: 'FCM token updated.' });
    } catch (error) {
        console.error('FCM token update error:', error);
        res.status(500).json({ message: 'Server error during FCM token update.' });
    }
});


// --- 8. PATIENT/CARETAKER MANAGEMENT ROUTES (/api/patient) ---

app.post('/api/patient/add-caretaker', authMiddleware, async (req, res) => {
    try {
        const patientId = req.user.userId;
        const patientRole = req.user.role;
        const { caretakerEmail } = req.body;

        if (patientRole !== 'patient') {
            return res.status(403).json({ message: 'Access denied. Only patients can assign caretakers.' });
        }

        const caretaker = await User.findOne({ username: caretakerEmail, role: 'caretaker' });

        if (!caretaker) {
            return res.status(404).json({ message: 'Caretaker not found with that email or incorrect role.' });
        }
        
        await User.findByIdAndUpdate(patientId, { assignedCaretakerId: caretaker._id });
        
        res.status(200).json({ message: `Caretaker (${caretaker.name}) successfully linked.` });
        
    } catch (error) {
        console.error('Add caretaker error:', error);
        res.status(500).json({ message: 'Server error during caretaker assignment.' });
    }
});


// --- 9. MEDICINE AND INTERACTION ROUTES (/api/medicines, /api/interaction) ---

app.post('/api/medicines/add', authMiddleware, async (req, res) => {
    try {
        const { name, dosage, frequency, startDate, endDate, userId } = req.body;
        
        if (!name || !dosage || !frequency || !startDate || !endDate) {
            return res.status(400).json({ message: 'Missing required medicine fields.' });
        }

        // 1. Find all currently ongoing medicines for comparison
        const currentMedicines = await Medicine.find({ 
            userId: userId, 
            endDate: { $gte: new Date() } // Medicine is ongoing if end date is future or today
        });
        
        // Initialize the result to a safe, low-severity default
        let highestInteractionResult = { 
            severity: 'low', 
            sideEffects: ['No other ongoing medications found to check against.'], 
            recommendations: ['Continue as prescribed.'], 
            interactingMedicines: [] 
        };
        
        // 2. CRITICAL FIX: Iterate over ALL existing drugs and check for interactions
        if (currentMedicines.length > 0) {
            // Use Promise.all to check all interactions concurrently for performance
            const checkPromises = currentMedicines.map(existingMedicine => 
                runInteractionCheck(name, existingMedicine.name)
            );
            
            const allCheckResults = await Promise.all(checkPromises);
            
            // Find the most severe result
            const highRiskResult = allCheckResults.find(r => r.severity === 'high');
            
            if (highRiskResult) {
                // If high risk is found, set the final result to the high risk result
                highestInteractionResult = highRiskResult;
            } else {
                // If no high risk, just confirm low risk
                highestInteractionResult = { 
                    severity: 'low', 
                    sideEffects: ['No severe interaction detected against ongoing medicines.'], 
                    recommendations: ['Continue as prescribed.'], 
                    interactingMedicines: [] 
                };
            }
        } 
        // If currentMedicines.length === 0, it uses the initialized default 'low' result

        const interactionResult = highestInteractionResult;

        const newMedicine = new Medicine({
            userId: userId,
            name,
            dosage,
            frequency,
            startDate: new Date(startDate),
            endDate: new Date(endDate),
            status: new Date(endDate) >= new Date() ? 'ongoing' : 'completed',
            interactionResult: interactionResult,
        });
        await newMedicine.save();
        
        // 4. If high risk, trigger DDI Alert Notification (existing logic)
        if (interactionResult.severity === 'high') {
            const user = await User.findById(userId);
            if (user && user.fcmToken) {
                // Send DDI alert to patient
                await sendFCMNotification(
                    user.fcmToken,
                    'HIGH INTERACTION ALERT',
                    `Risk detected between existing medications and new drug: ${name}`
                );
            }
            
            // Also send DDI alert to caretaker if assigned
            if (user && user.assignedCaretakerId) {
                const caretaker = await User.findById(user.assignedCaretakerId);
                if (caretaker && caretaker.fcmToken) {
                     await sendFCMNotification(
                         caretaker.fcmToken,
                         'URGENT: Patient DDI Alert',
                         `${user.name} has a HIGH interaction risk with new drug: ${name}`
                    );
                }
            }
        }

        res.status(201).json({ 
            message: 'Medicine added and DDI checked.', 
            medicine: newMedicine 
        });

    } catch (error) {
        console.error('Add medicine error:', error);
        res.status(500).json({ message: 'Server error during medicine addition.' });
    }
});

app.post('/api/interaction/manual', authMiddleware, async (req, res) => {
    try {
        const { userId } = req.user; // Get user ID from JWT
        const { drugA, drugB } = req.body;
        
        if (!drugA || !drugB) {
            return res.status(400).json({ message: 'Both drug names (drugA and drugB) are required.' });
        }

        const interactionResult = await runInteractionCheck(drugA, drugB);
        
        // NEW: Log the manual interaction check to history
        const newHistoryRecord = new ManualInteractionHistory({
            userId: userId,
            drugA: drugA,
            drugB: drugB,
            result: interactionResult
        });
        await newHistoryRecord.save();

        res.status(200).json(interactionResult);

    } catch (error) {
        console.error('Manual interaction check error:', error);
        res.status(500).json({ message: 'Server error during manual DDI check.' });
    }
});

// NEW ROUTE: Get Interaction History for a user
app.get('/api/interaction/history/:userId', authMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        
        // Authorization check: User can only see their own history
        if (req.user.userId !== userId) {
            return res.status(403).json({ message: 'Access denied.' });
        }
        
        const history = await ManualInteractionHistory.find({ userId: userId }).sort({ checkedAt: -1 });

        res.status(200).json({ history: history });
    } catch (error) {
        console.error('Fetch interaction history error:', error);
        res.status(500).json({ message: 'Server error fetching interaction history.' });
    }
});

// NEW ROUTE: DELETE Interaction History Item
app.delete('/api/interaction/history/:itemId', authMiddleware, async (req, res) => {
    try {
        const { itemId } = req.params;
        const userId = req.user.userId;

        // Find and delete the item, ensuring it belongs to the logged-in user
        const result = await ManualInteractionHistory.deleteOne({ _id: itemId, userId: userId });

        if (result.deletedCount === 0) {
            return res.status(404).json({ message: 'History item not found or not owned by user.' });
        }

        res.status(200).json({ message: 'History item deleted successfully.' });
    } catch (error) {
        console.error('Delete interaction history error:', error);
        res.status(500).json({ message: 'Server error during history deletion.' });
    }
});


// GET /api/medicines/ongoing/:userId - Protected by authMiddleware
app.get('/api/medicines/ongoing/:userId', authMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        
        if (req.user.role === 'patient' && req.user.userId !== userId) {
            return res.status(403).json({ message: 'Access denied.' });
        }
        
        const ongoingMedicines = await Medicine.find({ 
            userId: userId, 
            endDate: { $gte: new Date() } 
        }).sort({ startDate: -1 });

        res.status(200).json({ medicines: ongoingMedicines });

    } catch (error) {
        console.error('Fetch ongoing error:', error);
        res.status(500).json({ message: 'Server error fetching ongoing medicines.' });
    }
});

// GET /api/patients/:doctorId - Fetch list of assigned patients
app.get('/api/patients/:staffId', authMiddleware, async (req, res) => {
    try {
        const { staffId } = req.params;
        const staffRoles = ['doctor', 'caretaker'];

        if (!staffRoles.includes(req.user.role) || req.user.userId !== staffId) {
            return res.status(403).json({ message: 'Access denied. You can only view your assigned list.' });
        }
        
        let patientQuery = { role: 'patient' };

        if (req.user.role === 'doctor') {
            // Doctors see assigned patients AND unassigned patients to claim
            patientQuery = {
                role: 'patient',
                $or: [
                    { assignedDoctorId: staffId },
                    { assignedDoctorId: null }
                ]
            };
        } else if (req.user.role === 'caretaker') {
            // FIX: Caretakers ONLY see patients who assigned THEM (via assignedCaretakerId)
            patientQuery = {
                role: 'patient',
                assignedCaretakerId: staffId // Patients whose assignedCaretakerId matches the staffId
            };
        }
        
        const patientList = await User.find(patientQuery, 'id username role name assignedDoctorId assignedCaretakerId');

        res.status(200).json({ patients: patientList });

    } catch (error) {
        console.error('Fetch patients error:', error);
        res.status(500).json({ message: 'Server error fetching assigned patients.' });
    }
});

// POST /api/patients/assign - Allows Doctor/Caretaker to claim a patient
app.post('/api/patients/assign', authMiddleware, async (req, res) => {
    try {
        const { patientId } = req.body;
        const staffId = req.user.userId; 
        const staffRole = req.user.role;
        const staffRoles = ['doctor', 'caretaker'];

        if (!staffRoles.includes(staffRole)) {
            return res.status(403).json({ message: 'Access denied. Only staff can perform assignments.' });
        }

        const patient = await User.findById(patientId);

        if (!patient) {
            return res.status(404).json({ message: 'Patient not found.' });
        }
        
        if (patient.assignedDoctorId && patient.assignedDoctorId.toString() !== staffId) {
             return res.status(409).json({ message: 'Conflict: Patient is already assigned to another staff member.' });
        }
        
        // This route is primarily for Doctor assignment. Caretaker assignment uses /patient/add-caretaker.
        if (staffRole === 'doctor') {
            await User.findByIdAndUpdate(patientId, { assignedDoctorId: staffId });
        } else if (staffRole === 'caretaker') {
            // Caretakers cannot 'claim' an unassigned patient via this route; assignment is done by patient email.
            return res.status(403).json({ message: 'Caretakers cannot assign via this endpoint. Patient must link via email.' });
        }

        res.status(200).json({ message: `Patient ${patientId} successfully assigned to ${staffRole} ${staffId}.` });

    } catch (error) {
        console.error('Assignment error:', error);
        res.status(500).json({ message: 'Server error during patient assignment.' });
    }
});


app.get('/api/patient/:userId', authMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;

        const isStaff = ['doctor', 'caretaker'].includes(req.user.role);
        
        if (isStaff) {
             const patient = await User.findById(userId);
             // Staff member must be assigned to the patient either as Doctor or Caretaker
             const isAssignedDoctor = patient?.assignedDoctorId?.toString() === req.user.userId;
             const isAssignedCaretaker = patient?.assignedCaretakerId?.toString() === req.user.userId;

             if (!isAssignedDoctor && !isAssignedCaretaker) {
                 return res.status(403).json({ message: 'Access denied. Patient is not assigned to you.' });
             }
        } else if (req.user.userId !== userId) {
             return res.status(403).json({ message: 'Access denied.' });
        }

        const medicineRecords = await Medicine.find({ userId: userId }).sort({ startDate: -1 });

        res.status(200).json({ medicines: medicineRecords });

    } catch (error) {
        console.error('Fetch patient record error:', error);
        res.status(500).json({ message: 'Server error fetching patient record.' });
    }
});

// --- 11. SERVER STARTUP ---
app.listen(PORT, () => {
    console.log(`MediGuard Backend Server running on port ${PORT}...`);
});
