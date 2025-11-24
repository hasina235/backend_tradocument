import express from "express";
import cors from "cors";
import multer from "multer";
import fs from "fs";
import { PDFDocument } from "pdf-lib";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import path from "path";
import axios from 'axios'

//configuration supabase
import {createClient} from '@supabase/supabase-js'

dotenv.config();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServicekey = process.env.SUPABASE_SERVICE_KEY;

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({ origin: "*" }));
app.use(express.json());

// Directories
const uploadsDir = path.join(process.cwd(), "uploads");

//initialisation du supabase
const supabaseAdmin = createClient(supabaseUrl, supabaseServicekey);


// Multer storage
 const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage });

// --- Gestion codes persistants ---
const codesFile = path.join(process.cwd(), "codes.json");

function loadCodes() {
  if (fs.existsSync(codesFile)) {
    try {
      return JSON.parse(fs.readFileSync(codesFile, "utf-8"));
    } catch (err) {
      console.error("Erreur lecture codes.json :", err);
      return {};
    }
  }
  return {};
}

// Servir les fichiers uploads (avec authentification)
app.use('/uploads', async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader ? authHeader.split(' ')[1] : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Non autorisé: Jeton manquant."
    });
  }

  try {
    const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(token);

    if (userError || !userData?.user) {
      return res.status(401).json({
        success: false,
        message: "Jeton non valide."
      });
    }

    // Vérifier que l'utilisateur est un partenaire ou admin
    const userRole = userData.user.app_metadata.user_role;
    if (userRole !== 'partner' && userRole !== 'admin') {
      return res.status(403).json({
        success: false,
        message: "Accès refusé."
      });
    }

    next();
  } catch (err) {
    console.error("❌ Erreur authentification:", err);
    res.status(500).json({
      success: false,
      message: "Erreur serveur."
    });
  }
}, express.static('uploads'));

function saveCodes(codes) {
  try {
    fs.writeFileSync(codesFile, JSON.stringify(codes));
  } catch (err) {
    console.error("Erreur écriture codes.json :", err);
  }
}

//generation mot de passe
const generateRandomPassword = () => {
  // Mot de passe aléatoire de 16 caractères (caractères, chiffres, majuscules)
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
  let password = "";
  for (let i = 0; i < 16; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
};


//configuration transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: true,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

// --- Routes ---
app.get("/", (req, res) => {
  res.send("Backend Node.js fonctionne 🚀");
});

// Upload PDF + calcul prix
app.post("/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Aucun fichier reçu" });

    const fileBuffer = fs.readFileSync(req.file.path);
    const pdfDoc = await PDFDocument.load(fileBuffer);
    const pageCount = pdfDoc.getPageCount();
    const totalPrice = pageCount * 10; // 10€/page

    res.json({ pages: pageCount, price: totalPrice });
  } catch (err) {
    console.error("Erreur traitement PDF :", err);
    res.status(500).json({ error: "Erreur lors du traitement du PDF", details: err.message });
  }
});

//configuration pour uploader les fichiers
// Configuration de multer pour l'upload
/* const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, 'uploads', 'translated');
    // Créer le dossier s'il n'existe pas
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'translated_' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // Limite de 10MB
  fileFilter: function (req, file, cb) {
    // Accepter seulement certains types de fichiers
    const allowedTypes = /pdf|doc|docx|jpg|jpeg|png/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Type de fichier non autorisé. Formats acceptés: PDF, DOC, DOCX, JPG, PNG'));
    }
  }
}); */

app.post('/partner/documents/:documentId/upload-translation', upload.single('file'), async (req, res) => {
  const { documentId } = req.params;

  // 1. Vérification du JWT
  const authHeader = req.headers.authorization;
  const token = authHeader ? authHeader.split(' ')[1] : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Non autorisé: Jeton manquant."
    });
  }

  try {
    // 2. Validation du JWT
    const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(token);

    if (userError || !userData?.user) {
      return res.status(401).json({
        success: false,
        message: "Jeton non valide ou expiré."
      });
    }

    const userId = userData.user.id;

    // 3. Vérifier qu'un fichier a été uploadé
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "Aucun fichier uploadé."
      });
    }

    // 4. Vérifier que le document appartient au partenaire
    const { data: document, error: fetchError } = await supabaseAdmin
      .from('documents')
      .select('*')
      .eq('id', documentId)
      .single();

    if (fetchError || !document) {
      // Supprimer le fichier uploadé si le document n'existe pas
      fs.unlinkSync(req.file.path);
      return res.status(404).json({
        success: false,
        message: "Document non trouvé."
      });
    }

    if (document.partner_id !== userId) {
      // Supprimer le fichier uploadé
      fs.unlinkSync(req.file.path);
      return res.status(403).json({
        success: false,
        message: "Vous n'êtes pas autorisé à modifier ce document."
      });
    }

    // 5. Mettre à jour la base de données avec le chemin du fichier traduit
    const translatedFileName = req.file.filename;

    const { data: updatedDoc, error: updateError } = await supabaseAdmin
      .from('documents')
      .update({
        translated_document_url: translatedFileName,
        updated_at: new Date().toISOString()
      })
      .eq('id', documentId)
      .select()
      .single();

    if (updateError) {
      console.error("❌ Erreur mise à jour:", updateError.message);
      return res.status(500).json({
        success: false,
        message: "Erreur lors de la mise à jour du document."
      });
    }

    res.json({
      success: true,
      message: "Document traduit uploadé avec succès.",
      data: {
        document: updatedDoc,
        file: {
          filename: req.file.filename,
          originalname: req.file.originalname,
          size: req.file.size
        }
      }
    });

  } catch (err) {
    console.error("❌ Erreur serveur:", err);

    // Supprimer le fichier en cas d'erreur
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    res.status(500).json({
      success: false,
      message: "Erreur serveur inattendue.",
      error: err.message
    });
  }
});

// Livraison → calcul pages, distance, prix
app.post("/livraison", upload.single("file"), async (req, res) => {
  try {
    const { region, ville } = req.body;

    if (!req.file) return res.status(400).json({ error: "Aucun fichier reçu" });

    const fileBuffer = fs.readFileSync(req.file.path);
    const pdfDoc = await PDFDocument.load(fileBuffer);
    const pages = pdfDoc.getPageCount();
    const docPrice = pages * 10;

    const distance = region && ville ? 50 + 10 : 0;
    const deliveryPrice = distance * 0.5;

    res.json({
      pages,
      price: docPrice,
      distance,
      totalPrice: docPrice + deliveryPrice
    });
  } catch (err) {
    console.error("Erreur livraison :", err);
    res.status(500).json({ error: "Erreur lors de la livraison", details: err.message });
  }
});

// Codes de vérification
function createTransporter() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: true,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

app.post("/send-code", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email requis" });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 10 * 60 * 1000; // 10 minutes

  const codes = loadCodes();
  codes[email] = { code, expires };
  saveCodes(codes); // ✅ on sauvegarde

  try {
    const transporter = createTransporter();
    await transporter.sendMail({
      from: `"Tradocument" <${process.env.SMTP_USER}>`,
      to: email,
      subject: "Votre code de vérification",
      text: `Votre code est : ${code} (valide 10 minutes)`,
      html: `<p>Bonjour,</p><p>Votre code de vérification est : <b>${code}</b></p><p>Ce code expire dans 10 minutes.</p>`
    });
    res.json({ message: "Code envoyé par email ✅", expires });
  } catch (err) {
    console.error("Erreur envoi mail:", err);
    res.status(500).json({ error: "Impossible d’envoyer l’email" });
  }
});



app.post("/verify-code", (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ success: false, error: "Email et code requis" });

  const codes = loadCodes();
  const record = codes[email];
  if (!record) return res.json({ success: false, error: "Aucun code trouvé" });
  if (Date.now() > record.expires) {
    delete codes[email];
    saveCodes(codes);
    return res.json({ success: false, error: "Code expiré" });
  }
  if (record.code !== code) return res.json({ success: false, error: "Code incorrect" });

  delete codes[email];
  saveCodes(codes);
  res.json({ success: true });
});



app.get("/procuration", (req, res) => {
  res.json({ message: "Page procuration prête" });
});


//Envoi procuration par mail
const upload_procuration = multer({ dest: "uploads/" });

app.post("/procuration", upload_procuration.any(), async (req, res) => {
  try {
    console.log("REQ BODY:", req.body);
    console.log("REQ FILES:", req.files);

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT),
      secure: true, // true pour port 465
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    let mailOptions = {
      from: `"Nouvelle Procuration" <${process.env.SMTP_USER}>`,
      to: process.env.SMTP_USER, // Par défaut envoyer à toi-même
      subject: "Nouvelle Procuration reçue",
      text: `
Nouvelle procuration remplie par un client :

Nom : ${req.body.nom}
Prénom : ${req.body.prenom}
Date de naissance : ${req.body.date_naissance}
Lieu de naissance : ${req.body.lieu_naissance}
Nationalité : ${req.body.nationalite}
Adresse : ${req.body.adresse}
Institution : ${req.body.institution}
Date limite de validité : ${req.body.validite}
Lieu de signature : ${req.body.lieu_signature}
Date de signature : ${req.body.date_signature}
Document concerné: ${req.body.document}
Numéro d'identité ou de passeport: ${req.body.id_numero}
Email: ${req.body.email}
      `,
      attachments: req.files.map((f) => ({
        filename: f.originalname,
        path: f.path,
      })),
    };

    await transporter.sendMail(mailOptions);

    res.json({ success: true, message: "Procuration envoyée avec succès" });
  } catch (err) {
    console.error("Erreur envoi procuration :", err); // ← log l'erreur réelle
    res.status(500).json({ success: false, message: "Erreur lors de l'envoi de la procuration", error: err.message });
  }
});

// Stockage temporaire des codes
const verificationCodesTraduction = {};

// Fonction pour générer un code à 6 chiffres
const generateCode = () => Math.floor(100000 + Math.random() * 900000).toString();

// Envoi du code de vérification pour traduction
app.post("/send-code-traduction", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email requis" });

  const code = generateCode();
  verificationCodesTraduction[email] = { code, expires: Date.now() + 5 * 60 * 1000 }; // 5 minutes

  const transporter = createTransporter(); // ← création ici

  const mailOptions = {
    from: `"Tradocument" <${process.env.SMTP_USER}>`,
    to: email,
    subject: "Votre code de vérification Traduction",
    text: `Votre code de vérification est : ${code}. Il expire dans 5 minutes.`
  };

  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      console.error("Erreur envoi mail traduction:", error); // ← log détaillé
      return res.status(500).json({ message: "Erreur lors de l’envoi du code", error: error.message });
    }
    res.json({ message: "Code envoyé avec succès" });
  });
});

// send traduction
app.post("/send-traduction", upload.single("file"), async (req, res) => {
  try {
    console.log("📥 Données reçues :", req.body);
    console.log("📎 Fichier reçu :", req.file);
    const { prenom, nom, email, tel, pays, docType, langSource, langCible, infos, pages, price } = req.body;

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT),
      secure: true,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    // Envoi uniquement à l’ADMIN
    await transporter.sendMail({
      from: `"Tradocument" <${process.env.SMTP_USER}>`,
      to: process.env.ADMIN_MAIL, // <-- ton mail admin
      subject: "Nouvelle demande de traduction",
      text: `
Nouvelle demande de traduction reçue :

👤 Client
Prénom : ${prenom}
Nom : ${nom}
Email : ${email}
Téléphone : ${tel}
Pays : ${pays}

📄 Document
Type de document : ${docType}
Langue source : ${langSource}
Langue cible : ${langCible}
Infos supplémentaires : ${infos || "Aucune"}

📊 Devis
Nombre de pages : ${pages || "Non calculé"}
Prix total : ${price ? price + " €" : "Non calculé"}
      `,
      attachments: req.file
        ? [
            {
              filename: req.file.originalname,
              path: req.file.path,
            },
          ]
        : [],
    });

    res.json({ success: true, message: "Demande envoyée avec succès ✅" });
  } catch (err) {
    console.error("Erreur envoi traduction :", err);
    res.status(500).json({ success: false, message: "Erreur lors de l'envoi", error: err.message });
  }
});




// Vérification du code traduction
app.post("/verify-code-traduction", (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ success: false, message: "Email et code requis" });

  const record = verificationCodesTraduction[email];
  if (!record) return res.status(400).json({ success: false, message: "Aucun code trouvé pour cet email" });

  if (Date.now() > record.expires) {
    delete verificationCodesTraduction[email];
    return res.status(400).json({ success: false, message: "Code expiré" });
  }

  if (record.code === code) {
    delete verificationCodesTraduction[email];
    return res.json({ success: true });
  }

  res.status(400).json({ success: false, message: "Code incorrect" });
});


// ✅ Route pour vérifier le captcha
app.post("/verify-captcha", async (req, res) => {
  try {
    const { token } = req.body;

    const secretKey = process.env.RECAPTCHA_SECRET_KEY;
    const verifyURL = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`;

    const googleResponse = await fetch(verifyURL, { method: "POST" });
    const data = await googleResponse.json();

    console.log("🧠 Google reCAPTCHA:", data);

    if (!data.success) return res.status(400).json({ success: false });

    // Exemple : bloquer score trop faible
    if (data.score < 0.5) {
      return res.status(403).json({ success: false, score: data.score });
    }

    res.status(200).json({ success: true, score: data.score });
  } catch (error) {
    console.error("Erreur reCAPTCHA backend:", error);
    res.status(500).json({ success: false });
  }
});

// Route formulaire partenaire
app.post("/api/rejoindre/submit", upload.single("justificatif"), async (req, res) => {
  console.log("\n========== NOUVELLE DEMANDE ==========");
  console.log("📥 Requête reçue :", req.body, req.file?.path);
  console.log("📎 Fichier reçu :", req.file);

  //les variables utiles
  const justificatif = req.file ? req.file.path : null;

  try {
    const { nom, prenom, email, pays, ville, adresse, nomSociete, adresseSociete, telephoneSociete, telephoneMobile, specialite, commentaires, token } = req.body;

    //verification
    if (!token) {
      console.warn("❌ Token manquant");
      return res.status(400).json({ success: false, message: "Token reCAPTCHA requis" });
    }

    console.log("🔐 Token reçu ✅");

    const secretKey = process.env.RECAPTCHA_SECRET_KEY;
    if (!secretKey) {
      console.error("❌ RECAPTCHA_SECRET_KEY manquante");
      return res.status(500).json({ success: false, message: "Erreur config" });
    }

    console.log("🔑 Clé secrète trouvée ✅");
    console.log("🔄 Vérification reCAPTCHA...");

    try {
      const response = await axios.post(
        'https://www.google.com/recaptcha/api/siteverify',
        null,
        {
          params: {
            secret: secretKey,
            response: token
          },
          timeout: 50000
        }
      );

      const data = response.data;
      console.log("📨 Réponse reCAPTCHA :", data);

      if (!data.success) {
        console.error("❌ reCAPTCHA échoué :", data["error-codes"]);
        return res.status(403).json({ success: false, message: "reCAPTCHA échoué : " + data["error-codes"]?.join(", ") });
      }

      console.log("✅ reCAPTCHA valide - Score :", data.score);

      if (data.score && data.score < 0.5) {
        console.warn("⚠️ Score trop faible :", data.score);
        return res.status(403).json({ success: false, message: "Score trop faible" });
      }

      console.log("✅ Score acceptable");

    } catch (recaptchaError) {
      console.error("❌ Erreur vérification reCAPTCHA :", recaptchaError.message);
      console.error("Code erreur:", recaptchaError.code);
      // IMPORTANT : Arrêter ici si reCAPTCHA échoue
      return res.status(500).json({
        success: false,
        message: "Impossible de vérifier reCAPTCHA. Veuillez réessayer."
      });
    }



    //insertion des candidatures pour les partenaires
    const { error: dbError } = await supabaseAdmin
      .from('pending_partenaires')
      .insert({
        //user_id: userId,
        nom: nom,
        prenom: prenom,
        email: email,
        pays: pays,
        ville: ville,
        adresse: adresse,
        nomSociete: nomSociete,
        adresseSociete: adresseSociete,
        telephoneSociete: telephoneSociete,
        telephoneMobile: telephoneMobile,
        specialite: specialite,
        commentaires: commentaires,
        status: "pending",
        submitted_at: new Date().toISOString(),
      });

    if (dbError) {
      console.error("❌ Erreur insertion DB (pending_applications):", dbError.message);
      throw new Error("Erreur lors de l'enregistrement de la candidature.");
    }

    console.log("✅ Candidature enregistrée en statut 'pending'.");

    // 4. Envoi des e-mails (mis à jour)
    console.log("📧 Envoi email...");

    await Promise.all([
      // A. Mail ADMIN (pour examen)
      transporter.sendMail({
        from: `"Tradocument" <${process.env.SMTP_USER}>`,
        to: process.env.ADMIN_DEV_MAIL, // Adresse de l'administrateur
        subject: `[ACTION REQUISE] Nouvelle demande partenaire : ${nom} ${prenom}`,
        html: `
            <h2>Nouvelle demande partenaire en attente d'approbation</h2>
            <p>Veuillez examiner la candidature de : ${nom} ${prenom} (${email}).</p>
            <p><strong>Spécialité :</strong> ${specialite}</p>
            <p><strong>Lien vers le panneau Admin pour validation :</strong> [Votre URL Admin]</p>
        `,
        attachments: justificatif ? [{ path: justificatif }] : []
      }),

      // B. Mail PARTENAIRE (confirmation de réception et attente)
      transporter.sendMail({
        from: `"Tradocument" <${process.env.SMTP_USER}>`,
        to: email,
        subject: `Tradocument : Confirmation de réception de votre candidature`,
        html: `
            <h2>Bonjour ${prenom},</h2>
            <p>Nous avons bien reçu votre candidature pour rejoindre notre équipe de partenaires traducteurs.</p>
            <p>Notre équipe examine actuellement votre dossier et vous recevrez un e-mail séparé contenant vos identifiants d'accès **après validation** de votre profil.</p>
            <p>Merci pour votre patience.</p>
            <p>L'équipe Tradocument.</p>
        `,
      })
    ]);

    console.log("✅ Emails de notification envoyés");
    console.log("========== FIN OK (EN ATTENTE) ==========\n");

    res.json({ success: true, message: "Candidature soumise avec succès. Vous recevrez un e-mail après validation par notre équipe." });


  } catch (err) {
    console.error("❌ ERREUR :", err.message);
    console.log("========== FIN ERREUR ==========\n");
    res.status(500).json({ success: false, message: "Erreur serveur lors de la soumission de la candidature" });
  }
});


// Assurez-vous d'avoir défini et initialisé 'supabaseAdmin', 'transporter' et 'generateRandomPassword' en dehors de cette fonction.

app.post("/api/admin/validate-partner/:applicationId", async (req, res) => {
  const { applicationId } = req.params;
  const partnerPassword = generateRandomPassword();
  let userId = null;
  let destination_mail = null;


  try {
    // 1. Récupérer et VÉRIFIER les données de l'application en attente
    const { data: application, error: fetchError } = await supabaseAdmin
      .from('pending_partenaires')
      .select('*')
      .eq('user_id', applicationId)
      .eq('status', 'pending') // S'assure qu'elle est bien en attente
      .maybeSingle();

    destination_mail = application.email;

    if (fetchError) throw fetchError;

    if (!application) {
      // 404 si introuvable ou si le statut n'est plus 'pending'
      return res.status(404).json({ success: false, message: "Candidature non trouvée ou déjà traitée." });
    }

    // 2. Créer l'utilisateur dans Supabase Auth
    const { data: userData, error: userError } = await supabaseAdmin.auth.admin.createUser({
      email: application.email,
      password: partnerPassword,
      email_confirm: true,
      app_metadata: { user_role: 'partner' },
      user_metadata: { specialite: application.specialite }
    });

    if (userError) {
      console.error("❌ Erreur Supabase Auth:", userError.message);
      if (userError.message.includes('User already registered')) {
        return res.status(409).json({ success: false, message: "Cet email est déjà utilisé par un utilisateur existant." });
      }
      return res.status(400).json({ success: false, message: "Erreur lors de la création du compte utilisateur." });
    }

    // Récupère l'ID réel de l'utilisateur AUTH créé
    userId = userData.user.id;

    console.log(userId);

    // 3. Insérer les données dans la table Partenaires (avec le VRAI user_id)
    // CORRECTION: L'ID de l'application en attente n'est PAS utilisé comme PK de la table Partenaires.
    const { error: insertError } = await supabaseAdmin
      .from('Partenaires')
      .insert({
        // La clé 'user_id' lie l'enregistrement à auth.users
        user_id: userId,
        email: application.email,
        nom: application.nom,
        prenom: application.prenom,
        specialite: application.specialite,
        status: 'approved',
        // Copie des autres champs
        pays: application.pays,
        ville: application.ville,
        adresse: application.adresse,
        nomSociete: application.nomSociete,
        adresseSociete: application.adresseSociete,
        telephoneSociete: application.telephoneSociete,
        telephoneMobile: application.telephoneMobile,
        commentaires: application.commentaires,
      });

    if (insertError) {
      throw insertError; // Lance l'erreur pour activer le bloc catch (et le rollback)
    }

    // 4. Mettre à jour l'application en attente
    const { error: updateError } = await supabaseAdmin
      .from('pending_partenaires')
      .update({ status: 'validated', user_id: userId, validated_at: new Date().toISOString() })
      .eq('user_id', applicationId);

    if (updateError) {
      throw updateError;
    }

    console.log("envoi de l'email", application.email);

    // 5. Envoyer l'e-mail d'activation avec le mot de passe temporaire
    await transporter.sendMail({
      from: `"Tradocument" <${process.env.SMTP_USER}>`,
      to: destination_mail,
      subject: `Bienvenue chez Tradocument - Votre compte est actif !`,
      html: `
        <p>Bonjour ${application.prenom},</p>
        <p>Votre compte Partenaire est validé. Voici vos identifiants temporaires :</p>
        <ul>
          <li><strong>Email:</strong> ${destination_mail}</li>
          <li><strong>Mot de passe temporaire:</strong> <strong>${partnerPassword}</strong></li>
        </ul>
        <p>Veuillez vous connecter et changer votre mot de passe immédiatement.</p>
        <p>L'équipe Tradocument.</p>
      `
    });

    res.json({ success: true, message: "Partenaire validé, compte créé, et email envoyé." });

  } catch (err) {
    console.error("❌ ERREUR VALIDATION ADMIN:", err.message);

    // LOGIQUE DE ROLLBACK : Tente de supprimer l'utilisateur si la création Auth a réussi
    if (userId) {
      console.warn(`Tentative de suppression de l'utilisateur ${userId} suite à une erreur DB.`);
      const { error: deleteError } = await supabaseAdmin.auth.admin.deleteUser(userId);
      if (deleteError) {
        console.error("Échec du rollback utilisateur:", deleteError.message);
      }
    }

    // 500 si l'erreur n'a pas déjà été gérée (409 ou 400)
    if (!res.headersSent) {
      res.status(500).json({ success: false, message: "Erreur serveur lors de la validation: " + err.message });
    }
  }
});


// DELETE partenaire
app.delete("/api/admin/delete-partner/:userId", async (req, res) => {
  const { userId } = req.params;

  const authHeader = req.headers.authorization;

  // 1. VÉRIFICATION DU TOKEN ET DE L'ADMIN (RÉINTÉGRATION DE LA SÉCURITÉ)
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: "Accès refusé. Jeton manquant." });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Vérification de l'administrateur
    const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(token);

    if (userError || !userData?.user || userData.user.app_metadata?.user_role !== 'admin') {
      return res.status(403).json({ success: false, message: "Accès refusé. Seul un administrateur peut supprimer des partenaires." });
    }

    // --- L'utilisateur est ADMIN, on procède à la suppression ---

    // 2. SUPPRESSION du partenaire dans la table Partenaires
    // NOTE : Supabase .delete() retourne { data, error, count }
    const { data: deletedData, error: deleteDbError, count: deleteCount } = await supabaseAdmin
      .from("Partenaires")
      .delete()
      .eq("user_id", userId)
      .select('*');

    if (deleteDbError) throw deleteDbError;

    if(!deletedData) {
      return res.statut(400).json({ success: false, message: 'erreur lors de la suppression' })
    }

    if (deleteCount === 0) {
      // Si aucune ligne n'a été trouvée/supprimée
      return res.status(404).json({ success: false, message: "Partenaire non trouvé dans la base de données." });
    }

    // 3. SUPPRESSION du compte utilisateur dans Supabase Auth
    // IMPORTANT : Ceci est essentiel pour nettoyer complètement l'utilisateur.
    const { error: deleteAuthError } = await supabaseAdmin.auth.admin.deleteUser(userId);

    if (deleteAuthError) {
      // Log l'erreur mais ne bloque pas le 200 si la DB a réussi, car la suppression Auth est le problème
      console.error("❌ Avertissement: Échec de la suppression de l'utilisateur AUTH:", deleteAuthError.message);
    }


    res.json({ success: true, message: "Partenaire et compte utilisateur associés supprimés avec succès." });

  } catch (err) {
    console.error("❌ ERREUR SUPPRESSION ADMIN:", err.message);
    res.status(500).json({
      success: false,
      message: "Erreur serveur inattendue lors de la suppression."
    });
  }
});



// route pour recuperer les partenaires
  app.get('/partner', async (req, res) => {
    // 1. Récupérer le jeton JWT de l'utilisateur
    const authHeader = req.headers.authorization;
    const token = authHeader ? authHeader.split(' ')[1] : null;

    if (!token) {
      return res.status(401).json({ success: false, message: "Non autorisé: Jeton manquant." });
    }

    try {
      // 2. VÉRIFICATION DU RÔLE EN DÉCODANT LE JWT
      // Nous utilisons la fonction d'admin de Supabase pour vérifier la validité du JWT et obtenir les métadonnées.
      const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(token);


      if (userError || !userData?.user) {
        console.error("❌ Erreur validation JWT:", userError?.message || "Utilisateur non trouvé.");
        return res.status(401).json({ success: false, message: "Jeton non valide ou expiré." });
      }

      // Récupérer le rôle injecté via les Custom Claims (que nous avons configuré)
      const userRole = userData.user.app_metadata.user_role;

      // --- VÉRIFICATION D'AUTORISATION ---
      if (userRole !== 'admin') {
        return res.status(403).json({
          success: false,
          message: "Accès refusé. Seul un administrateur peut voir ces données."
        });
      }

      // --- UTILISATION DE SUPABASE ADMIN POUR LA LECTURE (BYPASS RLS) ---
      // Nous utilisons supabaseAdmin car l'autorisation est déjà vérifiée ci-dessus.

      // --- A. RÉCUPÉRATION DES CANDIDATURES EN ATTENTE (PENDING) ---
      const { data: pending, error: pendingError } = await supabaseAdmin
        .from('pending_partenaires')
        .select('*')
        .eq('status', 'pending');

      if (pendingError) {
        console.error("❌ Erreur DB pending:", pendingError.message);
        return res.status(500).json({
          success: false,
          message: "Erreur DB lors de la récupération des candidatures en attente."
        });
      }

      // --- B. RÉCUPÉRATION DES PARTENAIRES ACTIFS (ACTIVE) ---
      const { data: active, error: activeError } = await supabaseAdmin
        .from('Partenaires')
        .select('*');

      if (activeError) {
        console.error("❌ Erreur DB actifs:", activeError.message);
        throw activeError;
      }

      // 3. Renvoyer les données structurées au frontend
      res.json({
        success: true,
        data: {
          pending_partners: pending || [],
          active_partners: active || []
        }
      });

    } catch (err) {
      console.error("Erreur interne du serveur:", err);
      res.status(500).json({
        success: false,
        message: "Erreur serveur inattendue lors de la récupération."
      });
    }
  });


  //route pour recuperer les documents assignée a un partenaires

app.get('/partner/documents', async (req, res) => {
  // 1. Récupérer le jeton JWT de l'utilisateur
  const authHeader = req.headers.authorization;
  const token = authHeader ? authHeader.split(' ')[1] : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Non autorisé: Jeton manquant."
    });
  }

  try {
    // 2. VÉRIFICATION DU JWT ET RÉCUPÉRATION DE L'UTILISATEUR
    const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(token);

    if (userError || !userData?.user) {
      console.error("❌ Erreur validation JWT:", userError?.message || "Utilisateur non trouvé.");
      return res.status(401).json({
        success: false,
        message: "Jeton non valide ou expiré."
      });
    }

    const userId = userData.user.id;
    const userRole = userData.user.app_metadata.user_role;

    // 3. VÉRIFICATION DU RÔLE - Seuls les partenaires peuvent accéder à cette route
    if (userRole !== 'partner') {
      return res.status(403).json({
        success: false,
        message: "Accès refusé. Seuls les partenaires peuvent accéder à cette route."
      });
    }

    // 4. RÉCUPÉRATION DES DOCUMENTS ASSIGNÉS AU PARTENAIRE
    const { data: documents, error: documentsError } = await supabaseAdmin
      .from('documents')
      .select('*')
      .eq('partner_id', userId)
      .order('assigned_at', { ascending: false });

    if (documentsError) {
      console.error("❌ Erreur DB documents:", documentsError.message);
      return res.status(500).json({
        success: false,
        message: "Erreur lors de la récupération des documents.",
        error: documentsError.message
      });
    }

    // 5. CALCUL DES STATISTIQUES
    const stats = {
      pending: documents.filter(doc => doc.status === 'pending').length,
      in_progress: documents.filter(doc => doc.status === 'in_progress').length,
      completed: documents.filter(doc => doc.status === 'completed').length,
      total: documents.length,
      overdue: documents.filter(doc =>
        doc.deadline &&
        new Date(doc.deadline) < new Date() &&
        doc.status !== 'completed'
      ).length
    };

    // 6. RÉPARTITION DES DOCUMENTS PAR CATÉGORIE
    const assignedDocuments = documents.filter(doc => doc.status !== 'completed');
    const inProgressDocuments = documents.filter(doc => doc.status === 'in_progress');
    const completedDocuments = documents.filter(doc => doc.status === 'completed');

    // 7. CALCUL DES GAINS
    const totalEarned = documents
      .filter(doc => doc.status === 'completed' && doc.montant)
      .reduce((sum, doc) => sum + parseFloat(doc.montant), 0);

    const potentialEarnings = documents
      .filter(doc => doc.status !== 'completed' && doc.montant)
      .reduce((sum, doc) => sum + parseFloat(doc.montant), 0);

    // 8. RENVOYER LES DONNÉES STRUCTURÉES
    res.json({
      success: true,
      data: {
        all_documents: documents,
        assigned_documents: assignedDocuments,
        in_progress_documents: inProgressDocuments,
        completed_documents: completedDocuments,
        stats: stats,
        earnings: {
          total_earned: totalEarned.toFixed(2),
          potential_earnings: potentialEarnings.toFixed(2),
          currency: 'EUR'
        }
      }
    });

  } catch (err) {
    console.error("❌ Erreur interne du serveur:", err);
    res.status(500).json({
      success: false,
      message: "Erreur serveur inattendue lors de la récupération.",
      error: err.message
    });
  }
});

// mette a jour l'etat d'un document
app.put('/partner/documents/:documentId/progress', async (req, res) => {
  const { documentId } = req.params;
  const { progress } = req.body;

  // 1. Vérification du JWT
  const authHeader = req.headers.authorization;
  const token = authHeader ? authHeader.split(' ')[1] : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Non autorisé: Jeton manquant."
    });
  }

  try {
    // 2. Validation du JWT
    const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(token);

    if (userError || !userData?.user) {
      return res.status(401).json({
        success: false,
        message: "Jeton non valide ou expiré."
      });
    }

    const userId = userData.user.id;

    // 3. Validation de la progression
    if (typeof progress !== 'number' || progress < 0 || progress > 100) {
      return res.status(400).json({
        success: false,
        message: "La progression doit être un nombre entre 0 et 100."
      });
    }

    // 4. Vérifier que le document appartient bien au partenaire
    const { data: document, error: fetchError } = await supabaseAdmin
      .from('documents')
      .select('partner_id')
      .eq('id', documentId)
      .single();

    if (fetchError || !document) {
      return res.status(404).json({
        success: false,
        message: "Document non trouvé."
      });
    }

    if (document.partner_id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Vous n'êtes pas autorisé à modifier ce document."
      });
    }

    // 5. Mettre à jour la progression
    const { data: updatedDoc, error: updateError } = await supabaseAdmin
      .from('documents')
      .update({
        progress: progress,
        updated_at: new Date().toISOString()
      })
      .eq('id', documentId)
      .select()
      .single();

    if (updateError) {
      console.error("❌ Erreur mise à jour:", updateError.message);
      return res.status(500).json({
        success: false,
        message: "Erreur lors de la mise à jour de la progression."
      });
    }

    res.json({
      success: true,
      message: "Progression mise à jour avec succès.",
      data: updatedDoc
    });

  } catch (err) {
    console.error("❌ Erreur serveur:", err);
    res.status(500).json({
      success: false,
      message: "Erreur serveur inattendue."
    });
  }
});


// route pour demarer la traduction
app.put('/partner/documents/:documentId/start', async (req, res) => {
  const { documentId } = req.params;

  // 1. Vérification du JWT
  const authHeader = req.headers.authorization;
  const token = authHeader ? authHeader.split(' ')[1] : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Non autorisé: Jeton manquant."
    });
  }

  try {
    // 2. Validation du JWT
    const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(token);

    if (userError || !userData?.user) {
      return res.status(401).json({
        success: false,
        message: "Jeton non valide ou expiré."
      });
    }

    const userId = userData.user.id;

    // 3. Vérifier que le document appartient au partenaire
    const { data: document, error: fetchError } = await supabaseAdmin
      .from('documents')
      .select('*')
      .eq('id', documentId)
      .single();

    if (fetchError || !document) {
      return res.status(404).json({
        success: false,
        message: "Document non trouvé."
      });
    }

    if (document.partner_id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Vous n'êtes pas autorisé à modifier ce document."
      });
    }

    if (document.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: "Ce document a déjà été démarré ou complété."
      });
    }

    // 4. Démarrer la traduction
    const { data: updatedDoc, error: updateError } = await supabaseAdmin
      .from('documents')
      .update({
        status: 'in_progress',
        started_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .eq('id', documentId)
      .select()
      .single();

    if (updateError) {
      console.error("❌ Erreur mise à jour:", updateError.message);
      return res.status(500).json({
        success: false,
        message: "Erreur lors du démarrage de la traduction."
      });
    }

    res.json({
      success: true,
      message: "Traduction démarrée avec succès.",
      data: updatedDoc
    });

  } catch (err) {
    console.error("❌ Erreur serveur:", err);
    res.status(500).json({
      success: false,
      message: "Erreur serveur inattendue."
    });
  }
});

//route pour completer le document
app.put('/partner/documents/:documentId/complete', async (req, res) => {
  const { documentId } = req.params;

  // 1. Vérification du JWT
  const authHeader = req.headers.authorization;
  const token = authHeader ? authHeader.split(' ')[1] : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Non autorisé: Jeton manquant."
    });
  }

  try {
    // 2. Validation du JWT
    const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(token);

    if (userError || !userData?.user) {
      return res.status(401).json({
        success: false,
        message: "Jeton non valide ou expiré."
      });
    }

    const userId = userData.user.id;

    // 3. Vérifier que le document appartient au partenaire
    const { data: document, error: fetchError } = await supabaseAdmin
      .from('documents')
      .select('*')
      .eq('id', documentId)
      .single();

    if (fetchError || !document) {
      return res.status(404).json({
        success: false,
        message: "Document non trouvé."
      });
    }

    if (document.partner_id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Vous n'êtes pas autorisé à modifier ce document."
      });
    }

    if (document.status === 'completed') {
      return res.status(400).json({
        success: false,
        message: "Ce document est déjà marqué comme complété."
      });
    }

    // 4. Marquer comme complété
    const { data: updatedDoc, error: updateError } = await supabaseAdmin
      .from('documents')
      .update({
        status: 'completed',
        progress: 100,
        completed_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .eq('id', documentId)
      .select()
      .single();

    if (updateError) {
      console.error("❌ Erreur mise à jour:", updateError.message);
      return res.status(500).json({
        success: false,
        message: "Erreur lors de la complétion du document."
      });
    }

    res.json({
      success: true,
      message: "Document marqué comme complété avec succès.",
      data: updatedDoc
    });

  } catch (err) {
    console.error("❌ Erreur serveur:", err);
    res.status(500).json({
      success: false,
      message: "Erreur serveur inattendue."
    });
  }
});

// route pour les statistiques
app.get('/partner/statistics', async (req, res) => {
  // 1. Vérification du JWT
  const authHeader = req.headers.authorization;
  const token = authHeader ? authHeader.split(' ')[1] : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Non autorisé: Jeton manquant."
    });
  }

  try {
    // 2. Validation du JWT
    const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(token);

    if (userError || !userData?.user) {
      return res.status(401).json({
        success: false,
        message: "Jeton non valide ou expiré."
      });
    }

    const userId = userData.user.id;

    // 3. Récupérer les statistiques depuis la vue
    const { data: stats, error: statsError } = await supabaseAdmin
      .from('partner_statistics')
      .select('*')
      .eq('partner_id', userId)
      .single();

    if (statsError) {
      console.error("❌ Erreur statistiques:", statsError.message);
      return res.status(500).json({
        success: false,
        message: "Erreur lors de la récupération des statistiques."
      });
    }

    res.json({
      success: true,
      data: stats || {
        total_documents: 0,
        pending_count: 0,
        in_progress_count: 0,
        completed_count: 0,
        average_progress: 0,
        total_earned: 0,
        overdue_count: 0
      }
    });

  } catch (err) {
    console.error("❌ Erreur serveur:", err);
    res.status(500).json({
      success: false,
      message: "Erreur serveur inattendue."
    });
  }
});


// route pour telecharger les documents originale
app.get('/partner/documents/:documentId/download', async (req, res) => {
  const { documentId } = req.params;

  // 1. Vérification du JWT
  const authHeader = req.headers.authorization;
  const token = authHeader ? authHeader.split(' ')[1] : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Non autorisé: Jeton manquant."
    });
  }

  try {
    // 2. Validation du JWT
    const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(token);

    if (userError || !userData?.user) {
      return res.status(401).json({
        success: false,
        message: "Jeton non valide ou expiré."
      });
    }

    const userId = userData.user.id;
    const userRole = userData.user.app_metadata.user_role;

    // 3. Vérifier que l'utilisateur est un partenaire
    if (userRole !== 'partner') {
      return res.status(403).json({
        success: false,
        message: "Accès refusé. Seuls les partenaires peuvent télécharger."
      });
    }

    // 4. Récupérer le document de la base de données
    const { data: document, error: fetchError } = await supabaseAdmin
      .from('documents')
      .select('*')
      .eq('id', documentId)
      .single();

    if (fetchError || !document) {
      return res.status(404).json({
        success: false,
        message: "Document non trouvé."
      });
    }

    // 5. Vérifier que le document est assigné au partenaire
    if (document.partner_id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Vous n'êtes pas autorisé à télécharger ce document."
      });
    }

    // 6. Vérifier que le document a un fichier associé
    if (!document.document_url) {
      return res.status(404).json({
        success: false,
        message: "Aucun fichier associé à ce document."
      });
    }

    // 7. Construire le chemin vers le fichier
    // document_url contient le nom du fichier (ex: "document_1234567890.pdf")
    const fileName = document.document_url;
    const filePath = path.join(__dirname, 'uploads', fileName);

    // 8. Vérifier que le fichier existe
    if (!fs.existsSync(filePath)) {
      console.error(`❌ Fichier non trouvé: ${filePath}`);
      return res.status(404).json({
        success: false,
        message: "Fichier non trouvé sur le serveur."
      });
    }

    // 9. Déterminer le type MIME du fichier
    const ext = path.extname(fileName).toLowerCase();
    const mimeTypes = {
      '.pdf': 'application/pdf',
      '.doc': 'application/msword',
      '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.txt': 'text/plain'
    };
    const mimeType = mimeTypes[ext] || 'application/octet-stream';

    // 10. Définir les en-têtes pour le téléchargement
    const originalFileName = `${document.nom_client}_${document.prenom_client}_${document.doc_type}${ext}`;

    res.setHeader('Content-Type', mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(originalFileName)}"`);
    res.setHeader('Content-Length', fs.statSync(filePath).size);

    // 11. Envoyer le fichier
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);

    fileStream.on('error', (error) => {
      console.error('❌ Erreur lors de la lecture du fichier:', error);
      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          message: "Erreur lors du téléchargement du fichier."
        });
      }
    });

  } catch (err) {
    console.error("❌ Erreur serveur:", err);
    res.status(500).json({
      success: false,
      message: "Erreur serveur inattendue."
    });
  }
});




  app.use(express.static(path.join(process.cwd(), "dist")));

// Toutes les autres routes renvoient index.html
  app.get(/.*/, (req, res) => {
    res.sendFile(path.join(process.cwd(), "dist", "index.html"));
  });

  app.listen(PORT, () => console.log(`✅ Serveur démarré sur le port ${PORT}`));
