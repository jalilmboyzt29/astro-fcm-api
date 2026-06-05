// Mengonversi string Base64 ke format URL-safe untuk standar JWT
const base64url = (str) => {
  return btoa(str)
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
};

// Fungsi internal untuk membuat Google OAuth2 Access Token dari Service Account
async function getGoogleAccessToken(clientEmail, privateKey) {
  const header = JSON.stringify({ alg: 'RS256', typ: 'JWT' });
  
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600; // Token berlaku selama 1 jam
  
  const payload = JSON.stringify({
    iss: clientEmail,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    exp: exp,
    iat: iat
  });

  const unsignedToken = `${base64url(header)}.${base64url(payload)}`;

  // Membersihkan format private key dari environment variable
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = privateKey
    .replace(pemHeader, "")
    .replace(pemFooter, "")
    .replace(/\s+/g, "");
    
  // Mengonversi string base64 key menjadi ArrayBuffer
  const binaryDerString = atob(pemContents);
  const binaryDer = new Uint8Array(binaryDerString.length);
  for (let i = 0; i < binaryDerString.length; i++) {
    binaryDer[i] = binaryDerString.charCodeAt(i);
  }

  // Import key menggunakan Web Crypto API bawaan Cloudflare Workers
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    binaryDer.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  // Melakukan signing JWT
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(unsignedToken)
  );

  const signedToken = `${unsignedToken}.${base64url(String.fromCharCode(...new Uint8Array(signature)))}`;

  // Menukar JWT dengan Access Token resmi dari Google
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: signedToken
    })
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(`Gagal generate OAuth token: ${data.error_description || data.error}`);
  }
  return data.access_token;
}

const ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'http://localhost:4173',
  'https://jadwal-operasi-420da.web.app',
  'https://jadwal-operasi-rsmi.web.app'
];

// Fungsi pembantu untuk mengecek dan mengambil origin yang valid
const getCorsOrigin = (request) => {
  const origin = request.headers.get('Origin');
  if (ALLOWED_ORIGINS.includes(origin)) {
    return origin;
  }
  // Jika tidak terdaftar, kembalikan domain production sebagai default aman
  return 'https://jadwal-operasi-rsmi.web.app';
};

// 1. Method OPTIONS: Menangani Preflight Request dari browser (CORS)
export const OPTIONS = async () => {
const origin = getCorsOrigin(request);

  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': origin, //'https://web.app', // Ganti dengan domain Firebase Hosting kamu
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
};

// 2. Method POST: Menerima request dari Vue dan meneruskannya ke FCM HTTP v1 API
export const POST = async ({ request }) => {
const origin = getCorsOrigin(request);

  const corsHeaders = {
    'Access-Control-Allow-Origin': origin, //'https://web.app', // Ganti dengan domain Firebase Hosting kamu
    'Content-Type': 'application/json'
  };

  try {
    const body = await request.json();
    const tokenFCM = body.token;
    const title = body.title || 'Halo!';
    const messageText = body.body || 'Pesan dari Astro';

    if (!tokenFCM) {
      return new Response(JSON.stringify({ success: false, error: 'Token FCM tidak ditemukan' }), {
        status: 400,
        headers: corsHeaders
      });
    }

    // Mengambil data rahasia dari Environment Variables Cloudflare Pages
    const PROJECT_ID = process.env.FIREBASE_PROJECT_ID;
    const CLIENT_EMAIL = process.env.FIREBASE_CLIENT_EMAIL;
    const PRIVATE_KEY = process.env.FIREBASE_PRIVATE_KEY;

    if (!PROJECT_ID || !CLIENT_EMAIL || !PRIVATE_KEY) {
      throw new Error("Konfigurasi Environment Variables di Cloudflare belum lengkap.");
    }

    // Ambil Bearer Token Access secara realtime
    const accessToken = await getGoogleAccessToken(CLIENT_EMAIL, PRIVATE_KEY);

    // Kirim payload ke Google FCM HTTP v1 API
    const fcmResponse = await fetch(`https://googleapis.com{PROJECT_ID}/messages:send`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        message: {
          token: tokenFCM,
          notification: { 
            title: title, 
            body: messageText 
          }
        }
      })
    });

    const fcmData = await fcmResponse.json();

    if (!fcmResponse.ok) {
      throw new Error(`FCM Server Error: ${JSON.stringify(fcmData)}`);
    }

    return new Response(JSON.stringify({ success: true, data: fcmData }), {
      status: 200,
      headers: corsHeaders
    });

  } catch (error) {
    return new Response(JSON.stringify({ success: false, error: error.message }), {
      status: 500,
      headers: corsHeaders
    });
  }
};
