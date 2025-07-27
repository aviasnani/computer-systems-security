import { useState, useEffect } from "react";
import CryptoService from "../services/cryptoService";
import { auth } from "../firebase.config";

export const useKeyManagement = (userId) => {
  const [rsaKeys, setRsaKeys] = useState(null);
  const [aesKey, setAesKey] = useState(null);
  const [isGenerating, setIsGenerating] = useState(false);

  // Generate keys on mount
  useEffect(() => {
    if (userId && !rsaKeys) {
      generateKeys();
    }
  }, [userId]);

  const generateKeys = async () => {
    setIsGenerating(true);
    try {
      const rsa = await CryptoService.generateRSAKeyPair();
      const aes = await CryptoService.generateAESKey();

      setRsaKeys(rsa);
      setAesKey(aes);

      // Store in localStorage
      localStorage.setItem(`rsa_private_${userId}`, rsa.privateKey);
      localStorage.setItem(`aes_key_${userId}`, aes);

      // Send public key to server
      await sendPublicKeyToServer(rsa.publicKey);
    } catch (error) {
      console.error("Key generation failed:", error);
    } finally {
      setIsGenerating(false);
    }
  };

  const sendPublicKeyToServer = async (publicKey) => {
    try {
      // Get Firebase token
      const user = auth.currentUser;
      if (!user) return;
      
      const token = await user.getIdToken();
      
      const response = await fetch("http://localhost:5000/api/public-key", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ publicKey }),
      });
      if (!response.ok) throw new Error("Failed to upload public key");
    } catch (error) {
      console.error("Public key upload failed:", error);
    }
  };

  return {
    rsaKeys,
    aesKey,
    isGenerating,
    generateKeys,
  };
};
