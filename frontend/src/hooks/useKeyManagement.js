import { useState, useEffect } from "react";
import CryptoService from "../services/cryptoService";

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
      const response = await fetch("/api/users/public-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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
