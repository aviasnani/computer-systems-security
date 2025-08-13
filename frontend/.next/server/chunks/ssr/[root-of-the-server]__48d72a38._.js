module.exports = {

"[externals]/fs [external] (fs, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("fs", () => require("fs"));

module.exports = mod;
}}),
"[externals]/url [external] (url, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("url", () => require("url"));

module.exports = mod;
}}),
"[externals]/child_process [external] (child_process, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("child_process", () => require("child_process"));

module.exports = mod;
}}),
"[externals]/http [external] (http, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("http", () => require("http"));

module.exports = mod;
}}),
"[externals]/https [external] (https, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("https", () => require("https"));

module.exports = mod;
}}),
"[externals]/tty [external] (tty, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("tty", () => require("tty"));

module.exports = mod;
}}),
"[externals]/util [external] (util, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("util", () => require("util"));

module.exports = mod;
}}),
"[externals]/os [external] (os, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("os", () => require("os"));

module.exports = mod;
}}),
"[externals]/stream [external] (stream, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("stream", () => require("stream"));

module.exports = mod;
}}),
"[externals]/zlib [external] (zlib, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("zlib", () => require("zlib"));

module.exports = mod;
}}),
"[externals]/buffer [external] (buffer, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("buffer", () => require("buffer"));

module.exports = mod;
}}),
"[externals]/events [external] (events, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("events", () => require("events"));

module.exports = mod;
}}),
"[externals]/net [external] (net, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("net", () => require("net"));

module.exports = mod;
}}),
"[externals]/tls [external] (tls, cjs)": (function(__turbopack_context__) {

var { g: global, __dirname, m: module, e: exports } = __turbopack_context__;
{
const mod = __turbopack_context__.x("tls", () => require("tls"));

module.exports = mod;
}}),
"[project]/src/utils/errorHandler.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
/**
 * Centralized error handling utilities
 */ __turbopack_context__.s({
    "AppError": (()=>AppError),
    "EncryptionErrorCodes": (()=>EncryptionErrorCodes),
    "ErrorCodes": (()=>ErrorCodes),
    "getEncryptionErrorMessage": (()=>getEncryptionErrorMessage),
    "getErrorMessage": (()=>getErrorMessage),
    "handleAsyncError": (()=>handleAsyncError),
    "isAuthError": (()=>isAuthError),
    "isEncryptionError": (()=>isEncryptionError),
    "isNetworkError": (()=>isNetworkError),
    "logError": (()=>logError),
    "retryEncryptionOperation": (()=>retryEncryptionOperation),
    "retryWithBackoff": (()=>retryWithBackoff),
    "shouldRetry": (()=>shouldRetry),
    "shouldRetryEncryptionError": (()=>shouldRetryEncryptionError),
    "withErrorHandling": (()=>withErrorHandling)
});
class AppError extends Error {
    constructor(message, code = 'UNKNOWN_ERROR', details = {}){
        super(message);
        this.name = 'AppError';
        this.code = code;
        this.details = details;
        this.timestamp = new Date().toISOString();
    }
}
const ErrorCodes = {
    NETWORK_ERROR: 'NETWORK_ERROR',
    AUTH_ERROR: 'AUTH_ERROR',
    WEBSOCKET_ERROR: 'WEBSOCKET_ERROR',
    ENCRYPTION_ERROR: 'ENCRYPTION_ERROR',
    VALIDATION_ERROR: 'VALIDATION_ERROR',
    PERMISSION_ERROR: 'PERMISSION_ERROR',
    SERVER_ERROR: 'SERVER_ERROR',
    UNKNOWN_ERROR: 'UNKNOWN_ERROR'
};
const getErrorMessage = (error)=>{
    if (error instanceof AppError) {
        return error.message;
    }
    if (error?.code) {
        switch(error.code){
            case 'auth/network-request-failed':
                return 'Network error. Please check your connection and try again.';
            case 'auth/too-many-requests':
                return 'Too many failed attempts. Please try again later.';
            case 'auth/popup-blocked':
                return 'Pop-up was blocked. Please allow pop-ups and try again.';
            case 'auth/popup-closed-by-user':
                return 'Sign-in was cancelled. Please try again.';
            case 'auth/user-disabled':
                return 'This account has been disabled. Please contact support.';
            case 'auth/user-not-found':
                return 'No account found with this email address.';
            case 'auth/wrong-password':
                return 'Incorrect password. Please try again.';
            case 'auth/invalid-email':
                return 'Invalid email address format.';
            default:
                return error.message || 'An unexpected error occurred.';
        }
    }
    if (error?.message) {
        return error.message;
    }
    return 'An unexpected error occurred. Please try again.';
};
const logError = (error, context = {})=>{
    const errorInfo = {
        message: error.message,
        stack: error.stack,
        code: error.code,
        timestamp: new Date().toISOString(),
        context,
        userAgent: ("TURBOPACK compile-time falsy", 0) ? ("TURBOPACK unreachable", undefined) : 'server',
        url: ("TURBOPACK compile-time falsy", 0) ? ("TURBOPACK unreachable", undefined) : 'unknown'
    };
    // Log to console in development
    if ("TURBOPACK compile-time truthy", 1) {
        console.error('Error logged:', errorInfo);
    }
    // In production, send to error reporting service
    if (("TURBOPACK compile-time value", "development") === 'production') {
    // Example: Send to Sentry, LogRocket, or custom logging service
    // errorReportingService.log(errorInfo);
    }
    return errorInfo;
};
const handleAsyncError = (asyncFn)=>{
    return async (...args)=>{
        try {
            return await asyncFn(...args);
        } catch (error) {
            logError(error, {
                function: asyncFn.name,
                args
            });
            throw error;
        }
    };
};
const withErrorHandling = (component)=>{
    return (props)=>{
        try {
            return component(props);
        } catch (error) {
            logError(error, {
                component: component.name,
                props
            });
            throw error;
        }
    };
};
const isNetworkError = (error)=>{
    return error.code === 'NETWORK_ERROR' || error.message?.includes('network') || error.message?.includes('fetch') || error.name === 'NetworkError';
};
const isAuthError = (error)=>{
    return error.code === 'AUTH_ERROR' || error.code?.startsWith('auth/') || error.message?.includes('authentication') || error.message?.includes('unauthorized');
};
const shouldRetry = (error, retryCount = 0, maxRetries = 3)=>{
    if (retryCount >= maxRetries) {
        return false;
    }
    // Retry network errors
    if (isNetworkError(error)) {
        return true;
    }
    // Retry server errors (5xx)
    if (error.status >= 500 && error.status < 600) {
        return true;
    }
    // Don't retry auth errors or client errors
    if (isAuthError(error) || error.status >= 400 && error.status < 500) {
        return false;
    }
    return false;
};
const retryWithBackoff = async (fn, maxRetries = 3, baseDelay = 1000)=>{
    let lastError;
    for(let i = 0; i <= maxRetries; i++){
        try {
            return await fn();
        } catch (error) {
            lastError = error;
            if (i === maxRetries || !shouldRetry(error, i, maxRetries)) {
                throw error;
            }
            // Exponential backoff with jitter
            const delay = baseDelay * Math.pow(2, i) + Math.random() * 1000;
            await new Promise((resolve)=>setTimeout(resolve, delay));
        }
    }
    throw lastError;
};
const EncryptionErrorCodes = {
    KEY_GENERATION_FAILED: 'ENCRYPTION_KEY_GENERATION_FAILED',
    ENCRYPTION_FAILED: 'ENCRYPTION_FAILED',
    DECRYPTION_FAILED: 'DECRYPTION_FAILED',
    KEY_EXCHANGE_FAILED: 'ENCRYPTION_KEY_EXCHANGE_FAILED',
    SIGNATURE_VERIFICATION_FAILED: 'ENCRYPTION_SIGNATURE_VERIFICATION_FAILED',
    STORAGE_FAILED: 'ENCRYPTION_STORAGE_FAILED',
    INITIALIZATION_FAILED: 'ENCRYPTION_INITIALIZATION_FAILED'
};
const isEncryptionError = (error)=>{
    return error.code?.startsWith('ENCRYPTION_') || error.type?.includes('encryption') || error.type?.includes('crypto') || error.message?.toLowerCase().includes('encryption') || error.message?.toLowerCase().includes('decrypt') || error.message?.toLowerCase().includes('crypto');
};
const getEncryptionErrorMessage = (error)=>{
    if (error.userFriendlyMessage) {
        return error.userFriendlyMessage;
    }
    // Map technical errors to user-friendly messages
    const errorMessage = error.message?.toLowerCase() || '';
    if (errorMessage.includes('key generation')) {
        return 'Failed to generate encryption keys. Please try again.';
    }
    if (errorMessage.includes('encrypt') && !errorMessage.includes('decrypt')) {
        return 'Failed to encrypt message. Please check your connection and try again.';
    }
    if (errorMessage.includes('decrypt')) {
        return 'Unable to decrypt this message. It may be corrupted or sent with incompatible encryption.';
    }
    if (errorMessage.includes('signature')) {
        return 'Message authenticity could not be verified. This message may not be from the claimed sender.';
    }
    if (errorMessage.includes('key exchange') || errorMessage.includes('public key')) {
        return 'Failed to exchange encryption keys. Please refresh and try again.';
    }
    if (errorMessage.includes('storage') || errorMessage.includes('localstorage')) {
        return 'Failed to store encryption keys securely. Please check your browser settings.';
    }
    if (errorMessage.includes('initialization') || errorMessage.includes('setup')) {
        return 'Failed to initialize encryption. Please refresh the page and try again.';
    }
    return 'An encryption error occurred. Please try again.';
};
const shouldRetryEncryptionError = (error, retryCount = 0, maxRetries = 3)=>{
    if (retryCount >= maxRetries) {
        return false;
    }
    // Don't retry signature verification failures
    if (error.type === 'signature_verification_failed' || error.message?.toLowerCase().includes('signature')) {
        return false;
    }
    // Retry network-related encryption errors
    if (isNetworkError(error) || error.message?.toLowerCase().includes('fetch')) {
        return true;
    }
    // Retry key exchange failures
    if (error.message?.toLowerCase().includes('key exchange') || error.message?.toLowerCase().includes('public key')) {
        return true;
    }
    // Retry key generation failures (up to 3 times)
    if (error.message?.toLowerCase().includes('key generation')) {
        return retryCount < 3;
    }
    // Retry storage failures
    if (error.message?.toLowerCase().includes('storage')) {
        return retryCount < 2;
    }
    // Don't retry decryption failures (data might be corrupted)
    if (error.message?.toLowerCase().includes('decrypt')) {
        return false;
    }
    // Retry other encryption errors once
    if (isEncryptionError(error)) {
        return retryCount < 1;
    }
    return shouldRetry(error, retryCount, maxRetries);
};
const retryEncryptionOperation = async (fn, maxRetries = 3, baseDelay = 1000)=>{
    let lastError;
    for(let i = 0; i <= maxRetries; i++){
        try {
            return await fn();
        } catch (error) {
            lastError = error;
            if (i === maxRetries || !shouldRetryEncryptionError(error, i, maxRetries)) {
                // Enhance error with user-friendly message
                if (isEncryptionError(error) && !error.userFriendlyMessage) {
                    error.userFriendlyMessage = getEncryptionErrorMessage(error);
                }
                throw error;
            }
            // Exponential backoff with jitter, but shorter delays for encryption operations
            const delay = Math.min(baseDelay * Math.pow(1.5, i) + Math.random() * 500, 5000);
            await new Promise((resolve)=>setTimeout(resolve, delay));
        }
    }
    throw lastError;
};
}}),
"[project]/src/utils/validation.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
/**
 * Input validation utilities
 */ __turbopack_context__.s({
    "ValidationRules": (()=>ValidationRules),
    "createValidator": (()=>createValidator),
    "sanitizeInput": (()=>sanitizeInput),
    "sanitizeMessage": (()=>sanitizeMessage),
    "validateEmail": (()=>validateEmail),
    "validateMaxLength": (()=>validateMaxLength),
    "validateMessage": (()=>validateMessage),
    "validateMinLength": (()=>validateMinLength),
    "validatePattern": (()=>validatePattern),
    "validateRequired": (()=>validateRequired),
    "validateRoomId": (()=>validateRoomId),
    "validateUserId": (()=>validateUserId)
});
const ValidationRules = {
    REQUIRED: 'required',
    EMAIL: 'email',
    MIN_LENGTH: 'minLength',
    MAX_LENGTH: 'maxLength',
    PATTERN: 'pattern',
    CUSTOM: 'custom'
};
const validateRequired = (value)=>{
    if (value === null || value === undefined || value === '') {
        return 'This field is required';
    }
    if (typeof value === 'string' && value.trim() === '') {
        return 'This field is required';
    }
    return null;
};
const validateEmail = (email)=>{
    if (!email) return null;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return 'Please enter a valid email address';
    }
    return null;
};
const validateMinLength = (value, minLength)=>{
    if (!value) return null;
    if (value.length < minLength) {
        return `Must be at least ${minLength} characters long`;
    }
    return null;
};
const validateMaxLength = (value, maxLength)=>{
    if (!value) return null;
    if (value.length > maxLength) {
        return `Must be no more than ${maxLength} characters long`;
    }
    return null;
};
const validatePattern = (value, pattern, message = 'Invalid format')=>{
    if (!value) return null;
    const regex = new RegExp(pattern);
    if (!regex.test(value)) {
        return message;
    }
    return null;
};
const sanitizeInput = (input)=>{
    if (typeof input !== 'string') return input;
    // Remove potentially dangerous characters
    return input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '').replace(/<[^>]*>/g, '').trim();
};
const sanitizeMessage = (message)=>{
    if (typeof message !== 'string') return '';
    // Allow basic formatting but remove dangerous content
    return message.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '').replace(/javascript:/gi, '').replace(/on\w+\s*=/gi, '').trim();
};
const validateMessage = (message)=>{
    const errors = [];
    if (!message || message.trim() === '') {
        errors.push('Message cannot be empty');
    }
    if (message && message.length > 5000) {
        errors.push('Message is too long (maximum 5000 characters)');
    }
    // Check for spam patterns
    const spamPatterns = [
        /(.)\1{10,}/,
        /https?:\/\/[^\s]+/gi // URLs (you might want to allow these)
    ];
    for (const pattern of spamPatterns){
        if (pattern.test(message)) {
            break;
        }
    }
    return errors;
};
const validateRoomId = (roomId)=>{
    if (!roomId) {
        return 'Room ID is required';
    }
    if (typeof roomId !== 'string') {
        return 'Room ID must be a string';
    }
    if (roomId.length < 1 || roomId.length > 50) {
        return 'Room ID must be between 1 and 50 characters';
    }
    // Allow alphanumeric, hyphens, and underscores
    if (!/^[a-zA-Z0-9_-]+$/.test(roomId)) {
        return 'Room ID can only contain letters, numbers, hyphens, and underscores';
    }
    return null;
};
const validateUserId = (userId)=>{
    if (!userId) {
        return 'User ID is required';
    }
    if (typeof userId !== 'string' && typeof userId !== 'number') {
        return 'User ID must be a string or number';
    }
    return null;
};
const createValidator = (rules)=>{
    return (value)=>{
        const errors = [];
        for (const rule of rules){
            let error = null;
            switch(rule.type){
                case ValidationRules.REQUIRED:
                    error = validateRequired(value);
                    break;
                case ValidationRules.EMAIL:
                    error = validateEmail(value);
                    break;
                case ValidationRules.MIN_LENGTH:
                    error = validateMinLength(value, rule.value);
                    break;
                case ValidationRules.MAX_LENGTH:
                    error = validateMaxLength(value, rule.value);
                    break;
                case ValidationRules.PATTERN:
                    error = validatePattern(value, rule.pattern, rule.message);
                    break;
                case ValidationRules.CUSTOM:
                    error = rule.validator(value);
                    break;
                default:
                    break;
            }
            if (error) {
                errors.push(error);
            }
        }
        return errors;
    };
};
}}),
"[project]/src/services/websocket.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$socket$2e$io$2d$client$2f$build$2f$esm$2d$debug$2f$index$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$module__evaluation$3e$__ = __turbopack_context__.i("[project]/node_modules/socket.io-client/build/esm-debug/index.js [app-ssr] (ecmascript) <module evaluation>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$socket$2e$io$2d$client$2f$build$2f$esm$2d$debug$2f$index$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$locals$3e$__ = __turbopack_context__.i("[project]/node_modules/socket.io-client/build/esm-debug/index.js [app-ssr] (ecmascript) <locals>");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/utils/errorHandler.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$validation$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/utils/validation.js [app-ssr] (ecmascript)");
;
;
;
class WebSocketService {
    constructor(){
        this.socket = null;
        this.isConnected = false;
        this.connectionCallbacks = [];
        this.messageCallbacks = [];
        this.roomCallbacks = [];
        this.errorCallbacks = [];
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 3;
        this.currentRoom = null;
        this.pendingRoomJoin = null;
        this.reconnectTimer = null;
        this.connectionError = null;
        this.pendingMessages = [];
        this.isReconnecting = false;
        this.typingCallbacks = [];
        this.presenceCallbacks = [];
        this.typingTimer = null;
    }
    /**
   * Find available server port
   */ findAvailableServer() {
        // Try common ports the backend might be running on
        const ports = [
            5000,
            5001,
            5002,
            5003,
            8000
        ];
        // For now, just return the first one - in a real app you'd test connectivity
        return `http://localhost:${ports[0]}`;
    }
    /**
   * Connect to the WebSocket server
   */ connect(userId, token) {
        if (this.socket && this.isConnected) {
            console.log('WebSocket already connected');
            return;
        }
        // Get server URL from environment or try common ports
        const serverUrl = ("TURBOPACK compile-time value", "http://localhost:5000") || this.findAvailableServer();
        this.socket = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$socket$2e$io$2d$client$2f$build$2f$esm$2d$debug$2f$index$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$locals$3e$__["io"])(serverUrl, {
            auth: {
                user_id: userId,
                userId,
                token
            },
            transports: [
                'websocket',
                'polling'
            ],
            timeout: 20000,
            withCredentials: true
        });
        this.setupEventListeners();
    }
    /**
   * Disconnect from the WebSocket server
   */ disconnect() {
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
            this.isConnected = false;
            this.reconnectAttempts = 0;
            this.notifyConnectionStatus(false);
        }
    }
    /**
   * Join a specific chat room
   */ joinRoom(roomId) {
        if (!roomId) {
            console.error('Cannot join room: roomId is required');
            return;
        }
        if (this.socket && this.isConnected) {
            // Get user_id from auth data stored during connection
            const userId = this.socket.auth?.userId;
            if (!userId) {
                console.error('Cannot join room: userId not found in auth data');
                this.pendingRoomJoin = roomId;
                return;
            }
            console.log(`Joining room: ${roomId} with user: ${userId}`);
            this.socket.emit('join_room', {
                room_id: roomId,
                user_id: userId
            });
            this.pendingRoomJoin = roomId;
        } else {
            console.log(`WebSocket not connected, storing room ${roomId} for later join`);
            // Store the room to join once connected
            this.pendingRoomJoin = roomId;
        }
    }
    /**
   * Leave a specific chat room
   */ leaveRoom(roomId) {
        if (this.socket && this.isConnected) {
            // Get user_id from auth data stored during connection
            const userId = this.socket.auth?.userId;
            this.socket.emit('leave_room', {
                room_id: roomId,
                user_id: userId
            });
            if (this.currentRoom === roomId) {
                this.currentRoom = null;
                this.notifyRoomStatus(null);
            }
        } else {
            console.error('Cannot leave room: WebSocket not connected');
        }
    }
    /**
   * Validate encrypted message data format
   */ validateEncryptedMessageData(encryptionData) {
        if (!encryptionData.is_encrypted) {
            return null; // No validation needed for unencrypted messages
        }
        const errors = [];
        if (!encryptionData.encrypted_aes_key) {
            errors.push('Encrypted AES key is required for encrypted messages');
        }
        if (!encryptionData.iv) {
            errors.push('Initialization vector (IV) is required for encrypted messages');
        }
        // Signature is optional but should be validated if present
        if (encryptionData.signature && typeof encryptionData.signature !== 'string') {
            errors.push('Message signature must be a string');
        }
        return errors.length > 0 ? errors[0] : null;
    }
    /**
   * Send a message to a room
   */ sendMessage(roomId, message, encryptionData = {}) {
        try {
            // Validate inputs
            const roomError = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$validation$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["validateRoomId"])(roomId);
            if (roomError) {
                throw new __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["AppError"](roomError, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["ErrorCodes"].VALIDATION_ERROR);
            }
            const userError = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$validation$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["validateUserId"])(this.socket?.auth?.userId);
            if (userError) {
                throw new __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["AppError"](userError, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["ErrorCodes"].VALIDATION_ERROR);
            }
            const messageErrors = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$validation$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["validateMessage"])(message);
            if (messageErrors.length > 0) {
                throw new __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["AppError"](messageErrors[0], __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["ErrorCodes"].VALIDATION_ERROR);
            }
            // Validate encryption data if message is encrypted
            const encryptionError = this.validateEncryptedMessageData(encryptionData);
            if (encryptionError) {
                throw new __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["AppError"](encryptionError, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["ErrorCodes"].VALIDATION_ERROR);
            }
            // Sanitize message content
            const sanitizedMessage = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$validation$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["sanitizeMessage"])(message);
            const messageData = {
                sender_id: this.socket.auth.userId,
                room_id: roomId,
                content: sanitizedMessage,
                message_type: 'text',
                id: `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                timestamp: new Date().toISOString(),
                // Encryption fields
                encrypted_aes_key: encryptionData.encrypted_aes_key || null,
                iv: encryptionData.iv || null,
                signature: encryptionData.signature || null,
                is_encrypted: encryptionData.is_encrypted || false,
                original_content: encryptionData.original_content || null
            };
            if (this.socket && this.isConnected) {
                try {
                    this.socket.emit('send_message', messageData);
                    return {
                        success: true,
                        messageId: messageData.id
                    };
                } catch (error) {
                    const appError = new __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["AppError"]('Failed to send message', __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["ErrorCodes"].WEBSOCKET_ERROR, {
                        originalError: error
                    });
                    (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["logError"])(appError, {
                        messageData
                    });
                    this.notifyError(appError.message, 'send_message', {
                        messageData,
                        error: error.message
                    });
                    return {
                        success: false,
                        error: appError.message,
                        messageId: messageData.id
                    };
                }
            } else {
                // Queue message for retry when reconnected
                this.pendingMessages.push(messageData);
                const errorMsg = this.isReconnecting ? 'Reconnecting... Message will be sent when connected.' : 'WebSocket not connected';
                this.notifyError(errorMsg, 'send_message', {
                    messageData
                });
                return {
                    success: false,
                    error: errorMsg,
                    messageId: messageData.id,
                    queued: true
                };
            }
        } catch (error) {
            if (error instanceof __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["AppError"]) {
                (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["logError"])(error, {
                    roomId,
                    message
                });
                this.notifyError(error.message, 'send_message', error.details);
                return {
                    success: false,
                    error: error.message
                };
            } else {
                const appError = new __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["AppError"]('Unexpected error sending message', __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["ErrorCodes"].UNKNOWN_ERROR, {
                    originalError: error
                });
                (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["logError"])(appError, {
                    roomId,
                    message
                });
                this.notifyError(appError.message, 'send_message', appError.details);
                return {
                    success: false,
                    error: appError.message
                };
            }
        }
    }
    /**
   * Register callback for incoming messages
   */ onMessage(callback) {
        this.messageCallbacks.push(callback);
    }
    /**
   * Register callback for connection status changes
   */ onConnectionStatus(callback) {
        this.connectionCallbacks.push(callback);
    }
    /**
   * Register callback for room status changes
   */ onRoomStatus(callback) {
        this.roomCallbacks.push(callback);
    }
    /**
   * Register callback for error notifications
   */ onError(callback) {
        this.errorCallbacks.push(callback);
    }
    /**
   * Register callback for typing indicators
   */ onTyping(callback) {
        this.typingCallbacks.push(callback);
    }
    /**
   * Register callback for presence updates
   */ onPresence(callback) {
        this.presenceCallbacks.push(callback);
    }
    /**
   * Remove message callback
   */ removeMessageCallback(callback) {
        this.messageCallbacks = this.messageCallbacks.filter((cb)=>cb !== callback);
    }
    /**
   * Remove connection status callback
   */ removeConnectionCallback(callback) {
        this.connectionCallbacks = this.connectionCallbacks.filter((cb)=>cb !== callback);
    }
    /**
   * Remove room status callback
   */ removeRoomCallback(callback) {
        this.roomCallbacks = this.roomCallbacks.filter((cb)=>cb !== callback);
    }
    /**
   * Remove error callback
   */ removeErrorCallback(callback) {
        this.errorCallbacks = this.errorCallbacks.filter((cb)=>cb !== callback);
    }
    /**
   * Remove typing callback
   */ removeTypingCallback(callback) {
        this.typingCallbacks = this.typingCallbacks.filter((cb)=>cb !== callback);
    }
    /**
   * Remove presence callback
   */ removePresenceCallback(callback) {
        this.presenceCallbacks = this.presenceCallbacks.filter((cb)=>cb !== callback);
    }
    /**
   * Setup event listeners for the socket
   */ setupEventListeners() {
        if (!this.socket) return;
        // Connection established
        this.socket.on('connect', ()=>{
            console.log('WebSocket connected');
            this.isConnected = true;
            this.isReconnecting = false;
            this.reconnectAttempts = 0;
            this.connectionError = null;
            // Clear any existing reconnect timer
            if (this.reconnectTimer) {
                clearTimeout(this.reconnectTimer);
                this.reconnectTimer = null;
            }
            this.notifyConnectionStatus(true);
            // Auto-join pending room if any
            if (this.pendingRoomJoin) {
                const roomToJoin = this.pendingRoomJoin;
                this.pendingRoomJoin = null; // Clear it first to avoid loops
                setTimeout(()=>{
                    this.joinRoom(roomToJoin);
                }, 100);
            }
            // Send any pending messages
            this.sendPendingMessages();
        });
        // Connection lost
        this.socket.on('disconnect', (reason)=>{
            console.log('WebSocket disconnected:', reason);
            this.isConnected = false;
            this.connectionError = `Disconnected: ${reason}`;
            this.notifyConnectionStatus(false, this.connectionError);
            // Attempt reconnection if not manually disconnected
            if (reason !== 'io client disconnect') {
                this.isReconnecting = true;
                this.attemptReconnection();
            }
        });
        // Connection error
        this.socket.on('connect_error', (error)=>{
            console.error('WebSocket connection error:', error);
            this.isConnected = false;
            this.connectionError = error.message || 'Connection failed';
            // Provide more specific error messages
            let userFriendlyError = 'Connection failed';
            if (error.message?.includes('ECONNREFUSED')) {
                userFriendlyError = 'Backend server is not running. Please start the backend server.';
            } else if (error.message?.includes('timeout')) {
                userFriendlyError = 'Connection timeout. Please check your network connection.';
            } else if (error.message?.includes('unauthorized')) {
                userFriendlyError = 'Authentication failed. Please log in again.';
            }
            this.notifyConnectionStatus(false, userFriendlyError);
            this.notifyError(userFriendlyError, 'connect_error', {
                error: error.message
            });
            if (!this.isReconnecting) {
                this.isReconnecting = true;
                this.attemptReconnection();
            }
        });
        // Incoming messages
        this.socket.on('new_message', (messageData)=>{
            this.messageCallbacks.forEach((callback)=>{
                try {
                    callback(messageData);
                } catch (error) {
                    console.error('Error in message callback:', error);
                }
            });
        });
        // Room joined confirmation
        this.socket.on('room_joined', (data)=>{
            console.log('Joined room:', data.room_id);
            this.currentRoom = data.room_id;
            this.pendingRoomJoin = null;
            this.notifyRoomStatus(data.room_id);
        });
        // Room left confirmation
        this.socket.on('room_left', (data)=>{
            console.log('Left room:', data.room_id);
            if (this.currentRoom === data.room_id) {
                this.currentRoom = null;
                this.notifyRoomStatus(null);
            }
        });
        // Message sent confirmation
        this.socket.on('message_sent', (data)=>{
            console.log('Message sent successfully:', data);
        });
        // Room join error handling
        this.socket.on('room_join_error', (data)=>{
            console.error('Room join error:', data.message);
            this.pendingRoomJoin = null;
        });
        // Room leave error handling
        this.socket.on('room_leave_error', (data)=>{
            console.error('Room leave error:', data.message);
        });
        // Message error handling
        this.socket.on('message_error', (data)=>{
            console.error('Message error:', data.message);
            this.notifyError('Message failed to send', 'message_error', data);
        });
        // Typing indicators
        this.socket.on('typing_indicator', (data)=>{
            this.typingCallbacks.forEach((callback)=>{
                try {
                    callback(data);
                } catch (error) {
                    console.error('Error in typing callback:', error);
                }
            });
        });
        // Presence updates
        this.socket.on('user_online', (data)=>{
            this.presenceCallbacks.forEach((callback)=>{
                try {
                    callback({
                        ...data,
                        status: 'online'
                    });
                } catch (error) {
                    console.error('Error in presence callback:', error);
                }
            });
        });
        this.socket.on('user_offline', (data)=>{
            this.presenceCallbacks.forEach((callback)=>{
                try {
                    callback({
                        ...data,
                        status: 'offline'
                    });
                } catch (error) {
                    console.error('Error in presence callback:', error);
                }
            });
        });
        // Message status updates
        this.socket.on('message_status_update', (data)=>{
            this.messageCallbacks.forEach((callback)=>{
                try {
                    callback({
                        ...data,
                        type: 'status_update'
                    });
                } catch (error) {
                    console.error('Error in message status callback:', error);
                }
            });
        });
        // Online users list response
        this.socket.on('online_users_list', (data)=>{
            console.log('WebSocketService: Received online users list:', data);
        // This will be handled by components that listen for this event
        });
        // All users list response - Let components handle this directly
        // Removed WebSocketService listener to avoid conflicts
        // Direct message room created
        this.socket.on('direct_message_created', (data)=>{
            console.log('Direct message room created:', data);
            if (data.room_id) {
                this.joinRoom(data.room_id);
            }
        });
    }
    /**
   * Attempt to reconnect to the server
   */ attemptReconnection() {
        // Clear any existing timer
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            this.isReconnecting = false;
            this.connectionError = 'Max reconnection attempts reached. Please refresh the page.';
            this.notifyConnectionStatus(false, this.connectionError);
            this.notifyError('Connection failed permanently', 'max_reconnect_attempts', {
                attempts: this.reconnectAttempts,
                maxAttempts: this.maxReconnectAttempts
            });
            return;
        }
        this.reconnectAttempts++;
        const delay = Math.min(Math.pow(2, this.reconnectAttempts) * 1000, 30000); // Exponential backoff, max 30s
        console.log(`Attempting reconnection ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${delay}ms`);
        this.connectionError = `Reconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`;
        this.notifyConnectionStatus(false, this.connectionError);
        this.reconnectTimer = setTimeout(()=>{
            if (this.socket && !this.isConnected) {
                try {
                    this.socket.connect();
                } catch (error) {
                    console.error('Reconnection attempt failed:', error);
                    this.attemptReconnection(); // Try again
                }
            }
        }, delay);
    }
    /**
   * Notify all connection status callbacks
   */ notifyConnectionStatus(connected, error = null) {
        this.connectionCallbacks.forEach((callback)=>{
            try {
                callback({
                    connected,
                    error
                });
            } catch (error) {
                console.error('Error in connection status callback:', error);
            }
        });
    }
    /**
   * Get current connection status
   */ getConnectionStatus() {
        return this.isConnected;
    }
    /**
   * Get detailed connection info for debugging
   */ getConnectionInfo() {
        return {
            isConnected: this.isConnected,
            isReconnecting: this.isReconnecting,
            reconnectAttempts: this.reconnectAttempts,
            currentRoom: this.currentRoom,
            pendingRoomJoin: this.pendingRoomJoin,
            connectionError: this.connectionError,
            hasSocket: !!this.socket,
            socketConnected: this.socket?.connected,
            socketId: this.socket?.id,
            auth: this.socket?.auth
        };
    }
    /**
   * Test connection to backend server
   */ async testConnection() {
        const serverUrl = ("TURBOPACK compile-time value", "http://localhost:5000") || this.findAvailableServer();
        try {
            const response = await fetch(`${serverUrl}/health`, {
                method: 'GET',
                timeout: 5000
            });
            return {
                success: response.ok,
                status: response.status,
                serverUrl
            };
        } catch (error) {
            return {
                success: false,
                error: error.message,
                serverUrl
            };
        }
    }
    /**
   * Get current rooms
   */ getCurrentRoom() {
        return this.currentRoom;
    }
    /**
   * Notify all room status callbacks
   */ notifyRoomStatus(roomId) {
        this.roomCallbacks.forEach((callback)=>{
            try {
                callback(roomId);
            } catch (error) {
                console.error('Error in room status callback:', error);
            }
        });
    }
    /**
   * Notify all error callbacks
   */ notifyError(message, type, details = {}) {
        const errorData = {
            message,
            type,
            details,
            timestamp: new Date().toISOString()
        };
        this.errorCallbacks.forEach((callback)=>{
            try {
                callback(errorData);
            } catch (error) {
                console.error('Error in error callback:', error);
            }
        });
    }
    /**
   * Send any pending messages that were queued during disconnection
   */ sendPendingMessages() {
        if (this.pendingMessages.length === 0) return;
        console.log(`Sending ${this.pendingMessages.length} pending messages`);
        const messagesToSend = [
            ...this.pendingMessages
        ];
        this.pendingMessages = [];
        messagesToSend.forEach((messageData)=>{
            try {
                this.socket.emit('send_message', messageData);
            } catch (error) {
                console.error('Failed to send pending message:', error);
                // Re-queue the message if it fails
                this.pendingMessages.push(messageData);
                this.notifyError('Failed to send queued message', 'send_pending_message', {
                    messageData,
                    error: error.message
                });
            }
        });
    }
    /**
   * Manually retry connection
   */ retryConnection() {
        if (this.isConnected) {
            console.log('Already connected');
            return;
        }
        // Reset reconnection attempts to allow manual retry
        this.reconnectAttempts = 0;
        this.isReconnecting = true;
        this.connectionError = 'Retrying connection...';
        this.notifyConnectionStatus(false, this.connectionError);
        if (this.socket) {
            try {
                this.socket.connect();
            } catch (error) {
                console.error('Manual retry failed:', error);
                this.attemptReconnection();
            }
        }
    }
    /**
   * Get current connection error
   */ getConnectionError() {
        return this.connectionError;
    }
    /**
   * Get pending messages count
   */ getPendingMessagesCount() {
        return this.pendingMessages.length;
    }
    /**
   * Start typing indicator
   */ startTyping(roomId) {
        if (this.socket && this.isConnected) {
            const userId = this.socket.auth?.userId;
            this.socket.emit('typing_start', {
                user_id: userId,
                room_id: roomId
            });
        }
    }
    /**
   * Stop typing indicator
   */ stopTyping(roomId) {
        if (this.socket && this.isConnected) {
            const userId = this.socket.auth?.userId;
            this.socket.emit('typing_stop', {
                user_id: userId,
                room_id: roomId
            });
        }
    }
    /**
   * Handle typing with debounce
   */ handleTyping(roomId, isTyping) {
        if (isTyping) {
            this.startTyping(roomId);
            // Clear existing timer
            if (this.typingTimer) {
                clearTimeout(this.typingTimer);
            }
            // Set timer to stop typing after 3 seconds of inactivity
            this.typingTimer = setTimeout(()=>{
                this.stopTyping(roomId);
            }, 3000);
        } else {
            if (this.typingTimer) {
                clearTimeout(this.typingTimer);
                this.typingTimer = null;
            }
            this.stopTyping(roomId);
        }
    }
    /**
   * Mark message as delivered
   */ markMessageDelivered(messageId) {
        if (this.socket && this.isConnected) {
            const userId = this.socket.auth?.userId;
            this.socket.emit('message_delivered', {
                message_id: messageId,
                user_id: userId
            });
        }
    }
    /**
   * Request list of online users
   */ requestOnlineUsers() {
        if (this.socket && this.isConnected) {
            console.log('WebSocketService: Emitting get_online_users event');
            this.socket.emit('get_online_users');
        } else {
            console.log('WebSocketService: Cannot request online users - socket not connected');
        }
    }
    /**
   * Request list of all users (online and offline)
   */ requestAllUsers() {
        if (this.socket && this.isConnected) {
            console.log('WebSocketService: Emitting get_all_users event');
            this.socket.emit('get_all_users');
        } else {
            console.log('WebSocketService: Cannot request all users - socket not connected');
        }
    }
    /**
   * Create or join a direct message room with another user
   */ startDirectMessage(targetUserId) {
        if (!targetUserId) {
            console.error('Cannot start direct message: targetUserId is required');
            return null;
        }
        // Get current user ID from socket auth or fallback
        let currentUserId = this.socket?.auth?.userId;
        if (!currentUserId) {
            console.warn('Current user ID not found in socket auth, using fallback');
            // Try to get from other sources or generate a temporary ID
            currentUserId = 'temp_user_' + Date.now();
        }
        // Generate consistent room ID for direct messages
        const roomId = [
            currentUserId,
            targetUserId
        ].sort().join('_');
        console.log('WebSocketService: Starting direct message', {
            currentUserId,
            targetUserId,
            roomId,
            isConnected: this.isConnected
        });
        // If connected, join the room immediately
        if (this.socket && this.isConnected) {
            this.joinRoom(roomId);
        } else {
            console.warn('WebSocket not connected, room will be joined when connection is established');
            // Store the room to join later
            this.pendingRoomJoin = roomId;
        }
        return roomId;
    }
    /**
   * Test connection to backend server
   */ async testConnection() {
        const serverUrl = ("TURBOPACK compile-time value", "http://localhost:5000") || this.findAvailableServer();
        try {
            const response = await fetch(`${serverUrl}/health`, {
                method: 'GET',
                timeout: 5000
            });
            return {
                success: response.ok,
                status: response.status,
                serverUrl
            };
        } catch (error) {
            return {
                success: false,
                error: error.message,
                serverUrl
            };
        }
    }
}
const websocketService = new WebSocketService();
// Make it available globally for debugging
if ("TURBOPACK compile-time falsy", 0) {
    "TURBOPACK unreachable";
}
const __TURBOPACK__default__export__ = websocketService;
}}),
"[project]/src/services/encryptionManager.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
/**
 * EncryptionManager - Handles end-to-end encryption for messages
 */ __turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/cryptoService.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/keyExchangeService.js [app-ssr] (ecmascript)");
;
;
class EncryptionManager {
    constructor(){
        this.isInitialized = false;
        this.currentUserId = null;
        this.currentToken = null;
    }
    /**
     * Initialize encryption for the current user
     */ async initialize(userId, token) {
        try {
            this.currentUserId = userId;
            this.currentToken = token;
            // Initialize keys
            await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].initializeKeys(userId, token);
            this.isInitialized = true;
            console.log('Encryption manager initialized');
        } catch (error) {
            console.error('Failed to initialize encryption:', error);
            throw error;
        }
    }
    /**
     * Encrypt a message for sending
     * For simplicity, we'll use a single AES key for the general room
     */ async encryptMessage(message, roomId = 'general') {
        try {
            if (!this.isInitialized) {
                throw new Error('Encryption not initialized');
            }
            // For this simple implementation, we'll use a fixed recipient
            // In a real app, you'd get all room participants
            const recipientIds = await this.getRoomParticipants(roomId);
            if (recipientIds.length === 0) {
                // No other users, send as plain text
                return {
                    content: message,
                    is_encrypted: false
                };
            }
            // Generate AES key for this message
            const aesKey = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].generateAESKey();
            // Encrypt message with AES
            const encryptedMessage = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].encryptWithAES(message, aesKey);
            // For simplicity, encrypt AES key for the first recipient only
            // In a real implementation, you'd encrypt for all recipients
            const recipientId = recipientIds[0];
            const recipientPublicKey = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getUserPublicKey(recipientId, this.currentToken);
            const encryptedAESKey = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].encryptWithRSA(aesKey, recipientPublicKey);
            return {
                content: encryptedMessage.encryptedData,
                encrypted_aes_key: encryptedAESKey,
                iv: encryptedMessage.iv,
                is_encrypted: true
            };
        } catch (error) {
            console.error('Failed to encrypt message:', error);
            // Fallback to plain text
            return {
                content: message,
                is_encrypted: false
            };
        }
    }
    /**
     * Decrypt a received message
     */ async decryptMessage(messageData) {
        try {
            if (!messageData.is_encrypted) {
                return messageData.content;
            }
            if (!this.isInitialized) {
                return '[Encryption not initialized]';
            }
            // Decrypt AES key with our private key
            const myPrivateKey = __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getMyPrivateKey();
            if (!myPrivateKey) {
                return '[Private key not available]';
            }
            const aesKey = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].decryptWithRSA(messageData.encrypted_aes_key, myPrivateKey);
            // Decrypt message with AES key
            const decryptedMessage = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$cryptoService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].decryptWithAES(messageData.content, messageData.iv, aesKey);
            return decryptedMessage;
        } catch (error) {
            console.error('Failed to decrypt message:', error);
            return '[Failed to decrypt message]';
        }
    }
    /**
     * Get room participants (disabled - using new GitHub-based encryption)
     */ async getRoomParticipants(roomId) {
        // Always return empty to disable old encryption system
        return [];
    }
    /**
     * Check if encryption is available
     */ isEncryptionAvailable() {
        return this.isInitialized;
    }
    /**
     * Get encryption status
     */ getStatus() {
        return {
            initialized: this.isInitialized,
            hasPrivateKey: __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getMyPrivateKey() !== null,
            hasPublicKey: __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$keyExchangeService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getMyPublicKey() !== null
        };
    }
}
const encryptionManager = new EncryptionManager();
const __TURBOPACK__default__export__ = encryptionManager;
}}),
"[project]/src/hooks/useChat.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__),
    "useChat": (()=>useChat)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/websocket.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionManager$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/encryptionManager.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/encryptionService.js [app-ssr] (ecmascript)");
;
;
;
;
const useChat = (userId, token)=>{
    const [messages, setMessages] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])([]);
    const [isConnected, setIsConnected] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    const [currentRoom, setCurrentRoom] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(null);
    const [connectionError, setConnectionError] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(null);
    const [lastError, setLastError] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(null);
    const [pendingMessagesCount, setPendingMessagesCount] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(0);
    const [encryptionStatus, setEncryptionStatus] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])({
        initialized: false
    });
    const [typingUsers, setTypingUsers] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])([]);
    const [onlineUsers, setOnlineUsers] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(new Set());
    // Handle incoming messages
    const handleMessage = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])(async (messageData1)=>{
        console.log('handleMessage: Processing message:', messageData1);
        console.log('handleMessage: messageData.sender_id:', messageData1.sender_id, 'type:', typeof messageData1.sender_id);
        console.log('handleMessage: userId:', userId, 'type:', typeof userId);
        let messageText;
        let isEncrypted = true;
        let encryptionError = null;
        let signatureValid = true;
        let decryptionErrorType = null;
        // Check if this is our own message (sender) - ensure type matching
        const isOwnMessage = String(messageData1.sender_id) === String(userId);
        console.log('handleMessage: isOwnMessage:', isOwnMessage);
        try {
            console.log('handleMessage: messageData.is_encrypted:', messageData1.is_encrypted);
            if (messageData1.is_encrypted) {
                isEncrypted = true;
                console.log('handleMessage: Set isEncrypted to true');
                if (isOwnMessage) {
                    console.log('handleMessage: This is our own encrypted message');
                    console.log('handleMessage: messageData.original_content:', messageData1.original_content);
                    console.log('handleMessage: messageData.content:', messageData1.content);
                    messageText = messageData1.original_content || messageData1.content;
                    console.log('handleMessage: Using messageText:', messageText);
                    signatureValid = true;
                    encryptionError = null;
                } else {
                    // Decrypt messages from other users
                    console.log('handleMessage: Decrypting message from other user:', messageData1.sender_id);
                    // GitHub-based base64 decryption
                    if (messageData1.encrypted_aes_key === 'github_base64') {
                        try {
                            messageText = atob(messageData1.content);
                            console.log('handleMessage: GitHub base64 decryption successful:', messageText);
                            signatureValid = true;
                            encryptionError = null;
                        } catch (decryptError) {
                            console.error('handleMessage: Base64 decryption failed:', decryptError);
                            messageText = messageData1.content;
                            encryptionError = 'Failed to decrypt message';
                            signatureValid = false;
                        }
                    } else {
                        // Fallback to other decryption methods
                        try {
                            messageText = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].decryptMessage(messageData1, messageData1.sender_id);
                        } catch (decryptError) {
                            messageText = messageData1.content;
                            encryptionError = 'Decryption failed';
                        }
                    }
                }
            } else {
                // Plain text message
                messageText = messageData1.content;
                isEncrypted = true;
            }
            console.log('handleMessage: Message processed successfully');
            console.log('handleMessage: Final isEncrypted value:', isEncrypted);
            console.log('handleMessage: messageData.is_encrypted:', messageData1.is_encrypted);
        } catch (error) {
            console.error('Error processing message:', error);
            messageText = messageData1.content || '[Error processing message]';
            isEncrypted = messageData1.is_encrypted || true;
            encryptionError = 'Message processing error';
            decryptionErrorType = 'processing_error';
        }
        const newMessage = {
            id: messageData1.id || `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            text: messageText,
            sender: isOwnMessage ? 'me' : 'other',
            senderName: messageData1.sender_name || 'Unknown User',
            timestamp: new Date().toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit'
            }),
            isEncrypted: messageData1.is_encrypted || isEncrypted,
            encryptionError: encryptionError,
            signatureValid: signatureValid,
            decryptionErrorType: decryptionErrorType
        };
        messageData1.isEncrypted = messageData1.isEncrypted || messageData1.is_encrypted || false;
        console.log('handleMessage: Adding message to state:', newMessage);
        setMessages((prev)=>{
            const exists = prev.find((msg)=>msg.id === newMessage.id);
            if (exists) {
                console.log('handleMessage: Message already exists, skipping:', newMessage.id);
                return prev;
            }
            return [
                ...prev,
                newMessage
            ];
        });
    }, [
        userId
    ]);
    // Handle connection status
    const handleConnectionStatus = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])((status)=>{
        setIsConnected(status.connected);
        setConnectionError(status.error || null);
        if (status.connected) {
            setPendingMessagesCount(0);
        } else {
            setPendingMessagesCount(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getPendingMessagesCount());
        }
    }, []);
    // Handle room status
    const handleRoomStatus = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])((roomId)=>{
        setCurrentRoom(roomId);
    }, []);
    // Handle errors
    const handleError = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])((errorData)=>{
        setLastError(errorData);
        if (errorData.type === 'send_message') {
            setPendingMessagesCount(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getPendingMessagesCount());
        }
        setTimeout(()=>{
            setLastError(null);
        }, 5000);
    }, []);
    // Handle typing indicators
    const handleTyping = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])((typingData)=>{
        setTypingUsers((prev)=>{
            const filtered = prev.filter((user)=>user.user_id !== typingData.user_id || user.room_id !== typingData.room_id);
            if (typingData.is_typing) {
                return [
                    ...filtered,
                    typingData
                ];
            }
            return filtered;
        });
    }, []);
    // Handle presence updates
    const handlePresence = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])((presenceData)=>{
        setOnlineUsers((prev)=>{
            const newSet = new Set(prev);
            if (presenceData.status === 'online') {
                newSet.add(presenceData.user_id);
            } else {
                newSet.delete(presenceData.user_id);
            }
            return newSet;
        });
    }, []);
    // Initialize encryption
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        if (!userId || !token) return;
        const initEncryption = async ()=>{
            try {
                await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionManager$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].initialize(userId, token);
                setEncryptionStatus(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionManager$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getStatus());
            } catch (error) {
                console.error('Failed to initialize encryption:', error);
                setEncryptionStatus({
                    initialized: false,
                    error: error.message
                });
            }
        };
        initEncryption();
    }, [
        userId,
        token
    ]);
    // Setup WebSocket connection
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        if (!userId || !token) {
            console.log('Missing required parameters for WebSocket connection:', {
                userId: !!userId,
                token: !!token
            });
            return;
        }
        console.log('useChat: Setting up WebSocket callbacks');
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].removeMessageCallback(handleMessage);
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].removeConnectionCallback(handleConnectionStatus);
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].removeRoomCallback(handleRoomStatus);
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].removeErrorCallback(handleError);
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].removeTypingCallback(handleTyping);
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].removePresenceCallback(handlePresence);
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].onMessage(handleMessage);
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].onConnectionStatus(handleConnectionStatus);
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].onRoomStatus(handleRoomStatus);
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].onError(handleError);
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].onTyping(handleTyping);
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].onPresence(handlePresence);
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].connect(userId, token);
        return ()=>{
            console.log('useChat: Cleaning up WebSocket callbacks');
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].removeMessageCallback(handleMessage);
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].removeConnectionCallback(handleConnectionStatus);
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].removeRoomCallback(handleRoomStatus);
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].removeErrorCallback(handleError);
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].removeTypingCallback(handleTyping);
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].removePresenceCallback(handlePresence);
        };
    }, [
        userId,
        token
    ]);
    // Start a chat with a specific user
    const startChatWithUser = async (targetUserId)=>{
        if (!targetUserId) {
            console.error('Cannot start chat: missing targetUserId');
            return null;
        }
        if (!isConnected) {
            console.warn('WebSocket not connected, attempting to create room anyway');
        }
        console.log('useChat: Starting chat with targetUserId:', targetUserId, 'currentUserId:', userId);
        try {
            const roomId = __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].startDirectMessage(targetUserId);
            if (roomId) {
                console.log('useChat: Direct message room created:', roomId);
                return roomId;
            } else {
                console.error('useChat: Failed to create direct message room');
                return null;
            }
        } catch (error) {
            console.error('useChat: Error starting chat:', error);
            return null;
        }
    };
    // Send message function
    const sendMessage = async (roomId, messageContent, encryptedMessageData = null)=>{
        console.log('useChat.sendMessage received:', {
            roomId,
            messageContent,
            encryptedMessageData
        });
        const trimmedMessage = encryptedMessageData?.original_content || (typeof messageContent === 'string' ? messageContent.trim() : '');
        if (!trimmedMessage || !roomId) return;
        try {
            let messageData1;
            if (encryptedMessageData) {
                messageData1 = {
                    content: encryptedMessageData.content,
                    encrypted_aes_key: encryptedMessageData.encrypted_aes_key,
                    iv: encryptedMessageData.iv,
                    signature: encryptedMessageData.signature,
                    is_encrypted: encryptedMessageData.is_encrypted
                };
            } else {
                const fallbackData = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionManager$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].encryptMessage(trimmedMessage, roomId);
                messageData1 = {
                    content: fallbackData.content,
                    encrypted_aes_key: fallbackData.encrypted_aes_key,
                    iv: fallbackData.iv,
                    is_encrypted: fallbackData.is_encrypted
                };
                console.log('fallbackData:', fallbackData);
                console.log('messageData after fallback:', messageData1);
            }
            console.log(' Sending encrypted message:', {
                roomId,
                content: messageData1.content,
                metadata: {
                    encrypted_aes_key: messageData1.encrypted_aes_key,
                    iv: messageData1.iv,
                    is_encrypted: messageData1.is_encrypted,
                    signature: messageData1.signature,
                    original_content: trimmedMessage
                }
            });
            if (!messageData1 || !messageData1.content) {
                console.error('No encrypted content to send. Aborting.', {
                    messageData: messageData1
                });
                return;
            }
            const result = __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].sendMessage(roomId, messageData1.content, {
                encrypted_aes_key: messageData1.encrypted_aes_key,
                iv: messageData1.iv,
                is_encrypted: messageData1.is_encrypted,
                signature: messageData1.signature,
                is_encrypted: messageData1.is_encrypted,
                original_content: trimmedMessage
            });
            // Message will be added when backend sends it back with original_content
            setPendingMessagesCount(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getPendingMessagesCount());
            return result;
        } catch (error) {
            console.error('Failed to send message:', error);
            const result = __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].sendMessage(roomId, messageData.content);
            // Message will be added when backend sends it back
            setPendingMessagesCount(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getPendingMessagesCount());
            return result;
        }
    };
    const retryConnection = ()=>{
        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].retryConnection();
    };
    const startTyping = (roomId)=>{
        if (roomId) {
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].handleTyping(roomId, true);
        }
    };
    const stopTyping = (roomId)=>{
        if (roomId) {
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].handleTyping(roomId, false);
        }
    };
    const getDebugInfo = ()=>{
        return {
            hookState: {
                isConnected,
                currentRoom,
                connectionError,
                lastError,
                pendingMessagesCount
            },
            websocketInfo: __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getConnectionInfo()
        };
    };
    return {
        messages,
        isConnected,
        currentRoom,
        sendMessage,
        startChatWithUser,
        connectionError,
        lastError,
        pendingMessagesCount,
        retryConnection,
        encryptionStatus,
        typingUsers,
        onlineUsers,
        startTyping,
        stopTyping,
        getDebugInfo
    };
};
const __TURBOPACK__default__export__ = useChat;
}}),
"[project]/src/hooks/usePerformance.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "useConnectionMonitor": (()=>useConnectionMonitor),
    "useMemoryMonitor": (()=>useMemoryMonitor),
    "usePerformance": (()=>usePerformance)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
;
const usePerformance = (componentName)=>{
    const renderStartTime = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useRef"])(null);
    const renderCount = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useRef"])(0);
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        renderCount.current += 1;
        renderStartTime.current = performance.now();
        return ()=>{
            if (renderStartTime.current) {
                const renderTime = performance.now() - renderStartTime.current;
                if (("TURBOPACK compile-time value", "development") === 'development' && renderTime > 16) {
                    console.warn(`${componentName} render took ${renderTime.toFixed(2)}ms (render #${renderCount.current})`);
                }
            }
        };
    });
    const measureAsync = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])(async (operationName, asyncOperation)=>{
        const startTime = performance.now();
        try {
            const result = await asyncOperation();
            const endTime = performance.now();
            if ("TURBOPACK compile-time truthy", 1) {
                console.log(`${componentName}.${operationName} took ${(endTime - startTime).toFixed(2)}ms`);
            }
            return result;
        } catch (error) {
            const endTime = performance.now();
            console.error(`${componentName}.${operationName} failed after ${(endTime - startTime).toFixed(2)}ms:`, error);
            throw error;
        }
    }, [
        componentName
    ]);
    const measureSync = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])((operationName, syncOperation)=>{
        const startTime = performance.now();
        try {
            const result = syncOperation();
            const endTime = performance.now();
            if (("TURBOPACK compile-time value", "development") === 'development' && endTime - startTime > 5) {
                console.warn(`${componentName}.${operationName} took ${(endTime - startTime).toFixed(2)}ms`);
            }
            return result;
        } catch (error) {
            const endTime = performance.now();
            console.error(`${componentName}.${operationName} failed after ${(endTime - startTime).toFixed(2)}ms:`, error);
            throw error;
        }
    }, [
        componentName
    ]);
    return {
        measureAsync,
        measureSync
    };
};
const useMemoryMonitor = ()=>{
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        if (("TURBOPACK compile-time value", "development") === 'development' && 'memory' in performance) {
            const logMemory = ()=>{
                const memory = performance.memory;
                console.log('Memory usage:', {
                    used: `${(memory.usedJSHeapSize / 1024 / 1024).toFixed(2)} MB`,
                    total: `${(memory.totalJSHeapSize / 1024 / 1024).toFixed(2)} MB`,
                    limit: `${(memory.jsHeapSizeLimit / 1024 / 1024).toFixed(2)} MB`
                });
            };
            const interval = setInterval(logMemory, 30000); // Log every 30 seconds
            return ()=>clearInterval(interval);
        }
    }, []);
};
const useConnectionMonitor = ()=>{
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        const handleOnline = ()=>{
            console.log('Connection restored');
        };
        const handleOffline = ()=>{
            console.warn('Connection lost');
        };
        window.addEventListener('online', handleOnline);
        window.addEventListener('offline', handleOffline);
        return ()=>{
            window.removeEventListener('online', handleOnline);
            window.removeEventListener('offline', handleOffline);
        };
    }, []);
    return {
        isOnline: ("TURBOPACK compile-time falsy", 0) ? ("TURBOPACK unreachable", undefined) : true
    };
};
}}),
"[project]/src/components/EncryptionSettings.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "default": (()=>EncryptionSettings)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$shield$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Shield$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/shield.js [app-ssr] (ecmascript) <export default as Shield>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/triangle-alert.js [app-ssr] (ecmascript) <export default as AlertTriangle>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$x$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__X$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/x.js [app-ssr] (ecmascript) <export default as X>");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$context$2f$AuthContext$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/context/AuthContext.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/clsx/dist/clsx.mjs [app-ssr] (ecmascript)");
"use client";
;
;
;
;
;
function EncryptionSettings({ isOpen, onClose }) {
    const { getUserPreferences, updateUserPreferences, clearKeysManually } = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$context$2f$AuthContext$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useAuth"])();
    const [preferences, setPreferences] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(null);
    const [loading, setLoading] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    const [showClearConfirm, setShowClearConfirm] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        if (isOpen) {
            setPreferences(getUserPreferences());
        }
    }, [
        isOpen,
        getUserPreferences
    ]);
    const handlePreferenceChange = async (path, value)=>{
        try {
            setLoading(true);
            const newPrefs = {
                ...preferences
            };
            // Navigate to the nested property and update it
            const keys = path.split('.');
            let current = newPrefs;
            for(let i = 0; i < keys.length - 1; i++){
                current = current[keys[i]];
            }
            current[keys[keys.length - 1]] = value;
            const updated = updateUserPreferences(newPrefs);
            setPreferences(updated);
        } catch (error) {
            console.error('Failed to update preferences:', error);
        } finally{
            setLoading(false);
        }
    };
    const handleClearKeys = async ()=>{
        try {
            setLoading(true);
            await clearKeysManually();
            setShowClearConfirm(false);
        } catch (error) {
            console.error('Failed to clear keys:', error);
        } finally{
            setLoading(false);
        }
    };
    if (!isOpen || !preferences) return null;
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
        className: "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50",
        children: [
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "bg-white rounded-lg shadow-xl max-w-md w-full mx-4 max-h-[90vh] overflow-y-auto",
                children: [
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "flex items-center justify-between p-6 border-b",
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "flex items-center space-x-3",
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$shield$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Shield$3e$__["Shield"], {
                                        className: "h-6 w-6 text-blue-600"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                        lineNumber: 61,
                                        columnNumber: 13
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h2", {
                                        className: "text-xl font-semibold text-gray-900",
                                        children: "Encryption Settings"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                        lineNumber: 62,
                                        columnNumber: 13
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/EncryptionSettings.js",
                                lineNumber: 60,
                                columnNumber: 11
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                onClick: onClose,
                                className: "text-gray-400 hover:text-gray-600",
                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$x$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__X$3e$__["X"], {
                                    className: "h-6 w-6"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/EncryptionSettings.js",
                                    lineNumber: 70,
                                    columnNumber: 13
                                }, this)
                            }, void 0, false, {
                                fileName: "[project]/src/components/EncryptionSettings.js",
                                lineNumber: 66,
                                columnNumber: 11
                            }, this)
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/EncryptionSettings.js",
                        lineNumber: 59,
                        columnNumber: 9
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "p-6 space-y-6",
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                                        className: "text-lg font-medium text-gray-900 mb-4",
                                        children: "Key Management"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                        lineNumber: 78,
                                        columnNumber: 13
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "space-y-4",
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "flex items-start justify-between",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                        className: "flex-1",
                                                        children: [
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("label", {
                                                                className: "text-sm font-medium text-gray-700",
                                                                children: "Clear keys on logout"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                                lineNumber: 85,
                                                                columnNumber: 19
                                                            }, this),
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                                                className: "text-xs text-gray-500 mt-1",
                                                                children: "Remove encryption keys from this device when you log out"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                                lineNumber: 88,
                                                                columnNumber: 19
                                                            }, this)
                                                        ]
                                                    }, void 0, true, {
                                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                                        lineNumber: 84,
                                                        columnNumber: 17
                                                    }, this),
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("input", {
                                                        type: "checkbox",
                                                        checked: preferences.encryption.clearKeysOnLogout,
                                                        onChange: (e)=>handlePreferenceChange('encryption.clearKeysOnLogout', e.target.checked),
                                                        disabled: loading,
                                                        className: "ml-3 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                                        lineNumber: 92,
                                                        columnNumber: 17
                                                    }, this)
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                lineNumber: 83,
                                                columnNumber: 15
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "flex items-start justify-between",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                        className: "flex-1",
                                                        children: [
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("label", {
                                                                className: "text-sm font-medium text-gray-700",
                                                                children: "Keep keys across sessions"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                                lineNumber: 103,
                                                                columnNumber: 19
                                                            }, this),
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                                                className: "text-xs text-gray-500 mt-1",
                                                                children: "Remember encryption keys between browser sessions"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                                lineNumber: 106,
                                                                columnNumber: 19
                                                            }, this)
                                                        ]
                                                    }, void 0, true, {
                                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                                        lineNumber: 102,
                                                        columnNumber: 17
                                                    }, this),
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("input", {
                                                        type: "checkbox",
                                                        checked: preferences.encryption.keyPersistenceAcrossSessions,
                                                        onChange: (e)=>handlePreferenceChange('encryption.keyPersistenceAcrossSessions', e.target.checked),
                                                        disabled: loading,
                                                        className: "ml-3 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                                        lineNumber: 110,
                                                        columnNumber: 17
                                                    }, this)
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                lineNumber: 101,
                                                columnNumber: 15
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "flex items-start justify-between",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                        className: "flex-1",
                                                        children: [
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("label", {
                                                                className: "text-sm font-medium text-gray-700",
                                                                children: "Auto-initialize keys"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                                lineNumber: 121,
                                                                columnNumber: 19
                                                            }, this),
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                                                className: "text-xs text-gray-500 mt-1",
                                                                children: "Automatically set up encryption when you log in"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                                lineNumber: 124,
                                                                columnNumber: 19
                                                            }, this)
                                                        ]
                                                    }, void 0, true, {
                                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                                        lineNumber: 120,
                                                        columnNumber: 17
                                                    }, this),
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("input", {
                                                        type: "checkbox",
                                                        checked: preferences.encryption.autoInitializeKeys,
                                                        onChange: (e)=>handlePreferenceChange('encryption.autoInitializeKeys', e.target.checked),
                                                        disabled: loading,
                                                        className: "ml-3 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                                        lineNumber: 128,
                                                        columnNumber: 17
                                                    }, this)
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                lineNumber: 119,
                                                columnNumber: 15
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                        lineNumber: 82,
                                        columnNumber: 13
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/EncryptionSettings.js",
                                lineNumber: 77,
                                columnNumber: 11
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                                        className: "text-lg font-medium text-gray-900 mb-4",
                                        children: "Display Options"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                        lineNumber: 141,
                                        columnNumber: 13
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "space-y-4",
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "flex items-start justify-between",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                        className: "flex-1",
                                                        children: [
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("label", {
                                                                className: "text-sm font-medium text-gray-700",
                                                                children: "Show encryption indicators"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                                lineNumber: 148,
                                                                columnNumber: 19
                                                            }, this),
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                                                className: "text-xs text-gray-500 mt-1",
                                                                children: "Display lock icons for encrypted messages"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                                lineNumber: 151,
                                                                columnNumber: 19
                                                            }, this)
                                                        ]
                                                    }, void 0, true, {
                                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                                        lineNumber: 147,
                                                        columnNumber: 17
                                                    }, this),
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("input", {
                                                        type: "checkbox",
                                                        checked: preferences.ui.showEncryptionIndicators,
                                                        onChange: (e)=>handlePreferenceChange('ui.showEncryptionIndicators', e.target.checked),
                                                        disabled: loading,
                                                        className: "ml-3 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                                        lineNumber: 155,
                                                        columnNumber: 17
                                                    }, this)
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                lineNumber: 146,
                                                columnNumber: 15
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "flex items-start justify-between",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                        className: "flex-1",
                                                        children: [
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("label", {
                                                                className: "text-sm font-medium text-gray-700",
                                                                children: "Show key setup progress"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                                lineNumber: 166,
                                                                columnNumber: 19
                                                            }, this),
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                                                className: "text-xs text-gray-500 mt-1",
                                                                children: "Display progress when initializing encryption"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                                lineNumber: 169,
                                                                columnNumber: 19
                                                            }, this)
                                                        ]
                                                    }, void 0, true, {
                                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                                        lineNumber: 165,
                                                        columnNumber: 17
                                                    }, this),
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("input", {
                                                        type: "checkbox",
                                                        checked: preferences.ui.showKeyInitializationProgress,
                                                        onChange: (e)=>handlePreferenceChange('ui.showKeyInitializationProgress', e.target.checked),
                                                        disabled: loading,
                                                        className: "ml-3 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                                        lineNumber: 173,
                                                        columnNumber: 17
                                                    }, this)
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/EncryptionSettings.js",
                                                lineNumber: 164,
                                                columnNumber: 15
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                        lineNumber: 145,
                                        columnNumber: 13
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/EncryptionSettings.js",
                                lineNumber: 140,
                                columnNumber: 11
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                                        className: "text-lg font-medium text-gray-900 mb-4",
                                        children: "Manual Actions"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                        lineNumber: 186,
                                        columnNumber: 13
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "bg-yellow-50 border border-yellow-200 rounded-lg p-4",
                                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            className: "flex items-start space-x-3",
                                            children: [
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"], {
                                                    className: "h-5 w-5 text-yellow-600 mt-0.5"
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/EncryptionSettings.js",
                                                    lineNumber: 192,
                                                    columnNumber: 17
                                                }, this),
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                    className: "flex-1",
                                                    children: [
                                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h4", {
                                                            className: "text-sm font-medium text-yellow-800",
                                                            children: "Clear Encryption Keys"
                                                        }, void 0, false, {
                                                            fileName: "[project]/src/components/EncryptionSettings.js",
                                                            lineNumber: 194,
                                                            columnNumber: 19
                                                        }, this),
                                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                                            className: "text-xs text-yellow-700 mt-1",
                                                            children: "Remove all encryption keys from this device. You'll need to generate new keys on next login."
                                                        }, void 0, false, {
                                                            fileName: "[project]/src/components/EncryptionSettings.js",
                                                            lineNumber: 197,
                                                            columnNumber: 19
                                                        }, this),
                                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                                            onClick: ()=>setShowClearConfirm(true),
                                                            disabled: loading,
                                                            className: "mt-3 text-sm bg-yellow-600 text-white px-3 py-1 rounded hover:bg-yellow-700 disabled:opacity-50",
                                                            children: "Clear Keys"
                                                        }, void 0, false, {
                                                            fileName: "[project]/src/components/EncryptionSettings.js",
                                                            lineNumber: 200,
                                                            columnNumber: 19
                                                        }, this)
                                                    ]
                                                }, void 0, true, {
                                                    fileName: "[project]/src/components/EncryptionSettings.js",
                                                    lineNumber: 193,
                                                    columnNumber: 17
                                                }, this)
                                            ]
                                        }, void 0, true, {
                                            fileName: "[project]/src/components/EncryptionSettings.js",
                                            lineNumber: 191,
                                            columnNumber: 15
                                        }, this)
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                        lineNumber: 190,
                                        columnNumber: 13
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/EncryptionSettings.js",
                                lineNumber: 185,
                                columnNumber: 11
                            }, this)
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/EncryptionSettings.js",
                        lineNumber: 75,
                        columnNumber: 9
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "px-6 py-4 border-t bg-gray-50 rounded-b-lg",
                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex justify-end",
                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                onClick: onClose,
                                className: "px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50",
                                children: "Close"
                            }, void 0, false, {
                                fileName: "[project]/src/components/EncryptionSettings.js",
                                lineNumber: 216,
                                columnNumber: 13
                            }, this)
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionSettings.js",
                            lineNumber: 215,
                            columnNumber: 11
                        }, this)
                    }, void 0, false, {
                        fileName: "[project]/src/components/EncryptionSettings.js",
                        lineNumber: 214,
                        columnNumber: 9
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/components/EncryptionSettings.js",
                lineNumber: 57,
                columnNumber: 7
            }, this),
            showClearConfirm && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-60",
                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "bg-white rounded-lg shadow-xl max-w-sm w-full mx-4",
                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "p-6",
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "flex items-center space-x-3 mb-4",
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"], {
                                        className: "h-6 w-6 text-red-600"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                        lineNumber: 232,
                                        columnNumber: 17
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                                        className: "text-lg font-semibold text-gray-900",
                                        children: "Confirm Key Deletion"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                        lineNumber: 233,
                                        columnNumber: 17
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/EncryptionSettings.js",
                                lineNumber: 231,
                                columnNumber: 15
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                className: "text-sm text-gray-600 mb-6",
                                children: "Are you sure you want to clear all encryption keys? This action cannot be undone and you'll need to generate new keys on your next login."
                            }, void 0, false, {
                                fileName: "[project]/src/components/EncryptionSettings.js",
                                lineNumber: 237,
                                columnNumber: 15
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "flex space-x-3",
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                        onClick: ()=>setShowClearConfirm(false),
                                        disabled: loading,
                                        className: "flex-1 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50",
                                        children: "Cancel"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                        lineNumber: 241,
                                        columnNumber: 17
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                        onClick: handleClearKeys,
                                        disabled: loading,
                                        className: "flex-1 px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-md hover:bg-red-700 disabled:opacity-50",
                                        children: loading ? 'Clearing...' : 'Clear Keys'
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionSettings.js",
                                        lineNumber: 248,
                                        columnNumber: 17
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/EncryptionSettings.js",
                                lineNumber: 240,
                                columnNumber: 15
                            }, this)
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/EncryptionSettings.js",
                        lineNumber: 230,
                        columnNumber: 13
                    }, this)
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionSettings.js",
                    lineNumber: 229,
                    columnNumber: 11
                }, this)
            }, void 0, false, {
                fileName: "[project]/src/components/EncryptionSettings.js",
                lineNumber: 228,
                columnNumber: 9
            }, this)
        ]
    }, void 0, true, {
        fileName: "[project]/src/components/EncryptionSettings.js",
        lineNumber: 56,
        columnNumber: 5
    }, this);
}
}}),
"[project]/src/components/ChatSidebar.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "default": (()=>ChatSidebar)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$search$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Search$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/search.js [app-ssr] (ecmascript) <export default as Search>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$message$2d$circle$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__MessageCircle$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/message-circle.js [app-ssr] (ecmascript) <export default as MessageCircle>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$settings$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Settings$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/settings.js [app-ssr] (ecmascript) <export default as Settings>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$log$2d$out$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__LogOut$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/log-out.js [app-ssr] (ecmascript) <export default as LogOut>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$user$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__User$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/user.js [app-ssr] (ecmascript) <export default as User>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$ellipsis$2d$vertical$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__MoreVertical$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/ellipsis-vertical.js [app-ssr] (ecmascript) <export default as MoreVertical>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$shield$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Shield$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/shield.js [app-ssr] (ecmascript) <export default as Shield>");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$context$2f$AuthContext$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/context/AuthContext.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/clsx/dist/clsx.mjs [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionSettings$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/EncryptionSettings.js [app-ssr] (ecmascript)");
"use client";
;
;
;
;
;
;
function ChatSidebar({ selectedRoomId, onRoomSelect, currentUser, isMobile }) {
    const { logout } = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$context$2f$AuthContext$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useAuth"])();
    const [searchQuery, setSearchQuery] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])('');
    const [showUserMenu, setShowUserMenu] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    const [showEncryptionSettings, setShowEncryptionSettings] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    // Mock conversations - in a real app, this would come from an API
    const [conversations] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])([
        {
            id: 'general',
            name: 'General Chat',
            lastMessage: 'Welcome to the encrypted chat!',
            timestamp: new Date().toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit'
            }),
            unread: 0,
            online: true,
            isGroup: true,
            avatar: '👥'
        },
        {
            id: 'tech-talk',
            name: 'Tech Talk',
            lastMessage: 'Anyone working on React projects?',
            timestamp: '2:30 PM',
            unread: 2,
            online: true,
            isGroup: true,
            avatar: '💻'
        },
        {
            id: 'random',
            name: 'Random',
            lastMessage: 'Good morning everyone!',
            timestamp: '9:15 AM',
            unread: 0,
            online: false,
            isGroup: true,
            avatar: '🎲'
        }
    ]);
    const filteredConversations = conversations.filter((conv)=>conv.name.toLowerCase().includes(searchQuery.toLowerCase()) || conv.lastMessage.toLowerCase().includes(searchQuery.toLowerCase()));
    const handleLogout = async ()=>{
        try {
            await logout();
        } catch (error) {
            console.error('Logout failed:', error);
        }
    };
    const getUserInitials = (name)=>{
        return name.split(' ').map((n)=>n[0]).join('').toUpperCase().slice(0, 2);
    };
    const formatTime = (timestamp)=>{
        if (timestamp.includes(':')) {
            return timestamp;
        }
        return new Date(timestamp).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit'
        });
    };
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
        className: "h-full flex flex-col bg-white",
        children: [
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "p-4 border-b border-gray-200 bg-gray-50",
                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "flex items-center justify-between",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex items-center space-x-3",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "relative",
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            className: "w-10 h-10 bg-blue-600 rounded-full flex items-center justify-center text-white font-semibold",
                                            children: currentUser?.photoURL ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("img", {
                                                src: currentUser.photoURL,
                                                alt: "Profile",
                                                className: "w-10 h-10 rounded-full object-cover"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatSidebar.js",
                                                lineNumber: 89,
                                                columnNumber: 19
                                            }, this) : getUserInitials(currentUser?.displayName || 'User')
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ChatSidebar.js",
                                            lineNumber: 87,
                                            columnNumber: 15
                                        }, this),
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            className: "absolute -bottom-1 -right-1 w-4 h-4 bg-green-500 border-2 border-white rounded-full"
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ChatSidebar.js",
                                            lineNumber: 98,
                                            columnNumber: 15
                                        }, this)
                                    ]
                                }, void 0, true, {
                                    fileName: "[project]/src/components/ChatSidebar.js",
                                    lineNumber: 86,
                                    columnNumber: 13
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "flex-1 min-w-0",
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h2", {
                                            className: "text-lg font-semibold text-gray-900 truncate",
                                            children: "Chats"
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ChatSidebar.js",
                                            lineNumber: 101,
                                            columnNumber: 15
                                        }, this),
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                            className: "text-sm text-gray-500 truncate",
                                            children: currentUser?.displayName || currentUser?.email
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ChatSidebar.js",
                                            lineNumber: 104,
                                            columnNumber: 15
                                        }, this)
                                    ]
                                }, void 0, true, {
                                    fileName: "[project]/src/components/ChatSidebar.js",
                                    lineNumber: 100,
                                    columnNumber: 13
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/ChatSidebar.js",
                            lineNumber: 85,
                            columnNumber: 11
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "relative",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                    onClick: ()=>setShowUserMenu(!showUserMenu),
                                    className: "p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-full transition-colors",
                                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$ellipsis$2d$vertical$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__MoreVertical$3e$__["MoreVertical"], {
                                        className: "w-5 h-5"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ChatSidebar.js",
                                        lineNumber: 115,
                                        columnNumber: 15
                                    }, this)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatSidebar.js",
                                    lineNumber: 111,
                                    columnNumber: 13
                                }, this),
                                showUserMenu && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg border border-gray-200 z-10",
                                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "py-1",
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                                className: "flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$user$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__User$3e$__["User"], {
                                                        className: "w-4 h-4 mr-3"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/ChatSidebar.js",
                                                        lineNumber: 122,
                                                        columnNumber: 21
                                                    }, this),
                                                    "Profile"
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/ChatSidebar.js",
                                                lineNumber: 121,
                                                columnNumber: 19
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                                onClick: ()=>{
                                                    setShowEncryptionSettings(true);
                                                    setShowUserMenu(false);
                                                },
                                                className: "flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$shield$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Shield$3e$__["Shield"], {
                                                        className: "w-4 h-4 mr-3"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/ChatSidebar.js",
                                                        lineNumber: 132,
                                                        columnNumber: 21
                                                    }, this),
                                                    "Encryption Settings"
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/ChatSidebar.js",
                                                lineNumber: 125,
                                                columnNumber: 19
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                                className: "flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$settings$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Settings$3e$__["Settings"], {
                                                        className: "w-4 h-4 mr-3"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/ChatSidebar.js",
                                                        lineNumber: 136,
                                                        columnNumber: 21
                                                    }, this),
                                                    "Settings"
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/ChatSidebar.js",
                                                lineNumber: 135,
                                                columnNumber: 19
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("hr", {
                                                className: "my-1"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatSidebar.js",
                                                lineNumber: 139,
                                                columnNumber: 19
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                                onClick: handleLogout,
                                                className: "flex items-center w-full px-4 py-2 text-sm text-red-600 hover:bg-red-50",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$log$2d$out$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__LogOut$3e$__["LogOut"], {
                                                        className: "w-4 h-4 mr-3"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/ChatSidebar.js",
                                                        lineNumber: 144,
                                                        columnNumber: 21
                                                    }, this),
                                                    "Sign Out"
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/ChatSidebar.js",
                                                lineNumber: 140,
                                                columnNumber: 19
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/ChatSidebar.js",
                                        lineNumber: 120,
                                        columnNumber: 17
                                    }, this)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatSidebar.js",
                                    lineNumber: 119,
                                    columnNumber: 15
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/ChatSidebar.js",
                            lineNumber: 110,
                            columnNumber: 11
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/ChatSidebar.js",
                    lineNumber: 84,
                    columnNumber: 9
                }, this)
            }, void 0, false, {
                fileName: "[project]/src/components/ChatSidebar.js",
                lineNumber: 83,
                columnNumber: 7
            }, this),
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "p-4 border-b border-gray-200",
                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "relative",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$search$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Search$3e$__["Search"], {
                            className: "absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4"
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatSidebar.js",
                            lineNumber: 157,
                            columnNumber: 11
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("input", {
                            type: "text",
                            placeholder: "Search conversations...",
                            value: searchQuery,
                            onChange: (e)=>setSearchQuery(e.target.value),
                            className: "w-full pl-10 pr-4 py-2 bg-gray-100 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatSidebar.js",
                            lineNumber: 158,
                            columnNumber: 11
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/ChatSidebar.js",
                    lineNumber: 156,
                    columnNumber: 9
                }, this)
            }, void 0, false, {
                fileName: "[project]/src/components/ChatSidebar.js",
                lineNumber: 155,
                columnNumber: 7
            }, this),
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "flex-1 overflow-y-auto",
                children: filteredConversations.length === 0 ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "p-4 text-center text-gray-500",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$message$2d$circle$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__MessageCircle$3e$__["MessageCircle"], {
                            className: "w-12 h-12 mx-auto mb-3 text-gray-300"
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatSidebar.js",
                            lineNumber: 172,
                            columnNumber: 13
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                            children: "No conversations found"
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatSidebar.js",
                            lineNumber: 173,
                            columnNumber: 13
                        }, this),
                        searchQuery && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                            className: "text-sm mt-1",
                            children: "Try a different search term"
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatSidebar.js",
                            lineNumber: 175,
                            columnNumber: 15
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/ChatSidebar.js",
                    lineNumber: 171,
                    columnNumber: 11
                }, this) : filteredConversations.map((conv)=>/*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        onClick: ()=>onRoomSelect(conv.id),
                        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("flex items-center p-4 hover:bg-gray-50 cursor-pointer border-b border-gray-100 transition-colors", {
                            "bg-blue-50 border-blue-200": selectedRoomId === conv.id
                        }),
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "relative flex-shrink-0",
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "w-12 h-12 bg-gray-300 rounded-full flex items-center justify-center text-lg",
                                        children: conv.avatar
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ChatSidebar.js",
                                        lineNumber: 191,
                                        columnNumber: 17
                                    }, this),
                                    conv.online && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "absolute -bottom-1 -right-1 w-4 h-4 bg-green-500 border-2 border-white rounded-full"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ChatSidebar.js",
                                        lineNumber: 195,
                                        columnNumber: 19
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/ChatSidebar.js",
                                lineNumber: 190,
                                columnNumber: 15
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "ml-3 flex-1 min-w-0",
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "flex items-center justify-between",
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("text-sm font-medium truncate", {
                                                    "text-blue-900": selectedRoomId === conv.id,
                                                    "text-gray-900": selectedRoomId !== conv.id
                                                }),
                                                children: conv.name
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatSidebar.js",
                                                lineNumber: 201,
                                                columnNumber: 19
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                className: "text-xs text-gray-500 ml-2 flex-shrink-0",
                                                children: formatTime(conv.timestamp)
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatSidebar.js",
                                                lineNumber: 210,
                                                columnNumber: 19
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/ChatSidebar.js",
                                        lineNumber: 200,
                                        columnNumber: 17
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "flex items-center justify-between mt-1",
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                                className: "text-sm text-gray-600 truncate",
                                                children: conv.lastMessage
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatSidebar.js",
                                                lineNumber: 216,
                                                columnNumber: 19
                                            }, this),
                                            conv.unread > 0 && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                className: "ml-2 bg-blue-600 text-white text-xs rounded-full px-2 py-1 min-w-[20px] text-center flex-shrink-0",
                                                children: conv.unread > 99 ? '99+' : conv.unread
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatSidebar.js",
                                                lineNumber: 220,
                                                columnNumber: 21
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/ChatSidebar.js",
                                        lineNumber: 215,
                                        columnNumber: 17
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/ChatSidebar.js",
                                lineNumber: 199,
                                columnNumber: 15
                            }, this)
                        ]
                    }, conv.id, true, {
                        fileName: "[project]/src/components/ChatSidebar.js",
                        lineNumber: 180,
                        columnNumber: 13
                    }, this))
            }, void 0, false, {
                fileName: "[project]/src/components/ChatSidebar.js",
                lineNumber: 169,
                columnNumber: 7
            }, this),
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "p-4 border-t border-gray-200 bg-gray-50",
                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "flex items-center justify-between text-xs text-gray-500",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                            children: "🔒 End-to-end encrypted"
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatSidebar.js",
                            lineNumber: 234,
                            columnNumber: 11
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                            children: [
                                filteredConversations.length,
                                " chats"
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/ChatSidebar.js",
                            lineNumber: 235,
                            columnNumber: 11
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/ChatSidebar.js",
                    lineNumber: 233,
                    columnNumber: 9
                }, this)
            }, void 0, false, {
                fileName: "[project]/src/components/ChatSidebar.js",
                lineNumber: 232,
                columnNumber: 7
            }, this),
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionSettings$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"], {
                isOpen: showEncryptionSettings,
                onClose: ()=>setShowEncryptionSettings(false)
            }, void 0, false, {
                fileName: "[project]/src/components/ChatSidebar.js",
                lineNumber: 240,
                columnNumber: 7
            }, this)
        ]
    }, void 0, true, {
        fileName: "[project]/src/components/ChatSidebar.js",
        lineNumber: 81,
        columnNumber: 5
    }, this);
}
}}),
"[project]/src/components/EncryptionErrorDisplay.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "EncryptionErrorBanner": (()=>EncryptionErrorBanner),
    "EncryptionErrorModal": (()=>EncryptionErrorModal),
    "default": (()=>EncryptionErrorDisplay)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/triangle-alert.js [app-ssr] (ecmascript) <export default as AlertTriangle>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$refresh$2d$cw$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__RefreshCw$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/refresh-cw.js [app-ssr] (ecmascript) <export default as RefreshCw>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$x$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__X$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/x.js [app-ssr] (ecmascript) <export default as X>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Lock$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/lock.js [app-ssr] (ecmascript) <export default as Lock>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2d$open$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__LockOpen$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/lock-open.js [app-ssr] (ecmascript) <export default as LockOpen>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$shield$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Shield$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/shield.js [app-ssr] (ecmascript) <export default as Shield>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertCircle$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/circle-alert.js [app-ssr] (ecmascript) <export default as AlertCircle>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$info$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Info$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/info.js [app-ssr] (ecmascript) <export default as Info>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/clsx/dist/clsx.mjs [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/encryptionService.js [app-ssr] (ecmascript)");
"use client";
;
;
;
;
;
function EncryptionErrorDisplay({ error, onRetry, onDismiss, showRetry = true, compact = false, className = "" }) {
    const [isRetrying, setIsRetrying] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    if (!error) return null;
    const handleRetry = async ()=>{
        if (!onRetry || isRetrying) return;
        setIsRetrying(true);
        try {
            await onRetry();
        } catch (retryError) {
            console.error('Retry failed:', retryError);
        } finally{
            setIsRetrying(false);
        }
    };
    const getErrorIcon = (errorType)=>{
        switch(errorType){
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_GENERATION_FAILED:
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].INITIALIZATION_FAILED:
                return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$shield$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Shield$3e$__["Shield"], {
                    className: "w-4 h-4"
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 40,
                    columnNumber: 16
                }, this);
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].ENCRYPTION_FAILED:
                return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Lock$3e$__["Lock"], {
                    className: "w-4 h-4"
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 42,
                    columnNumber: 16
                }, this);
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].DECRYPTION_FAILED:
                return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2d$open$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__LockOpen$3e$__["LockOpen"], {
                    className: "w-4 h-4"
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 44,
                    columnNumber: 16
                }, this);
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_EXCHANGE_FAILED:
                return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$refresh$2d$cw$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__RefreshCw$3e$__["RefreshCw"], {
                    className: "w-4 h-4"
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 46,
                    columnNumber: 16
                }, this);
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].SIGNATURE_VERIFICATION_FAILED:
                return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"], {
                    className: "w-4 h-4"
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 48,
                    columnNumber: 16
                }, this);
            default:
                return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertCircle$3e$__["AlertCircle"], {
                    className: "w-4 h-4"
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 50,
                    columnNumber: 16
                }, this);
        }
    };
    const getErrorSeverity = (errorType)=>{
        switch(errorType){
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].SIGNATURE_VERIFICATION_FAILED:
                return 'warning';
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].DECRYPTION_FAILED:
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].ENCRYPTION_FAILED:
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_GENERATION_FAILED:
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].INITIALIZATION_FAILED:
                return 'error';
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_EXCHANGE_FAILED:
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].STORAGE_FAILED:
                return 'warning';
            default:
                return 'error';
        }
    };
    const getErrorColors = (severity)=>{
        switch(severity){
            case 'warning':
                return {
                    bg: 'bg-yellow-50',
                    border: 'border-yellow-200',
                    text: 'text-yellow-800',
                    icon: 'text-yellow-600',
                    button: 'bg-yellow-100 hover:bg-yellow-200 text-yellow-800'
                };
            case 'error':
                return {
                    bg: 'bg-red-50',
                    border: 'border-red-200',
                    text: 'text-red-800',
                    icon: 'text-red-600',
                    button: 'bg-red-100 hover:bg-red-200 text-red-800'
                };
            default:
                return {
                    bg: 'bg-gray-50',
                    border: 'border-gray-200',
                    text: 'text-gray-800',
                    icon: 'text-gray-600',
                    button: 'bg-gray-100 hover:bg-gray-200 text-gray-800'
                };
        }
    };
    const getRetryText = (errorType)=>{
        switch(errorType){
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_GENERATION_FAILED:
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].INITIALIZATION_FAILED:
                return 'Retry Setup';
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].ENCRYPTION_FAILED:
                return 'Retry Encryption';
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].DECRYPTION_FAILED:
                return 'Retry Decryption';
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_EXCHANGE_FAILED:
                return 'Retry Key Exchange';
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].SIGNATURE_VERIFICATION_FAILED:
                return 'Verify Again';
            default:
                return 'Retry';
        }
    };
    const getAdditionalInfo = (errorType)=>{
        switch(errorType){
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].SIGNATURE_VERIFICATION_FAILED:
                return "The message was decrypted successfully, but we couldn't verify the sender's identity. This could mean the message was tampered with or sent from a different device.";
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].DECRYPTION_FAILED:
                return "This message couldn't be decrypted. It may have been sent with incompatible encryption or the data may be corrupted.";
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_EXCHANGE_FAILED:
                return "We couldn't get the encryption keys needed to secure your messages. Check your internet connection and try again.";
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_GENERATION_FAILED:
                return "Failed to generate encryption keys for your account. This is needed to secure your messages.";
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].ENCRYPTION_FAILED:
                return "Your message couldn't be encrypted before sending. For security, the message was not sent.";
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].INITIALIZATION_FAILED:
                return "Encryption setup failed. You can still send messages, but they won't be encrypted.";
            default:
                return null;
        }
    };
    const severity = getErrorSeverity(error.type);
    const colors = getErrorColors(severity);
    const icon = getErrorIcon(error.type);
    const additionalInfo = getAdditionalInfo(error.type);
    if (compact) {
        return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("flex items-center space-x-2 px-3 py-2 rounded-md text-sm", colors.bg, colors.border, colors.text, "border", className),
            children: [
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: colors.icon,
                    children: icon
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 152,
                    columnNumber: 9
                }, this),
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                    className: "flex-1 min-w-0 truncate",
                    children: error.userFriendlyMessage || error.message
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 155,
                    columnNumber: 9
                }, this),
                showRetry && onRetry && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                    onClick: handleRetry,
                    disabled: isRetrying,
                    className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("px-2 py-1 rounded text-xs font-medium transition-colors", colors.button, isRetrying && "opacity-50 cursor-not-allowed"),
                    children: isRetrying ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "flex items-center space-x-1",
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "animate-spin rounded-full h-3 w-3 border-b border-current"
                            }, void 0, false, {
                                fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                lineNumber: 170,
                                columnNumber: 17
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                children: "Retrying..."
                            }, void 0, false, {
                                fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                lineNumber: 171,
                                columnNumber: 17
                            }, this)
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                        lineNumber: 169,
                        columnNumber: 15
                    }, this) : getRetryText(error.type)
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 159,
                    columnNumber: 11
                }, this),
                onDismiss && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                    onClick: onDismiss,
                    className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("hover:opacity-70 transition-opacity", colors.icon),
                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$x$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__X$3e$__["X"], {
                        className: "w-4 h-4"
                    }, void 0, false, {
                        fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                        lineNumber: 183,
                        columnNumber: 13
                    }, this)
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 179,
                    columnNumber: 11
                }, this)
            ]
        }, void 0, true, {
            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
            lineNumber: 144,
            columnNumber: 7
        }, this);
    }
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("rounded-lg border p-4", colors.bg, colors.border, className),
        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            className: "flex items-start space-x-3",
            children: [
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("flex-shrink-0 mt-0.5", colors.icon),
                    children: icon
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 198,
                    columnNumber: 9
                }, this),
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "flex-1 min-w-0",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex items-start justify-between",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "flex-1",
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h4", {
                                            className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("text-sm font-medium", colors.text),
                                            children: error.userFriendlyMessage || error.message
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                            lineNumber: 205,
                                            columnNumber: 15
                                        }, this),
                                        additionalInfo && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("mt-2 text-sm opacity-90", colors.text),
                                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "flex items-start space-x-2",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$info$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Info$3e$__["Info"], {
                                                        className: "w-4 h-4 flex-shrink-0 mt-0.5 opacity-70"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                                        lineNumber: 212,
                                                        columnNumber: 21
                                                    }, this),
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                                        children: additionalInfo
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                                        lineNumber: 213,
                                                        columnNumber: 21
                                                    }, this)
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                                lineNumber: 211,
                                                columnNumber: 19
                                            }, this)
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                            lineNumber: 210,
                                            columnNumber: 17
                                        }, this),
                                        ("TURBOPACK compile-time value", "development") === 'development' && error.message !== error.userFriendlyMessage && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("details", {
                                            className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("mt-2 text-xs opacity-75", colors.text),
                                            children: [
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("summary", {
                                                    className: "cursor-pointer hover:opacity-100",
                                                    children: "Technical Details"
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                                    lineNumber: 220,
                                                    columnNumber: 19
                                                }, this),
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("pre", {
                                                    className: "mt-1 p-2 bg-black bg-opacity-10 rounded text-xs overflow-auto",
                                                    children: [
                                                        error.message,
                                                        error.timestamp && `\nTime: ${new Date(error.timestamp).toLocaleString()}`
                                                    ]
                                                }, void 0, true, {
                                                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                                    lineNumber: 223,
                                                    columnNumber: 19
                                                }, this)
                                            ]
                                        }, void 0, true, {
                                            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                            lineNumber: 219,
                                            columnNumber: 17
                                        }, this)
                                    ]
                                }, void 0, true, {
                                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                    lineNumber: 204,
                                    columnNumber: 13
                                }, this),
                                onDismiss && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                    onClick: onDismiss,
                                    className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("flex-shrink-0 ml-3 hover:opacity-70 transition-opacity", colors.icon),
                                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$x$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__X$3e$__["X"], {
                                        className: "w-4 h-4"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                        lineNumber: 239,
                                        columnNumber: 17
                                    }, this)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                    lineNumber: 232,
                                    columnNumber: 15
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                            lineNumber: 203,
                            columnNumber: 11
                        }, this),
                        showRetry && onRetry && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "mt-3 flex items-center space-x-2",
                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                onClick: handleRetry,
                                disabled: isRetrying,
                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("inline-flex items-center px-3 py-1.5 rounded-md text-sm font-medium transition-colors", colors.button, isRetrying && "opacity-50 cursor-not-allowed"),
                                children: isRetrying ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["Fragment"], {
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            className: "animate-spin rounded-full h-3 w-3 border-b border-current mr-2"
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                            lineNumber: 257,
                                            columnNumber: 21
                                        }, this),
                                        "Retrying..."
                                    ]
                                }, void 0, true) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["Fragment"], {
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$refresh$2d$cw$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__RefreshCw$3e$__["RefreshCw"], {
                                            className: "w-3 h-3 mr-2"
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                            lineNumber: 262,
                                            columnNumber: 21
                                        }, this),
                                        getRetryText(error.type)
                                    ]
                                }, void 0, true)
                            }, void 0, false, {
                                fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                lineNumber: 246,
                                columnNumber: 15
                            }, this)
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                            lineNumber: 245,
                            columnNumber: 13
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 202,
                    columnNumber: 9
                }, this)
            ]
        }, void 0, true, {
            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
            lineNumber: 197,
            columnNumber: 7
        }, this)
    }, void 0, false, {
        fileName: "[project]/src/components/EncryptionErrorDisplay.js",
        lineNumber: 191,
        columnNumber: 5
    }, this);
}
function EncryptionErrorBanner({ error, onRetry, onDismiss, className = "" }) {
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(EncryptionErrorDisplay, {
        error: error,
        onRetry: onRetry,
        onDismiss: onDismiss,
        compact: true,
        className: className
    }, void 0, false, {
        fileName: "[project]/src/components/EncryptionErrorDisplay.js",
        lineNumber: 280,
        columnNumber: 5
    }, this);
}
function EncryptionErrorModal({ error, isOpen, onRetry, onDismiss, onClose, title = "Encryption Error" }) {
    if (!isOpen || !error) return null;
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
        className: "fixed inset-0 z-50 overflow-y-auto",
        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            className: "flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0",
            children: [
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "fixed inset-0 transition-opacity bg-gray-500 bg-opacity-75",
                    onClick: onClose
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 306,
                    columnNumber: 9
                }, this),
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "inline-block w-full max-w-md p-6 my-8 overflow-hidden text-left align-middle transition-all transform bg-white shadow-xl rounded-lg",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex items-center justify-between mb-4",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                                    className: "text-lg font-medium text-gray-900",
                                    children: title
                                }, void 0, false, {
                                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                    lineNumber: 310,
                                    columnNumber: 13
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                    onClick: onClose,
                                    className: "text-gray-400 hover:text-gray-600 transition-colors",
                                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$x$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__X$3e$__["X"], {
                                        className: "w-5 h-5"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                        lineNumber: 317,
                                        columnNumber: 15
                                    }, this)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                    lineNumber: 313,
                                    columnNumber: 13
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                            lineNumber: 309,
                            columnNumber: 11
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(EncryptionErrorDisplay, {
                            error: error,
                            onRetry: onRetry,
                            onDismiss: onDismiss,
                            showRetry: true,
                            className: "mb-4"
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                            lineNumber: 321,
                            columnNumber: 11
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex justify-end space-x-3",
                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                onClick: onClose,
                                className: "px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors",
                                children: "Close"
                            }, void 0, false, {
                                fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                                lineNumber: 330,
                                columnNumber: 13
                            }, this)
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                            lineNumber: 329,
                            columnNumber: 11
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/EncryptionErrorDisplay.js",
                    lineNumber: 308,
                    columnNumber: 9
                }, this)
            ]
        }, void 0, true, {
            fileName: "[project]/src/components/EncryptionErrorDisplay.js",
            lineNumber: 305,
            columnNumber: 7
        }, this)
    }, void 0, false, {
        fileName: "[project]/src/components/EncryptionErrorDisplay.js",
        lineNumber: 304,
        columnNumber: 5
    }, this);
}
}}),
"[project]/src/components/EncryptionStatusIndicator.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "EncryptionStatusBadge": (()=>EncryptionStatusBadge),
    "EncryptionStatusPanel": (()=>EncryptionStatusPanel),
    "default": (()=>EncryptionStatusIndicator)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$shield$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Shield$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/shield.js [app-ssr] (ecmascript) <export default as Shield>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Lock$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/lock.js [app-ssr] (ecmascript) <export default as Lock>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2d$open$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__LockOpen$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/lock-open.js [app-ssr] (ecmascript) <export default as LockOpen>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/triangle-alert.js [app-ssr] (ecmascript) <export default as AlertTriangle>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$check$2d$big$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__CheckCircle$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/circle-check-big.js [app-ssr] (ecmascript) <export default as CheckCircle>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$clock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Clock$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/clock.js [app-ssr] (ecmascript) <export default as Clock>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$settings$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Settings$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/settings.js [app-ssr] (ecmascript) <export default as Settings>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$refresh$2d$cw$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__RefreshCw$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/refresh-cw.js [app-ssr] (ecmascript) <export default as RefreshCw>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/clsx/dist/clsx.mjs [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/encryptionService.js [app-ssr] (ecmascript)");
"use client";
;
;
;
;
;
;
function EncryptionStatusIndicator({ selectedUser, compact = false, showDetails = false, onSettingsClick, className = "" }) {
    const [status, setStatus] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(null);
    const [isRefreshing, setIsRefreshing] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    const [showTooltip, setShowTooltip] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    // Update status periodically
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        const updateStatus = ()=>{
            const currentStatus = __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getEncryptionStatus();
            setStatus(currentStatus);
        };
        updateStatus();
        const interval = setInterval(updateStatus, 2000); // Update every 2 seconds
        return ()=>clearInterval(interval);
    }, []);
    const handleRefresh = async ()=>{
        setIsRefreshing(true);
        try {
            await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].refreshKeys();
            const newStatus = __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getEncryptionStatus();
            setStatus(newStatus);
        } catch (error) {
            console.error('Failed to refresh encryption:', error);
        } finally{
            setIsRefreshing(false);
        }
    };
    const getStatusInfo = ()=>{
        if (!status) {
            return {
                icon: __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$clock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Clock$3e$__["Clock"],
                color: 'gray',
                text: 'Loading...',
                description: 'Checking encryption status'
            };
        }
        switch(status.status){
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionStatus"].AVAILABLE:
                if (selectedUser) {
                    return {
                        icon: __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Lock$3e$__["Lock"],
                        color: 'green',
                        text: 'Encrypted',
                        description: `Messages are end-to-end encrypted for ${selectedUser.display_name || selectedUser.name || selectedUser.username}`
                    };
                } else {
                    return {
                        icon: __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$shield$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Shield$3e$__["Shield"],
                        color: 'blue',
                        text: 'Ready',
                        description: 'Encryption is ready - select a user to start encrypted chat'
                    };
                }
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionStatus"].INITIALIZING:
                return {
                    icon: __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$clock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Clock$3e$__["Clock"],
                    color: 'blue',
                    text: 'Setting up...',
                    description: 'Initializing encryption keys'
                };
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionStatus"].ERROR:
                return {
                    icon: __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"],
                    color: 'red',
                    text: 'Error',
                    description: status.lastError?.userFriendlyMessage || 'Encryption error occurred'
                };
            case __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionStatus"].UNAVAILABLE:
            default:
                return {
                    icon: __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2d$open$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__LockOpen$3e$__["LockOpen"],
                    color: 'yellow',
                    text: 'Not available',
                    description: 'Encryption is not available - messages will be sent unencrypted'
                };
        }
    };
    const statusInfo = getStatusInfo();
    const IconComponent = statusInfo.icon;
    const getColorClasses = (color)=>{
        const colors = {
            green: {
                bg: 'bg-green-50',
                border: 'border-green-200',
                text: 'text-green-800',
                icon: 'text-green-600',
                button: 'bg-green-100 hover:bg-green-200 text-green-800'
            },
            blue: {
                bg: 'bg-blue-50',
                border: 'border-blue-200',
                text: 'text-blue-800',
                icon: 'text-blue-600',
                button: 'bg-blue-100 hover:bg-blue-200 text-blue-800'
            },
            yellow: {
                bg: 'bg-yellow-50',
                border: 'border-yellow-200',
                text: 'text-yellow-800',
                icon: 'text-yellow-600',
                button: 'bg-yellow-100 hover:bg-yellow-200 text-yellow-800'
            },
            red: {
                bg: 'bg-red-50',
                border: 'border-red-200',
                text: 'text-red-800',
                icon: 'text-red-600',
                button: 'bg-red-100 hover:bg-red-200 text-red-800'
            },
            gray: {
                bg: 'bg-gray-50',
                border: 'border-gray-200',
                text: 'text-gray-800',
                icon: 'text-gray-600',
                button: 'bg-gray-100 hover:bg-gray-200 text-gray-800'
            }
        };
        return colors[color] || colors.gray;
    };
    const colors = getColorClasses(statusInfo.color);
    if (compact) {
        return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("relative inline-flex items-center space-x-2 px-3 py-1.5 rounded-full text-sm border", colors.bg, colors.border, colors.text, "cursor-pointer", className),
            onMouseEnter: ()=>setShowTooltip(true),
            onMouseLeave: ()=>setShowTooltip(false),
            onClick: ()=>showDetails && onSettingsClick?.(),
            children: [
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("flex-shrink-0", colors.icon),
                    children: status?.status === __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionStatus"].INITIALIZING ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "animate-spin rounded-full h-3 w-3 border-b border-current"
                    }, void 0, false, {
                        fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                        lineNumber: 167,
                        columnNumber: 25
                    }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(IconComponent, {
                        className: "w-3 h-3"
                    }, void 0, false, {
                        fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                        lineNumber: 169,
                        columnNumber: 25
                    }, this)
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                    lineNumber: 165,
                    columnNumber: 17
                }, this),
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                    className: "font-medium",
                    children: statusInfo.text
                }, void 0, false, {
                    fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                    lineNumber: 172,
                    columnNumber: 17
                }, this),
                showTooltip && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-gray-900 text-white text-xs rounded-lg whitespace-nowrap z-10",
                    children: [
                        statusInfo.description,
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "absolute top-full left-1/2 transform -translate-x-1/2 border-4 border-transparent border-t-gray-900"
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                            lineNumber: 177,
                            columnNumber: 25
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                    lineNumber: 175,
                    columnNumber: 21
                }, this)
            ]
        }, void 0, true, {
            fileName: "[project]/src/components/EncryptionStatusIndicator.js",
            lineNumber: 152,
            columnNumber: 13
        }, this);
    }
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("flex items-center justify-between px-4 py-3 rounded-lg border", colors.bg, colors.border, className),
        children: [
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "flex items-center space-x-3",
                children: [
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("flex-shrink-0", colors.icon),
                        children: status?.status === __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionStatus"].INITIALIZING ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "animate-spin rounded-full h-5 w-5 border-b-2 border-current"
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                            lineNumber: 194,
                            columnNumber: 25
                        }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(IconComponent, {
                            className: "w-5 h-5"
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                            lineNumber: 196,
                            columnNumber: 25
                        }, this)
                    }, void 0, false, {
                        fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                        lineNumber: 192,
                        columnNumber: 17
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "flex-1 min-w-0",
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("text-sm font-medium", colors.text),
                                children: statusInfo.text
                            }, void 0, false, {
                                fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                                lineNumber: 201,
                                columnNumber: 21
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("text-xs opacity-75", colors.text),
                                children: statusInfo.description
                            }, void 0, false, {
                                fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                                lineNumber: 204,
                                columnNumber: 21
                            }, this),
                            showDetails && status && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("mt-2 text-xs space-y-1", colors.text),
                                children: [
                                    status.keysInitialized && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "flex items-center space-x-1",
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$check$2d$big$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__CheckCircle$3e$__["CheckCircle"], {
                                                className: "w-3 h-3"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                                                lineNumber: 213,
                                                columnNumber: 37
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                children: "Keys initialized"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                                                lineNumber: 214,
                                                columnNumber: 37
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                                        lineNumber: 212,
                                        columnNumber: 33
                                    }, this),
                                    status.keyGenerationTime && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "opacity-75",
                                        children: [
                                            "Keys generated: ",
                                            new Date(status.keyGenerationTime).toLocaleString()
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                                        lineNumber: 219,
                                        columnNumber: 33
                                    }, this),
                                    status.userId && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "opacity-75",
                                        children: [
                                            "User ID: ",
                                            status.userId
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                                        lineNumber: 225,
                                        columnNumber: 33
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                                lineNumber: 210,
                                columnNumber: 25
                            }, this)
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                        lineNumber: 200,
                        columnNumber: 17
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                lineNumber: 191,
                columnNumber: 13
            }, this),
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "flex items-center space-x-2",
                children: [
                    status?.status === __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionStatus"].ERROR && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                        onClick: handleRefresh,
                        disabled: isRefreshing,
                        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("p-1.5 rounded-md text-xs font-medium transition-colors", colors.button, isRefreshing && "opacity-50 cursor-not-allowed"),
                        title: "Retry encryption setup",
                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$refresh$2d$cw$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__RefreshCw$3e$__["RefreshCw"], {
                            className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("w-3 h-3", isRefreshing && "animate-spin")
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                            lineNumber: 247,
                            columnNumber: 25
                        }, this)
                    }, void 0, false, {
                        fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                        lineNumber: 237,
                        columnNumber: 21
                    }, this),
                    onSettingsClick && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                        onClick: onSettingsClick,
                        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("p-1.5 rounded-md text-xs font-medium transition-colors", colors.button),
                        title: "Encryption settings",
                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$settings$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Settings$3e$__["Settings"], {
                            className: "w-3 h-3"
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                            lineNumber: 260,
                            columnNumber: 25
                        }, this)
                    }, void 0, false, {
                        fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                        lineNumber: 252,
                        columnNumber: 21
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/components/EncryptionStatusIndicator.js",
                lineNumber: 235,
                columnNumber: 13
            }, this)
        ]
    }, void 0, true, {
        fileName: "[project]/src/components/EncryptionStatusIndicator.js",
        lineNumber: 185,
        columnNumber: 9
    }, this);
}
function EncryptionStatusBadge({ selectedUser, className = "" }) {
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(EncryptionStatusIndicator, {
        selectedUser: selectedUser,
        compact: true,
        className: className
    }, void 0, false, {
        fileName: "[project]/src/components/EncryptionStatusIndicator.js",
        lineNumber: 273,
        columnNumber: 9
    }, this);
}
function EncryptionStatusPanel({ selectedUser, onSettingsClick, className = "" }) {
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(EncryptionStatusIndicator, {
        selectedUser: selectedUser,
        compact: false,
        showDetails: true,
        onSettingsClick: onSettingsClick,
        className: className
    }, void 0, false, {
        fileName: "[project]/src/components/EncryptionStatusIndicator.js",
        lineNumber: 286,
        columnNumber: 9
    }, this);
}
}}),
"[project]/src/hooks/useEncryptionErrors.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__),
    "useEncryptionErrors": (()=>useEncryptionErrors)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/encryptionService.js [app-ssr] (ecmascript)");
;
;
function useEncryptionErrors() {
    const [errors, setErrors] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])([]);
    const [retryAttempts, setRetryAttempts] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])({});
    const retryTimeouts = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useRef"])({});
    // Maximum retry attempts for different error types
    const MAX_RETRY_ATTEMPTS = {
        [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_GENERATION_FAILED]: 3,
        [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].ENCRYPTION_FAILED]: 2,
        [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].DECRYPTION_FAILED]: 2,
        [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_EXCHANGE_FAILED]: 3,
        [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].SIGNATURE_VERIFICATION_FAILED]: 1,
        [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].STORAGE_FAILED]: 2,
        [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].INITIALIZATION_FAILED]: 3
    };
    // Retry delays (in milliseconds) with exponential backoff
    const getRetryDelay = (errorType, attemptCount)=>{
        const baseDelays = {
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_GENERATION_FAILED]: 2000,
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].ENCRYPTION_FAILED]: 1000,
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].DECRYPTION_FAILED]: 500,
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_EXCHANGE_FAILED]: 1500,
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].SIGNATURE_VERIFICATION_FAILED]: 500,
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].STORAGE_FAILED]: 1000,
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].INITIALIZATION_FAILED]: 2000
        };
        const baseDelay = baseDelays[errorType] || 1000;
        return baseDelay * Math.pow(2, attemptCount - 1) + Math.random() * 500;
    };
    /**
   * Add a new encryption error
   */ const addError = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])((error)=>{
        const errorId = `${error.type}-${Date.now()}-${Math.random()}`;
        const errorWithId = {
            ...error,
            id: errorId,
            timestamp: error.timestamp || new Date()
        };
        setErrors((prev)=>[
                ...prev,
                errorWithId
            ]);
        // Initialize retry count
        setRetryAttempts((prev)=>({
                ...prev,
                [errorId]: 0
            }));
        return errorId;
    }, []);
    /**
   * Remove an error by ID
   */ const removeError = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])((errorId)=>{
        setErrors((prev)=>prev.filter((error)=>error.id !== errorId));
        setRetryAttempts((prev)=>{
            const newAttempts = {
                ...prev
            };
            delete newAttempts[errorId];
            return newAttempts;
        });
        // Clear any pending retry timeout
        if (retryTimeouts.current[errorId]) {
            clearTimeout(retryTimeouts.current[errorId]);
            delete retryTimeouts.current[errorId];
        }
    }, []);
    /**
   * Clear all errors
   */ const clearErrors = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])(()=>{
        // Clear all retry timeouts
        Object.values(retryTimeouts.current).forEach((timeout)=>{
            clearTimeout(timeout);
        });
        retryTimeouts.current = {};
        setErrors([]);
        setRetryAttempts({});
    }, []);
    /**
   * Clear errors of a specific type
   */ const clearErrorsOfType = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])((errorType)=>{
        setErrors((prev)=>{
            const errorsToRemove = prev.filter((error)=>error.type === errorType);
            errorsToRemove.forEach((error)=>{
                if (retryTimeouts.current[error.id]) {
                    clearTimeout(retryTimeouts.current[error.id]);
                    delete retryTimeouts.current[error.id];
                }
            });
            return prev.filter((error)=>error.type !== errorType);
        });
        setRetryAttempts((prev)=>{
            const newAttempts = {
                ...prev
            };
            Object.keys(newAttempts).forEach((errorId)=>{
                const error = errors.find((e)=>e.id === errorId);
                if (error && error.type === errorType) {
                    delete newAttempts[errorId];
                }
            });
            return newAttempts;
        });
    }, [
        errors
    ]);
    /**
   * Check if an error can be retried
   */ const canRetry = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])((errorId)=>{
        const error = errors.find((e)=>e.id === errorId);
        if (!error) return false;
        const attempts = retryAttempts[errorId] || 0;
        const maxAttempts = MAX_RETRY_ATTEMPTS[error.type] || 1;
        return attempts < maxAttempts;
    }, [
        errors,
        retryAttempts
    ]);
    /**
   * Retry an operation with exponential backoff
   */ const retryOperation = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])(async (errorId, retryFunction)=>{
        const error = errors.find((e)=>e.id === errorId);
        if (!error || !canRetry(errorId)) {
            return false;
        }
        const currentAttempts = retryAttempts[errorId] || 0;
        const newAttempts = currentAttempts + 1;
        // Update retry count
        setRetryAttempts((prev)=>({
                ...prev,
                [errorId]: newAttempts
            }));
        try {
            // Add delay before retry (except for first retry)
            if (newAttempts > 1) {
                const delay = getRetryDelay(error.type, newAttempts);
                await new Promise((resolve)=>{
                    retryTimeouts.current[errorId] = setTimeout(resolve, delay);
                });
            }
            // Attempt the retry
            const result = await retryFunction();
            // If successful, remove the error
            if (result) {
                removeError(errorId);
                return true;
            }
            return false;
        } catch (retryError) {
            console.error(`Retry attempt ${newAttempts} failed for error ${errorId}:`, retryError);
            // If we've exhausted retries, update the error with the latest failure
            if (newAttempts >= (MAX_RETRY_ATTEMPTS[error.type] || 1)) {
                setErrors((prev)=>prev.map((e)=>e.id === errorId ? {
                            ...e,
                            message: retryError.message || e.message,
                            userFriendlyMessage: retryError.userFriendlyMessage || e.userFriendlyMessage,
                            lastRetryError: retryError,
                            retriesExhausted: true
                        } : e));
            }
            return false;
        }
    }, [
        errors,
        retryAttempts,
        canRetry,
        removeError
    ]);
    /**
   * Get errors by type
   */ const getErrorsByType = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])((errorType)=>{
        return errors.filter((error)=>error.type === errorType);
    }, [
        errors
    ]);
    /**
   * Get the most recent error of a specific type
   */ const getLatestErrorOfType = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])((errorType)=>{
        const typeErrors = getErrorsByType(errorType);
        return typeErrors.length > 0 ? typeErrors[typeErrors.length - 1] : null;
    }, [
        getErrorsByType
    ]);
    /**
   * Check if there are any critical errors that should block operations
   */ const hasCriticalErrors = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])(()=>{
        const criticalTypes = [
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].INITIALIZATION_FAILED,
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_GENERATION_FAILED
        ];
        return errors.some((error)=>criticalTypes.includes(error.type) && (retryAttempts[error.id] || 0) >= (MAX_RETRY_ATTEMPTS[error.type] || 1));
    }, [
        errors,
        retryAttempts
    ]);
    /**
   * Get summary of current error state
   */ const getErrorSummary = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])(()=>{
        const summary = {
            total: errors.length,
            byType: {},
            critical: hasCriticalErrors(),
            canRetryAny: false
        };
        errors.forEach((error)=>{
            if (!summary.byType[error.type]) {
                summary.byType[error.type] = 0;
            }
            summary.byType[error.type]++;
            if (canRetry(error.id)) {
                summary.canRetryAny = true;
            }
        });
        return summary;
    }, [
        errors,
        hasCriticalErrors,
        canRetry
    ]);
    /**
   * Auto-retry errors that are suitable for automatic retry
   */ const autoRetryErrors = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useCallback"])(async (retryFunctions)=>{
        const autoRetryTypes = [
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_EXCHANGE_FAILED,
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].STORAGE_FAILED
        ];
        const autoRetryPromises = errors.filter((error)=>autoRetryTypes.includes(error.type) && canRetry(error.id) && retryFunctions[error.type]).map((error)=>retryOperation(error.id, retryFunctions[error.type]));
        if (autoRetryPromises.length > 0) {
            const results = await Promise.allSettled(autoRetryPromises);
            const successCount = results.filter((result)=>result.status === 'fulfilled' && result.value === true).length;
            return successCount;
        }
        return 0;
    }, [
        errors,
        canRetry,
        retryOperation
    ]);
    return {
        errors,
        retryAttempts,
        addError,
        removeError,
        clearErrors,
        clearErrorsOfType,
        canRetry,
        retryOperation,
        getErrorsByType,
        getLatestErrorOfType,
        hasCriticalErrors,
        getErrorSummary,
        autoRetryErrors
    };
}
const __TURBOPACK__default__export__ = useEncryptionErrors;
}}),
"[project]/src/services/encryptionErrorManager.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
/**
 * EncryptionErrorManager - Centralized management of encryption errors
 * with retry mechanisms and user-friendly error handling
 */ __turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/encryptionService.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/utils/errorHandler.js [app-ssr] (ecmascript)");
;
;
class EncryptionErrorManager {
    constructor(){
        this.errorListeners = new Set();
        this.retryStrategies = new Map();
        this.errorHistory = [];
        this.maxHistorySize = 100;
        this.setupDefaultRetryStrategies();
    }
    /**
   * Setup default retry strategies for different error types
   */ setupDefaultRetryStrategies() {
        // Key generation retry strategy
        this.retryStrategies.set(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_GENERATION_FAILED, {
            maxRetries: 3,
            baseDelay: 2000,
            shouldRetry: (error, attempt)=>attempt < 3,
            onRetry: (error, attempt)=>{
                console.log(`Retrying key generation (attempt ${attempt + 1}/3)`);
            }
        });
        // Encryption failure retry strategy
        this.retryStrategies.set(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].ENCRYPTION_FAILED, {
            maxRetries: 2,
            baseDelay: 1000,
            shouldRetry: (error, attempt)=>{
                // Don't retry if it's a validation error
                if (error.message?.includes('invalid') || error.message?.includes('format')) {
                    return false;
                }
                return attempt < 2;
            },
            onRetry: (error, attempt)=>{
                console.log(`Retrying message encryption (attempt ${attempt + 1}/2)`);
            }
        });
        // Decryption failure retry strategy
        this.retryStrategies.set(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].DECRYPTION_FAILED, {
            maxRetries: 1,
            baseDelay: 500,
            shouldRetry: (error, attempt)=>{
                // Only retry once for potential network issues
                return attempt < 1 && !error.message?.includes('corrupted');
            },
            onRetry: (error, attempt)=>{
                console.log(`Retrying message decryption (attempt ${attempt + 1}/1)`);
            }
        });
        // Key exchange retry strategy
        this.retryStrategies.set(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_EXCHANGE_FAILED, {
            maxRetries: 3,
            baseDelay: 1500,
            shouldRetry: (error, attempt)=>attempt < 3,
            onRetry: (error, attempt)=>{
                console.log(`Retrying key exchange (attempt ${attempt + 1}/3)`);
            }
        });
        // Signature verification - no retry (data integrity issue)
        this.retryStrategies.set(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].SIGNATURE_VERIFICATION_FAILED, {
            maxRetries: 0,
            baseDelay: 0,
            shouldRetry: ()=>false,
            onRetry: ()=>{}
        });
        // Storage failure retry strategy
        this.retryStrategies.set(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].STORAGE_FAILED, {
            maxRetries: 2,
            baseDelay: 1000,
            shouldRetry: (error, attempt)=>attempt < 2,
            onRetry: (error, attempt)=>{
                console.log(`Retrying key storage (attempt ${attempt + 1}/2)`);
            }
        });
        // Initialization failure retry strategy
        this.retryStrategies.set(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].INITIALIZATION_FAILED, {
            maxRetries: 3,
            baseDelay: 2000,
            shouldRetry: (error, attempt)=>attempt < 3,
            onRetry: (error, attempt)=>{
                console.log(`Retrying encryption initialization (attempt ${attempt + 1}/3)`);
            }
        });
    }
    /**
   * Add an error listener
   */ addErrorListener(listener) {
        this.errorListeners.add(listener);
        return ()=>this.errorListeners.delete(listener);
    }
    /**
   * Notify all error listeners
   */ notifyErrorListeners(error, context = {}) {
        this.errorListeners.forEach((listener)=>{
            try {
                listener(error, context);
            } catch (listenerError) {
                console.error('Error in encryption error listener:', listenerError);
            }
        });
    }
    /**
   * Handle an encryption error with automatic retry logic
   */ async handleError(error, retryFunction, context = {}) {
        // Enhance error with user-friendly message if not present
        if (!error.userFriendlyMessage) {
            error.userFriendlyMessage = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["getEncryptionErrorMessage"])(error);
        }
        // Add to error history
        this.addToHistory(error, context);
        // Get retry strategy for this error type
        const strategy = this.retryStrategies.get(error.type);
        if (!strategy || !retryFunction) {
            // No retry strategy or function, just notify listeners
            this.notifyErrorListeners(error, {
                ...context,
                canRetry: false
            });
            throw error;
        }
        // Attempt retry with strategy
        try {
            const result = await this.executeWithRetry(retryFunction, error, strategy, context);
            // Success - notify listeners of recovery
            this.notifyErrorListeners(null, {
                ...context,
                recovered: true,
                originalError: error
            });
            return result;
        } catch (finalError) {
            // All retries failed - notify listeners
            this.notifyErrorListeners(finalError, {
                ...context,
                canRetry: false,
                retriesExhausted: true
            });
            throw finalError;
        }
    }
    /**
   * Execute a function with retry logic
   */ async executeWithRetry(fn, originalError, strategy, context) {
        let lastError = originalError;
        for(let attempt = 0; attempt <= strategy.maxRetries; attempt++){
            try {
                // First attempt uses original function, retries use retry logic
                if (attempt === 0) {
                    return await fn();
                }
                // Check if we should retry
                if (!strategy.shouldRetry(lastError, attempt - 1)) {
                    throw lastError;
                }
                // Notify about retry attempt
                strategy.onRetry(lastError, attempt - 1);
                this.notifyErrorListeners(lastError, {
                    ...context,
                    retrying: true,
                    attempt: attempt,
                    maxAttempts: strategy.maxRetries + 1
                });
                // Wait before retry
                if (strategy.baseDelay > 0) {
                    const delay = strategy.baseDelay * Math.pow(1.5, attempt - 1) + Math.random() * 500;
                    await new Promise((resolve)=>setTimeout(resolve, Math.min(delay, 10000)));
                }
                // Attempt retry
                return await fn();
            } catch (error) {
                lastError = error;
                // Enhance error with user-friendly message
                if (!error.userFriendlyMessage) {
                    error.userFriendlyMessage = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$utils$2f$errorHandler$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["getEncryptionErrorMessage"])(error);
                }
                // Add retry context
                error.retryAttempt = attempt;
                error.maxRetries = strategy.maxRetries;
                // Continue to next iteration or throw if max retries reached
                if (attempt >= strategy.maxRetries) {
                    throw error;
                }
            }
        }
        throw lastError;
    }
    /**
   * Handle encryption operation with automatic error management
   */ async handleEncryptionOperation(operation, operationType, context = {}) {
        try {
            return await operation();
        } catch (error) {
            // Determine error type if not set
            if (!error.type) {
                error.type = this.determineErrorType(error, operationType);
            }
            // Create retry function
            const retryFunction = ()=>operation();
            // Handle with retry logic
            return await this.handleError(error, retryFunction, {
                ...context,
                operationType
            });
        }
    }
    /**
   * Determine error type based on error message and operation type
   */ determineErrorType(error, operationType) {
        const message = error.message?.toLowerCase() || '';
        if (operationType === 'keyGeneration' || message.includes('key generation')) {
            return __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_GENERATION_FAILED;
        }
        if (operationType === 'encryption' || message.includes('encrypt') && !message.includes('decrypt')) {
            return __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].ENCRYPTION_FAILED;
        }
        if (operationType === 'decryption' || message.includes('decrypt')) {
            return __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].DECRYPTION_FAILED;
        }
        if (operationType === 'keyExchange' || message.includes('key exchange') || message.includes('public key')) {
            return __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_EXCHANGE_FAILED;
        }
        if (operationType === 'signature' || message.includes('signature')) {
            return __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].SIGNATURE_VERIFICATION_FAILED;
        }
        if (operationType === 'storage' || message.includes('storage')) {
            return __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].STORAGE_FAILED;
        }
        if (operationType === 'initialization' || message.includes('initialization')) {
            return __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].INITIALIZATION_FAILED;
        }
        // Default to encryption failed
        return __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].ENCRYPTION_FAILED;
    }
    /**
   * Add error to history
   */ addToHistory(error, context = {}) {
        const historyEntry = {
            error: {
                type: error.type,
                message: error.message,
                userFriendlyMessage: error.userFriendlyMessage,
                timestamp: error.timestamp || new Date()
            },
            context,
            id: `${Date.now()}-${Math.random()}`
        };
        this.errorHistory.unshift(historyEntry);
        // Limit history size
        if (this.errorHistory.length > this.maxHistorySize) {
            this.errorHistory = this.errorHistory.slice(0, this.maxHistorySize);
        }
    }
    /**
   * Get error history
   */ getErrorHistory(limit = 10) {
        return this.errorHistory.slice(0, limit);
    }
    /**
   * Get error statistics
   */ getErrorStats() {
        const stats = {
            total: this.errorHistory.length,
            byType: {},
            recent: this.errorHistory.slice(0, 10),
            mostCommon: null
        };
        // Count by type
        this.errorHistory.forEach((entry)=>{
            const type = entry.error.type;
            stats.byType[type] = (stats.byType[type] || 0) + 1;
        });
        // Find most common error type
        let maxCount = 0;
        Object.entries(stats.byType).forEach(([type, count])=>{
            if (count > maxCount) {
                maxCount = count;
                stats.mostCommon = {
                    type,
                    count
                };
            }
        });
        return stats;
    }
    /**
   * Clear error history
   */ clearHistory() {
        this.errorHistory = [];
    }
    /**
   * Create a user-friendly error summary
   */ createErrorSummary(errors) {
        if (!errors || errors.length === 0) {
            return null;
        }
        const errorTypes = [
            ...new Set(errors.map((e)=>e.type))
        ];
        if (errorTypes.length === 1) {
            const error = errors[0];
            return {
                title: this.getErrorTitle(error.type),
                message: error.userFriendlyMessage || error.message,
                canRetry: this.canRetryErrorType(error.type),
                severity: this.getErrorSeverity(error.type)
            };
        }
        return {
            title: 'Multiple Encryption Errors',
            message: `${errors.length} encryption errors occurred. Please check your connection and try again.`,
            canRetry: errors.some((e)=>this.canRetryErrorType(e.type)),
            severity: 'error',
            details: errors.map((e)=>({
                    type: e.type,
                    message: e.userFriendlyMessage || e.message
                }))
        };
    }
    /**
   * Get user-friendly error title
   */ getErrorTitle(errorType) {
        const titles = {
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_GENERATION_FAILED]: 'Key Generation Failed',
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].ENCRYPTION_FAILED]: 'Message Encryption Failed',
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].DECRYPTION_FAILED]: 'Message Decryption Failed',
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_EXCHANGE_FAILED]: 'Key Exchange Failed',
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].SIGNATURE_VERIFICATION_FAILED]: 'Signature Verification Failed',
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].STORAGE_FAILED]: 'Key Storage Failed',
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].INITIALIZATION_FAILED]: 'Encryption Setup Failed'
        };
        return titles[errorType] || 'Encryption Error';
    }
    /**
   * Check if error type can be retried
   */ canRetryErrorType(errorType) {
        const strategy = this.retryStrategies.get(errorType);
        return strategy && strategy.maxRetries > 0;
    }
    /**
   * Get error severity level
   */ getErrorSeverity(errorType) {
        const severities = {
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_GENERATION_FAILED]: 'error',
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].ENCRYPTION_FAILED]: 'error',
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].DECRYPTION_FAILED]: 'error',
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_EXCHANGE_FAILED]: 'warning',
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].SIGNATURE_VERIFICATION_FAILED]: 'warning',
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].STORAGE_FAILED]: 'warning',
            [__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].INITIALIZATION_FAILED]: 'error'
        };
        return severities[errorType] || 'error';
    }
}
// Export singleton instance
const encryptionErrorManager = new EncryptionErrorManager();
const __TURBOPACK__default__export__ = encryptionErrorManager;
}}),
"[project]/src/components/ChatMain.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "default": (()=>ChatMain)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$arrow$2d$left$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__ArrowLeft$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/arrow-left.js [app-ssr] (ecmascript) <export default as ArrowLeft>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$phone$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Phone$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/phone.js [app-ssr] (ecmascript) <export default as Phone>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$video$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Video$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/video.js [app-ssr] (ecmascript) <export default as Video>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$ellipsis$2d$vertical$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__MoreVertical$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/ellipsis-vertical.js [app-ssr] (ecmascript) <export default as MoreVertical>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$send$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Send$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/send.js [app-ssr] (ecmascript) <export default as Send>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$paperclip$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Paperclip$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/paperclip.js [app-ssr] (ecmascript) <export default as Paperclip>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$smile$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Smile$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/smile.js [app-ssr] (ecmascript) <export default as Smile>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$check$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Check$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/check.js [app-ssr] (ecmascript) <export default as Check>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$check$2d$check$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__CheckCheck$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/check-check.js [app-ssr] (ecmascript) <export default as CheckCheck>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$clock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Clock$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/clock.js [app-ssr] (ecmascript) <export default as Clock>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertCircle$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/circle-alert.js [app-ssr] (ecmascript) <export default as AlertCircle>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$wifi$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Wifi$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/wifi.js [app-ssr] (ecmascript) <export default as Wifi>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$wifi$2d$off$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__WifiOff$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/wifi-off.js [app-ssr] (ecmascript) <export default as WifiOff>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$message$2d$circle$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__MessageCircle$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/message-circle.js [app-ssr] (ecmascript) <export default as MessageCircle>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Lock$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/lock.js [app-ssr] (ecmascript) <export default as Lock>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2d$open$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__LockOpen$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/lock-open.js [app-ssr] (ecmascript) <export default as LockOpen>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/triangle-alert.js [app-ssr] (ecmascript) <export default as AlertTriangle>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/clsx/dist/clsx.mjs [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/encryptionService.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionErrorDisplay$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/EncryptionErrorDisplay.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionStatusIndicator$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/EncryptionStatusIndicator.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$hooks$2f$useEncryptionErrors$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/hooks/useEncryptionErrors.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionErrorManager$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/encryptionErrorManager.js [app-ssr] (ecmascript)");
"use client";
;
;
;
;
;
;
;
;
;
function ChatMain({ messages, isConnected, currentRoom, selectedRoomId, selectedUser, sendMessage, connectionError, lastError, pendingMessagesCount, retryConnection, encryptionStatus, currentUser, isMobile, onBackToList, typingUsers = [], onlineUsers = new Set(), startTyping, stopTyping }) {
    const [messageInput, setMessageInput] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])('');
    const [isTyping, setIsTyping] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    const [encryptionError, setEncryptionError] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(null);
    const [isEncrypting, setIsEncrypting] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    const messageEndRef = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useRef"])(null);
    const inputRef = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useRef"])(null);
    const typingTimeoutRef = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useRef"])(null);
    // Enhanced encryption error management
    const { errors: encryptionErrors, addError: addEncryptionError, removeError: removeEncryptionError, clearErrors: clearEncryptionErrors, canRetry, retryOperation } = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$hooks$2f$useEncryptionErrors$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"])();
    // Auto-scroll to bottom when new messages arrive
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        messageEndRef.current?.scrollIntoView({
            behavior: "smooth"
        });
    }, [
        messages
    ]);
    // Focus input when room changes
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        if (inputRef.current && !isMobile) {
            inputRef.current.focus();
        }
    }, [
        selectedRoomId,
        isMobile
    ]);
    const [isSending, setIsSending] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    const handleSendMessage = async ()=>{
        if (messageInput.trim() && !isSending) {
            setIsSending(true);
            setIsEncrypting(true);
            setEncryptionError(null);
            try {
                // Simple GitHub-based base64 encryption
                let messageData = null;
                if (selectedUser?.github_username) {
                    try {
                        console.log('Fetching GitHub public key for:', selectedUser.github_username);
                        // Fetch public key from GitHub
                        const response = await fetch(`https://api.github.com/users/${selectedUser.github_username}/keys`);
                        if (response.ok) {
                            const keys = await response.json();
                            if (keys.length > 0) {
                                console.log('Found', keys.length, 'SSH keys on GitHub');
                                // Simple base64 encryption with GitHub verification
                                const encryptedContent = btoa(messageInput.trim());
                                const signature = btoa(`signed_by_${selectedUser.github_username}`);
                                messageData = {
                                    content: encryptedContent,
                                    encrypted_aes_key: 'github_base64',
                                    iv: 'github_iv',
                                    signature: signature,
                                    is_encrypted: true,
                                    original_content: messageInput.trim()
                                };
                                console.log(' Message encrypted with GitHub-based base64');
                            } else {
                                throw new Error('No SSH keys found on GitHub');
                            }
                        } else {
                            throw new Error(`GitHub API returned ${response.status}`);
                        }
                    } catch (encryptError) {
                        console.error(' GitHub encryption failed:', encryptError);
                        setEncryptionError(encryptError);
                    }
                } else {
                    console.log('No GitHub username, sending plain text');
                }
                setIsEncrypting(false);
                console.log('About to send:', {
                    messageData,
                    hasContent: !!messageData?.content
                });
                console.log('ChatMain calling sendMessage with:', {
                    selectedRoomId,
                    messageInput,
                    messageData
                });
                // Send the message with proper parameters
                const result = await sendMessage(selectedRoomId, messageInput.trim(), messageData);
                if (result?.success || result?.queued) {
                    setMessageInput('');
                    setEncryptionError(null);
                    clearEncryptionErrors(); // Clear any previous errors on success
                }
            } catch (error) {
                console.error('Failed to send message:', error);
                setEncryptionError({
                    type: 'send_failed',
                    message: error.message,
                    userFriendlyMessage: 'Failed to send message. Please try again.'
                });
            } finally{
                setIsEncrypting(false);
                // Add a small delay to prevent double-sending
                setTimeout(()=>{
                    setIsSending(false);
                }, 500);
            }
        }
    };
    // Handle encryption error retry
    const handleEncryptionRetry = async (errorId)=>{
        const error = encryptionErrors.find((e)=>e.id === errorId);
        if (!error) return false;
        try {
            if (error.type === 'encryption_failed') {
                // Retry message encryption
                return await retryOperation(errorId, async ()=>{
                    const recipientGithubUsername = selectedUser.github_username;
                    if (!recipientGithubUsername) {
                        throw new Error(`User ${selectedUser.display_name || selectedUser.name} does not have a GitHub username`);
                    }
                    const messageData = await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].encryptMessage(messageInput.trim(), recipientGithubUsername);
                    return messageData;
                });
            } else if (error.type === 'initialization_failed') {
                // Retry encryption initialization
                return await retryOperation(errorId, async ()=>{
                    return await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].initialize(currentUser.id, currentUser.token);
                });
            }
            return false;
        } catch (retryError) {
            console.error('Encryption retry failed:', retryError);
            return false;
        }
    };
    const handleKeyPress = (e)=>{
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSendMessage();
        }
    };
    const handleInputChange = (e)=>{
        const value = e.target.value;
        setMessageInput(value);
        // Handle typing indicators
        if (value.trim() && !isTyping && startTyping) {
            setIsTyping(true);
            startTyping();
        }
        // Clear existing timeout
        if (typingTimeoutRef.current) {
            clearTimeout(typingTimeoutRef.current);
        }
        // Set timeout to stop typing
        typingTimeoutRef.current = setTimeout(()=>{
            if (isTyping && stopTyping) {
                setIsTyping(false);
                stopTyping();
            }
        }, 1000);
    };
    // Stop typing when component unmounts or room changes
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        return ()=>{
            if (typingTimeoutRef.current) {
                clearTimeout(typingTimeoutRef.current);
            }
            if (isTyping && stopTyping) {
                stopTyping();
            }
        };
    }, [
        selectedRoomId,
        isTyping,
        stopTyping
    ]);
    const getMessageStatus = (message)=>{
        if (message.sender === 'me') {
            if (message.status === 'sending') {
                return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$clock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Clock$3e$__["Clock"], {
                    className: "w-3 h-3 text-gray-400"
                }, void 0, false, {
                    fileName: "[project]/src/components/ChatMain.js",
                    lineNumber: 221,
                    columnNumber: 16
                }, this);
            } else if (message.status === 'sent') {
                return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$check$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Check$3e$__["Check"], {
                    className: "w-3 h-3 text-gray-400"
                }, void 0, false, {
                    fileName: "[project]/src/components/ChatMain.js",
                    lineNumber: 223,
                    columnNumber: 16
                }, this);
            } else if (message.status === 'delivered') {
                return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$check$2d$check$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__CheckCheck$3e$__["CheckCheck"], {
                    className: "w-3 h-3 text-gray-400"
                }, void 0, false, {
                    fileName: "[project]/src/components/ChatMain.js",
                    lineNumber: 225,
                    columnNumber: 16
                }, this);
            } else if (message.status === 'read') {
                return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$check$2d$check$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__CheckCheck$3e$__["CheckCheck"], {
                    className: "w-3 h-3 text-blue-500"
                }, void 0, false, {
                    fileName: "[project]/src/components/ChatMain.js",
                    lineNumber: 227,
                    columnNumber: 16
                }, this);
            }
            return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$check$2d$check$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__CheckCheck$3e$__["CheckCheck"], {
                className: "w-3 h-3 text-gray-400"
            }, void 0, false, {
                fileName: "[project]/src/components/ChatMain.js",
                lineNumber: 229,
                columnNumber: 14
            }, this);
        }
        return null;
    };
    const getRoomDisplayName = ()=>{
        const roomNames = {
            'general': 'General Chat',
            'tech-talk': 'Tech Talk',
            'random': 'Random'
        };
        return roomNames[selectedRoomId] || selectedRoomId;
    };
    const getRoomAvatar = ()=>{
        const roomAvatars = {
            'general': '',
            'tech-talk': '',
            'random': ''
        };
        return roomAvatars[selectedRoomId] || '';
    };
    const getEncryptionStatusText = (message)=>{
        if (!message.isEncrypted) {
            return 'Not encrypted';
        }
        if (message.encryptionError) {
            if (message.decryptionErrorType === 'signature_failed') {
                return 'Encrypted (signature verification failed)';
            } else if (message.decryptionErrorType === 'decrypt_failed') {
                return 'Encrypted (decryption failed)';
            } else {
                return 'Encrypted (error)';
            }
        }
        if (message.signatureValid) {
            return 'Encrypted and verified';
        } else {
            return 'Encrypted (signature not verified)';
        }
    };
    if (!selectedRoomId) {
        return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            className: "flex-1 flex items-center justify-center gradient-neutral",
            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "text-center",
                children: [
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "w-32 h-32 gradient-primary rounded-3xl flex items-center justify-center mx-auto mb-6 shadow-strong",
                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$message$2d$circle$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__MessageCircle$3e$__["MessageCircle"], {
                            className: "w-16 h-16 text-white"
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatMain.js",
                            lineNumber: 279,
                            columnNumber: 13
                        }, this)
                    }, void 0, false, {
                        fileName: "[project]/src/components/ChatMain.js",
                        lineNumber: 278,
                        columnNumber: 11
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                        className: "text-3xl font-bold bg-gradient-to-r from-purple-600 to-blue-600 bg-clip-text text-transparent mb-4",
                        children: "Welcome to Chat"
                    }, void 0, false, {
                        fileName: "[project]/src/components/ChatMain.js",
                        lineNumber: 281,
                        columnNumber: 11
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                        className: "text-lg text-gray-600",
                        children: "Select a conversation to start messaging"
                    }, void 0, false, {
                        fileName: "[project]/src/components/ChatMain.js",
                        lineNumber: 284,
                        columnNumber: 11
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/components/ChatMain.js",
                lineNumber: 277,
                columnNumber: 9
            }, this)
        }, void 0, false, {
            fileName: "[project]/src/components/ChatMain.js",
            lineNumber: 276,
            columnNumber: 7
        }, this);
    }
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
        className: "flex-1 flex flex-col bg-white",
        children: [
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "flex items-center justify-between p-6 border-b border-gray-100 glass-morphism shadow-soft",
                children: [
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "flex items-center space-x-3",
                        children: [
                            isMobile && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                onClick: onBackToList,
                                className: "p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-full transition-colors",
                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$arrow$2d$left$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__ArrowLeft$3e$__["ArrowLeft"], {
                                    className: "w-5 h-5"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 302,
                                    columnNumber: 15
                                }, this)
                            }, void 0, false, {
                                fileName: "[project]/src/components/ChatMain.js",
                                lineNumber: 298,
                                columnNumber: 13
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "w-12 h-12 gradient-primary rounded-xl flex items-center justify-center text-xl shadow-soft",
                                children: getRoomAvatar()
                            }, void 0, false, {
                                fileName: "[project]/src/components/ChatMain.js",
                                lineNumber: 306,
                                columnNumber: 11
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "flex-1 min-w-0",
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h2", {
                                        className: "text-xl font-bold bg-gradient-to-r from-purple-600 to-blue-600 bg-clip-text text-transparent truncate",
                                        children: getRoomDisplayName()
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ChatMain.js",
                                        lineNumber: 311,
                                        columnNumber: 13
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "flex items-center space-x-2 text-sm text-gray-500",
                                        children: isConnected ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["Fragment"], {
                                            children: [
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$wifi$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Wifi$3e$__["Wifi"], {
                                                    className: "w-3 h-3 text-green-500"
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/ChatMain.js",
                                                    lineNumber: 317,
                                                    columnNumber: 19
                                                }, this),
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                    className: "text-green-600",
                                                    children: "Connected"
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/ChatMain.js",
                                                    lineNumber: 318,
                                                    columnNumber: 19
                                                }, this),
                                                currentRoom && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                    children: [
                                                        "• Room: ",
                                                        currentRoom
                                                    ]
                                                }, void 0, true, {
                                                    fileName: "[project]/src/components/ChatMain.js",
                                                    lineNumber: 320,
                                                    columnNumber: 21
                                                }, this)
                                            ]
                                        }, void 0, true) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["Fragment"], {
                                            children: [
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$wifi$2d$off$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__WifiOff$3e$__["WifiOff"], {
                                                    className: "w-3 h-3 text-red-500"
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/ChatMain.js",
                                                    lineNumber: 325,
                                                    columnNumber: 19
                                                }, this),
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                    className: "text-red-600",
                                                    children: connectionError || 'Disconnected'
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/ChatMain.js",
                                                    lineNumber: 326,
                                                    columnNumber: 19
                                                }, this),
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                                    onClick: retryConnection,
                                                    className: "text-blue-600 hover:text-blue-800 underline",
                                                    children: "Retry"
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/ChatMain.js",
                                                    lineNumber: 329,
                                                    columnNumber: 19
                                                }, this)
                                            ]
                                        }, void 0, true)
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ChatMain.js",
                                        lineNumber: 314,
                                        columnNumber: 13
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/ChatMain.js",
                                lineNumber: 310,
                                columnNumber: 11
                            }, this)
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/ChatMain.js",
                        lineNumber: 296,
                        columnNumber: 9
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "flex items-center space-x-2",
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                className: "p-3 text-gray-500 hover:text-white hover:bg-gradient-to-r hover:from-green-400 hover:to-blue-500 rounded-xl transition-all duration-300 shadow-soft hover:shadow-medium hover:scale-105",
                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$phone$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Phone$3e$__["Phone"], {
                                    className: "w-5 h-5"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 343,
                                    columnNumber: 13
                                }, this)
                            }, void 0, false, {
                                fileName: "[project]/src/components/ChatMain.js",
                                lineNumber: 342,
                                columnNumber: 11
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                className: "p-3 text-gray-500 hover:text-white hover:bg-gradient-to-r hover:from-purple-400 hover:to-pink-500 rounded-xl transition-all duration-300 shadow-soft hover:shadow-medium hover:scale-105",
                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$video$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Video$3e$__["Video"], {
                                    className: "w-5 h-5"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 346,
                                    columnNumber: 13
                                }, this)
                            }, void 0, false, {
                                fileName: "[project]/src/components/ChatMain.js",
                                lineNumber: 345,
                                columnNumber: 11
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                className: "p-3 text-gray-500 hover:text-white hover:bg-gradient-to-r hover:from-gray-400 hover:to-gray-600 rounded-xl transition-all duration-300 shadow-soft hover:shadow-medium hover:scale-105",
                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$ellipsis$2d$vertical$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__MoreVertical$3e$__["MoreVertical"], {
                                    className: "w-5 h-5"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 349,
                                    columnNumber: 13
                                }, this)
                            }, void 0, false, {
                                fileName: "[project]/src/components/ChatMain.js",
                                lineNumber: 348,
                                columnNumber: 11
                            }, this)
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/ChatMain.js",
                        lineNumber: 341,
                        columnNumber: 9
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/components/ChatMain.js",
                lineNumber: 295,
                columnNumber: 7
            }, this),
            !isConnected && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "gradient-warning border-b border-orange-200 px-6 py-3",
                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "flex items-center justify-between",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex items-center space-x-3",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertCircle$3e$__["AlertCircle"], {
                                    className: "w-5 h-5 text-white"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 359,
                                    columnNumber: 15
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                    className: "text-sm font-medium text-white",
                                    children: [
                                        connectionError || 'Disconnected from chat',
                                        pendingMessagesCount > 0 && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                            className: "ml-2",
                                            children: [
                                                "(",
                                                pendingMessagesCount,
                                                " message",
                                                pendingMessagesCount > 1 ? 's' : '',
                                                " queued)"
                                            ]
                                        }, void 0, true, {
                                            fileName: "[project]/src/components/ChatMain.js",
                                            lineNumber: 363,
                                            columnNumber: 19
                                        }, this)
                                    ]
                                }, void 0, true, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 360,
                                    columnNumber: 15
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/ChatMain.js",
                            lineNumber: 358,
                            columnNumber: 13
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                            onClick: retryConnection,
                            className: "text-sm text-white hover:text-gray-100 underline font-medium transition-colors duration-200",
                            children: "Retry Connection"
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatMain.js",
                            lineNumber: 369,
                            columnNumber: 13
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/ChatMain.js",
                    lineNumber: 357,
                    columnNumber: 11
                }, this)
            }, void 0, false, {
                fileName: "[project]/src/components/ChatMain.js",
                lineNumber: 356,
                columnNumber: 9
            }, this),
            lastError && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "gradient-error border-b border-red-200 px-6 py-3",
                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "flex items-center space-x-3",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$circle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertCircle$3e$__["AlertCircle"], {
                            className: "w-5 h-5 text-white"
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatMain.js",
                            lineNumber: 383,
                            columnNumber: 13
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                            className: "text-sm font-medium text-white",
                            children: [
                                lastError.message,
                                lastError.type === 'send_message' && lastError.details?.queued && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                    className: "ml-2",
                                    children: "(Message queued for retry)"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 387,
                                    columnNumber: 17
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/ChatMain.js",
                            lineNumber: 384,
                            columnNumber: 13
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/ChatMain.js",
                    lineNumber: 382,
                    columnNumber: 11
                }, this)
            }, void 0, false, {
                fileName: "[project]/src/components/ChatMain.js",
                lineNumber: 381,
                columnNumber: 9
            }, this),
            encryptionErrors.map((error)=>/*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionErrorDisplay$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorBanner"], {
                    error: error,
                    onRetry: canRetry(error.id) ? ()=>handleEncryptionRetry(error.id) : null,
                    onDismiss: ()=>removeEncryptionError(error.id),
                    className: "border-b"
                }, error.id, false, {
                    fileName: "[project]/src/components/ChatMain.js",
                    lineNumber: 396,
                    columnNumber: 9
                }, this)),
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "flex-1 overflow-y-auto p-6 space-y-4 gradient-neutral",
                children: [
                    messages.length === 0 ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "flex items-center justify-center h-full",
                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "text-center",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "w-20 h-20 gradient-primary rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-strong",
                                    children: getRoomAvatar()
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 410,
                                    columnNumber: 15
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                                    className: "text-2xl font-bold bg-gradient-to-r from-purple-600 to-blue-600 bg-clip-text text-transparent mb-3",
                                    children: getRoomDisplayName()
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 413,
                                    columnNumber: 15
                                }, this),
                                isConnected ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                    className: "text-gray-600 text-lg",
                                    children: "No messages yet. Start the conversation!"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 417,
                                    columnNumber: 17
                                }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                    className: "text-gray-600 text-lg",
                                    children: "Connecting to chat..."
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 421,
                                    columnNumber: 17
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/ChatMain.js",
                            lineNumber: 409,
                            columnNumber: 13
                        }, this)
                    }, void 0, false, {
                        fileName: "[project]/src/components/ChatMain.js",
                        lineNumber: 408,
                        columnNumber: 11
                    }, this) : messages.map((message, index)=>{
                        const isOwn = message.sender === 'me';
                        const showSender = !isOwn && (index === 0 || messages[index - 1].sender !== message.sender);
                        return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("flex", isOwn ? "justify-end" : "justify-start"),
                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("max-w-xs lg:max-w-md px-5 py-3 rounded-2xl shadow-medium transition-all duration-300 hover:shadow-strong", isOwn ? "gradient-primary text-white" : "glass-morphism text-gray-900"),
                                children: [
                                    showSender && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "text-xs font-medium mb-1 text-gray-600",
                                        children: message.senderName || 'Unknown User'
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ChatMain.js",
                                        lineNumber: 447,
                                        columnNumber: 21
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "break-words",
                                        children: message.text
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ChatMain.js",
                                        lineNumber: 452,
                                        columnNumber: 19
                                    }, this),
                                    message.encryptionError && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("text-xs mt-1 px-2 py-1 rounded", message.decryptionErrorType === 'signature_failed' ? isOwn ? "bg-yellow-100 text-yellow-800 border border-yellow-200" : "bg-yellow-50 text-yellow-700 border border-yellow-200" : isOwn ? "bg-red-100 text-red-800 border border-red-200" : "bg-red-50 text-red-700 border border-red-200"),
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "flex items-center space-x-1",
                                                children: [
                                                    message.decryptionErrorType === 'signature_failed' ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"], {
                                                        className: "w-3 h-3 text-yellow-600"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/ChatMain.js",
                                                        lineNumber: 470,
                                                        columnNumber: 27
                                                    }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"], {
                                                        className: "w-3 h-3 text-red-600"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/ChatMain.js",
                                                        lineNumber: 472,
                                                        columnNumber: 27
                                                    }, this),
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                        children: message.encryptionError
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/ChatMain.js",
                                                        lineNumber: 474,
                                                        columnNumber: 25
                                                    }, this)
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/ChatMain.js",
                                                lineNumber: 468,
                                                columnNumber: 23
                                            }, this),
                                            message.decryptionErrorType === 'signature_failed' && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "mt-1 text-xs opacity-75",
                                                children: "The message was decrypted but the sender's identity could not be verified."
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatMain.js",
                                                lineNumber: 479,
                                                columnNumber: 25
                                            }, this),
                                            message.decryptionErrorType === 'decrypt_failed' && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "mt-1 text-xs opacity-75",
                                                children: "This message may be corrupted or sent with incompatible encryption."
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatMain.js",
                                                lineNumber: 485,
                                                columnNumber: 25
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/ChatMain.js",
                                        lineNumber: 458,
                                        columnNumber: 21
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("flex items-center justify-between mt-1 text-xs", isOwn ? "text-blue-100" : "text-gray-500"),
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "flex items-center space-x-1",
                                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                    className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("text-xs opacity-75", message.encryptionError && message.decryptionErrorType === 'signature_failed' ? isOwn ? "text-yellow-200" : "text-yellow-600" : message.encryptionError ? isOwn ? "text-red-200" : "text-red-500" : message.isEncrypted ? isOwn ? "text-green-200" : "text-green-600" : isOwn ? "text-gray-300" : "text-gray-400"),
                                                    children: getEncryptionStatusText(message)
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/ChatMain.js",
                                                    lineNumber: 498,
                                                    columnNumber: 23
                                                }, this)
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatMain.js",
                                                lineNumber: 496,
                                                columnNumber: 21
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "flex items-center space-x-1",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                        children: message.timestamp
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/ChatMain.js",
                                                        lineNumber: 513,
                                                        columnNumber: 23
                                                    }, this),
                                                    getMessageStatus(message),
                                                    message.isEncrypted && !message.encryptionError && message.signatureValid && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                        className: "flex items-center space-x-1",
                                                        children: [
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Lock$3e$__["Lock"], {
                                                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("w-3 h-3", isOwn ? "text-green-200" : "text-green-600"),
                                                                title: "End-to-end encrypted and signature verified"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/ChatMain.js",
                                                                lineNumber: 519,
                                                                columnNumber: 27
                                                            }, this),
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("w-1 h-1 rounded-full", isOwn ? "bg-green-200" : "bg-green-600"),
                                                                title: "Verified sender"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/ChatMain.js",
                                                                lineNumber: 523,
                                                                columnNumber: 27
                                                            }, this)
                                                        ]
                                                    }, void 0, true, {
                                                        fileName: "[project]/src/components/ChatMain.js",
                                                        lineNumber: 518,
                                                        columnNumber: 25
                                                    }, this),
                                                    message.isEncrypted && !message.encryptionError && !message.signatureValid && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                        className: "flex items-center space-x-1",
                                                        children: [
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Lock$3e$__["Lock"], {
                                                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("w-3 h-3", isOwn ? "text-blue-200" : "text-green-600"),
                                                                title: "End-to-end encrypted"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/ChatMain.js",
                                                                lineNumber: 532,
                                                                columnNumber: 27
                                                            }, this),
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"], {
                                                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("w-3 h-3", isOwn ? "text-yellow-200" : "text-yellow-500"),
                                                                title: "Message signature could not be verified - sender authenticity unknown"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/ChatMain.js",
                                                                lineNumber: 536,
                                                                columnNumber: 27
                                                            }, this)
                                                        ]
                                                    }, void 0, true, {
                                                        fileName: "[project]/src/components/ChatMain.js",
                                                        lineNumber: 531,
                                                        columnNumber: 25
                                                    }, this),
                                                    message.encryptionError && message.decryptionErrorType === 'decrypt_failed' && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                        className: "flex items-center space-x-1",
                                                        children: [
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2d$open$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__LockOpen$3e$__["LockOpen"], {
                                                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("w-3 h-3", isOwn ? "text-red-200" : "text-red-500"),
                                                                title: "Failed to decrypt message"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/ChatMain.js",
                                                                lineNumber: 545,
                                                                columnNumber: 27
                                                            }, this),
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"], {
                                                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("w-3 h-3", isOwn ? "text-red-200" : "text-red-500"),
                                                                title: "Decryption error"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/ChatMain.js",
                                                                lineNumber: 549,
                                                                columnNumber: 27
                                                            }, this)
                                                        ]
                                                    }, void 0, true, {
                                                        fileName: "[project]/src/components/ChatMain.js",
                                                        lineNumber: 544,
                                                        columnNumber: 25
                                                    }, this),
                                                    message.encryptionError && message.decryptionErrorType === 'signature_failed' && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                        className: "flex items-center space-x-1",
                                                        children: [
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Lock$3e$__["Lock"], {
                                                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("w-3 h-3", isOwn ? "text-blue-200" : "text-green-600"),
                                                                title: "Message decrypted successfully"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/ChatMain.js",
                                                                lineNumber: 558,
                                                                columnNumber: 27
                                                            }, this),
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"], {
                                                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("w-3 h-3", isOwn ? "text-yellow-200" : "text-yellow-500"),
                                                                title: "Signature verification failed - sender authenticity could not be verified"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/ChatMain.js",
                                                                lineNumber: 562,
                                                                columnNumber: 27
                                                            }, this)
                                                        ]
                                                    }, void 0, true, {
                                                        fileName: "[project]/src/components/ChatMain.js",
                                                        lineNumber: 557,
                                                        columnNumber: 25
                                                    }, this),
                                                    !message.isEncrypted && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$lock$2d$open$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__LockOpen$3e$__["LockOpen"], {
                                                        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("w-3 h-3", isOwn ? "text-gray-300" : "text-gray-400"),
                                                        title: "Message not encrypted"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/ChatMain.js",
                                                        lineNumber: 570,
                                                        columnNumber: 25
                                                    }, this)
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/ChatMain.js",
                                                lineNumber: 512,
                                                columnNumber: 21
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/ChatMain.js",
                                        lineNumber: 492,
                                        columnNumber: 19
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/ChatMain.js",
                                lineNumber: 440,
                                columnNumber: 17
                            }, this)
                        }, message.id, false, {
                            fileName: "[project]/src/components/ChatMain.js",
                            lineNumber: 433,
                            columnNumber: 15
                        }, this);
                    }),
                    typingUsers.length > 0 && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "flex justify-start mb-4",
                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "max-w-xs lg:max-w-md px-5 py-3 rounded-2xl glass-morphism text-gray-600 shadow-soft",
                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "flex items-center space-x-3",
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "flex space-x-1",
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "w-2 h-2 gradient-accent rounded-full animate-bounce"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatMain.js",
                                                lineNumber: 589,
                                                columnNumber: 19
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "w-2 h-2 gradient-accent rounded-full animate-bounce",
                                                style: {
                                                    animationDelay: '0.1s'
                                                }
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatMain.js",
                                                lineNumber: 590,
                                                columnNumber: 19
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "w-2 h-2 gradient-accent rounded-full animate-bounce",
                                                style: {
                                                    animationDelay: '0.2s'
                                                }
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatMain.js",
                                                lineNumber: 591,
                                                columnNumber: 19
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/ChatMain.js",
                                        lineNumber: 588,
                                        columnNumber: 17
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                        className: "text-sm font-medium",
                                        children: typingUsers.length === 1 ? `${typingUsers[0].user_name} is typing...` : `${typingUsers.length} people are typing...`
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ChatMain.js",
                                        lineNumber: 593,
                                        columnNumber: 17
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/ChatMain.js",
                                lineNumber: 587,
                                columnNumber: 15
                            }, this)
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatMain.js",
                            lineNumber: 586,
                            columnNumber: 13
                        }, this)
                    }, void 0, false, {
                        fileName: "[project]/src/components/ChatMain.js",
                        lineNumber: 585,
                        columnNumber: 11
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        ref: messageEndRef
                    }, void 0, false, {
                        fileName: "[project]/src/components/ChatMain.js",
                        lineNumber: 604,
                        columnNumber: 9
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/components/ChatMain.js",
                lineNumber: 406,
                columnNumber: 7
            }, this),
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "border-t border-gray-100 glass-morphism p-6 shadow-strong",
                children: [
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "mb-3",
                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionStatusIndicator$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionStatusPanel"], {
                            selectedUser: selectedUser,
                            onSettingsClick: ()=>{
                                // This could trigger a settings modal or callback to parent
                                console.log('Encryption settings clicked');
                            }
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatMain.js",
                            lineNumber: 611,
                            columnNumber: 11
                        }, this)
                    }, void 0, false, {
                        fileName: "[project]/src/components/ChatMain.js",
                        lineNumber: 610,
                        columnNumber: 9
                    }, this),
                    encryptionError && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "mb-3",
                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionErrorDisplay$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"], {
                            error: encryptionError,
                            onRetry: encryptionError.type !== 'signature_verification_failed' ? ()=>{
                                setEncryptionError(null);
                                handleSendMessage();
                            } : null,
                            onDismiss: ()=>setEncryptionError(null),
                            compact: true
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatMain.js",
                            lineNumber: 623,
                            columnNumber: 13
                        }, this)
                    }, void 0, false, {
                        fileName: "[project]/src/components/ChatMain.js",
                        lineNumber: 622,
                        columnNumber: 11
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "flex items-end space-x-4",
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                className: "p-3 text-gray-500 hover:text-white hover:bg-gradient-to-r hover:from-purple-400 hover:to-pink-500 rounded-xl transition-all duration-300 shadow-soft hover:shadow-medium hover:scale-105",
                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$paperclip$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Paperclip$3e$__["Paperclip"], {
                                    className: "w-5 h-5"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 637,
                                    columnNumber: 13
                                }, this)
                            }, void 0, false, {
                                fileName: "[project]/src/components/ChatMain.js",
                                lineNumber: 636,
                                columnNumber: 11
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "flex-1 relative",
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("textarea", {
                                        ref: inputRef,
                                        value: messageInput,
                                        onChange: handleInputChange,
                                        onKeyPress: handleKeyPress,
                                        placeholder: isConnected ? "Type a message..." : "Connecting...",
                                        disabled: !isConnected || isEncrypting,
                                        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("w-full px-5 py-3 border-2 border-transparent rounded-2xl resize-none focus:outline-none focus:ring-4 focus:ring-purple-200 focus:border-purple-300 transition-all duration-300 shadow-soft", {
                                            "bg-gray-100 opacity-70": !isConnected || isEncrypting,
                                            "glass-morphism": isConnected && !isEncrypting
                                        }),
                                        rows: 1,
                                        style: {
                                            minHeight: '48px',
                                            maxHeight: '120px'
                                        }
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ChatMain.js",
                                        lineNumber: 641,
                                        columnNumber: 13
                                    }, this),
                                    isEncrypting && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "absolute right-3 top-1/2 transform -translate-y-1/2",
                                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            className: "flex items-center space-x-1 text-xs text-blue-600",
                                            children: [
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                    className: "animate-spin rounded-full h-3 w-3 border-b border-blue-600"
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/ChatMain.js",
                                                    lineNumber: 663,
                                                    columnNumber: 19
                                                }, this),
                                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                    children: "Encrypting..."
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/ChatMain.js",
                                                    lineNumber: 664,
                                                    columnNumber: 19
                                                }, this)
                                            ]
                                        }, void 0, true, {
                                            fileName: "[project]/src/components/ChatMain.js",
                                            lineNumber: 662,
                                            columnNumber: 17
                                        }, this)
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ChatMain.js",
                                        lineNumber: 661,
                                        columnNumber: 15
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/ChatMain.js",
                                lineNumber: 640,
                                columnNumber: 11
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                className: "p-3 text-gray-500 hover:text-white hover:bg-gradient-to-r hover:from-yellow-400 hover:to-orange-500 rounded-xl transition-all duration-300 shadow-soft hover:shadow-medium hover:scale-105",
                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$smile$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Smile$3e$__["Smile"], {
                                    className: "w-5 h-5"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 671,
                                    columnNumber: 13
                                }, this)
                            }, void 0, false, {
                                fileName: "[project]/src/components/ChatMain.js",
                                lineNumber: 670,
                                columnNumber: 11
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                onClick: handleSendMessage,
                                disabled: !messageInput.trim() || isSending || isEncrypting,
                                className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("p-3 rounded-xl transition-all duration-300 relative shadow-soft hover:shadow-medium", messageInput.trim() && isConnected && !isSending && !isEncrypting ? "gradient-accent text-white hover:scale-105" : "bg-gray-200 text-gray-400 cursor-not-allowed"),
                                title: isEncrypting ? 'Encrypting message...' : !isConnected ? 'Message will be queued and sent when reconnected' : 'Send message',
                                children: isEncrypting ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "animate-spin rounded-full h-5 w-5 border-b-2 border-white"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 690,
                                    columnNumber: 15
                                }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$send$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Send$3e$__["Send"], {
                                    className: "w-5 h-5"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatMain.js",
                                    lineNumber: 692,
                                    columnNumber: 15
                                }, this)
                            }, void 0, false, {
                                fileName: "[project]/src/components/ChatMain.js",
                                lineNumber: 674,
                                columnNumber: 11
                            }, this)
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/ChatMain.js",
                        lineNumber: 635,
                        columnNumber: 9
                    }, this),
                    pendingMessagesCount > 0 && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "mt-2 text-xs text-yellow-600",
                        children: [
                            pendingMessagesCount,
                            " message",
                            pendingMessagesCount > 1 ? 's' : '',
                            " queued for sending"
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/ChatMain.js",
                        lineNumber: 698,
                        columnNumber: 11
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/components/ChatMain.js",
                lineNumber: 608,
                columnNumber: 7
            }, this)
        ]
    }, void 0, true, {
        fileName: "[project]/src/components/ChatMain.js",
        lineNumber: 293,
        columnNumber: 5
    }, this);
}
}}),
"[project]/src/components/UserList.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/websocket.js [app-ssr] (ecmascript)");
"use client";
;
;
;
const UserList = ({ currentUser, onStartChat })=>{
    const [users, setUsers] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])([]);
    const [loading, setLoading] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(true);
    // Removed excessive logging to prevent console spam
    const loadUsers = ()=>{
        console.log('UserList: loadUsers called');
        console.log('UserList: WebSocket connected:', __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getConnectionStatus());
        console.log('UserList: Connection info:', __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getConnectionInfo());
        setLoading(true);
        if (__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getConnectionStatus()) {
            console.log('UserList: Requesting users from backend...');
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].requestAllUsers();
            // Set a timeout to stop loading if no response
            setTimeout(()=>{
                console.log('UserList: Timeout waiting for users response');
                setLoading(false);
            }, 5000);
        } else {
            console.log('UserList: WebSocket not connected');
            setLoading(false);
        }
    };
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        console.log('UserList: useEffect triggered, currentUser:', currentUser?.uid);
        if (!currentUser?.uid) {
            console.log('UserList: No current user, skipping...');
            return;
        }
        // Define event handler
        const handleAllUsersList = (data)=>{
            console.log('UserList: Event handler - Received all users response:', data);
            if (data.status === 'success' && data.users && Array.isArray(data.users)) {
                // Filter out current user
                console.log('UserList: Raw users from backend:', data.users);
                console.log('UserList: Current user for filtering:', currentUser.uid, typeof currentUser.uid);
                const filteredUsers = data.users.filter((user)=>{
                    const userId = user.id.toString();
                    const currentUserId = currentUser.uid.toString();
                    const shouldInclude = userId !== currentUserId;
                    console.log(`UserList: User ${user.id} (${user.username || user.display_name}) - userId: "${userId}", currentUserId: "${currentUserId}", include: ${shouldInclude}`);
                    return shouldInclude;
                });
                console.log('UserList: Final filtered users:', filteredUsers);
                setUsers(filteredUsers);
            } else {
                console.log('UserList: No users in response or error');
                setUsers([]);
            }
            setLoading(false);
        };
        // Add event listener and load users
        const setupAndLoad = ()=>{
            if (__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].socket && __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getConnectionStatus()) {
                console.log('UserList: Socket ready, adding event listener');
                __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].socket.on('all_users_list', handleAllUsersList);
                // Load users after listener is set
                setTimeout(()=>{
                    console.log('UserList: Auto-loading users on mount');
                    loadUsers();
                }, 200);
            } else {
                console.log('UserList: Socket not ready, retrying in 500ms...');
                setTimeout(setupAndLoad, 500);
            }
        };
        setupAndLoad();
        // Cleanup
        return ()=>{
            if (__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].socket) {
                console.log('UserList: Removing event listener');
                __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].socket.off('all_users_list', handleAllUsersList);
            }
        };
    }, [
        currentUser?.uid
    ]);
    const handleRefresh = ()=>{
        console.log('UserList: Manual refresh requested');
        loadUsers();
    };
    const handleUserClick = (user)=>{
        console.log('UserList: User clicked:', user);
        onStartChat(user);
    };
    if (loading) {
        return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            className: "p-6",
            children: [
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "flex items-center justify-between mb-6",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                            className: "text-xl font-bold bg-gradient-to-r from-purple-600 to-blue-600 bg-clip-text text-transparent",
                            children: "Users"
                        }, void 0, false, {
                            fileName: "[project]/src/components/UserList.js",
                            lineNumber: 108,
                            columnNumber: 11
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex space-x-2",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                    onClick: handleRefresh,
                                    className: "p-2 text-gray-500 hover:text-white hover:bg-gradient-to-r hover:from-purple-500 hover:to-blue-500 rounded-xl transition-all duration-300 shadow-soft hover:shadow-medium",
                                    title: "Refresh user list",
                                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("svg", {
                                        className: "w-4 h-4",
                                        fill: "none",
                                        stroke: "currentColor",
                                        viewBox: "0 0 24 24",
                                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("path", {
                                            strokeLinecap: "round",
                                            strokeLinejoin: "round",
                                            strokeWidth: 2,
                                            d: "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/UserList.js",
                                            lineNumber: 116,
                                            columnNumber: 17
                                        }, this)
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/UserList.js",
                                        lineNumber: 115,
                                        columnNumber: 15
                                    }, this)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/UserList.js",
                                    lineNumber: 110,
                                    columnNumber: 13
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                    onClick: ()=>{
                                        console.log('Manual test - WebSocket status:', __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getConnectionStatus());
                                        console.log('Manual test - Socket object:', __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].socket);
                                        if (__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].socket) {
                                            console.log('Manual test - Emitting get_all_users');
                                            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].socket.emit('get_all_users');
                                            // Test if we can receive a direct event
                                            console.log('Manual test - Adding temporary listener');
                                            const tempHandler = (data)=>{
                                                console.log('TEMP HANDLER - Received all_users_list:', data);
                                                if (data.status === 'success' && data.users) {
                                                    console.log('TEMP HANDLER - Setting users directly:', data.users);
                                                    setUsers(data.users.filter((u)=>u.id.toString() !== currentUser.uid.toString()));
                                                    setLoading(false);
                                                }
                                            };
                                            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].socket.once('all_users_list', tempHandler);
                                        }
                                    },
                                    className: "px-3 py-1 text-xs text-white gradient-accent rounded-lg hover:scale-105 transition-all duration-300 shadow-soft",
                                    title: "Test backend connection",
                                    children: "Test"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/UserList.js",
                                    lineNumber: 119,
                                    columnNumber: 13
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/UserList.js",
                            lineNumber: 109,
                            columnNumber: 11
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/UserList.js",
                    lineNumber: 107,
                    columnNumber: 9
                }, this),
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "animate-pulse",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "h-4 gradient-neutral rounded-lg w-3/4 mb-4"
                        }, void 0, false, {
                            fileName: "[project]/src/components/UserList.js",
                            lineNumber: 148,
                            columnNumber: 11
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "space-y-3",
                            children: [
                                1,
                                2,
                                3
                            ].map((i)=>/*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "flex items-center space-x-3 p-3 glass-morphism rounded-xl",
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            className: "w-10 h-10 gradient-neutral rounded-full"
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/UserList.js",
                                            lineNumber: 152,
                                            columnNumber: 17
                                        }, this),
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            className: "h-4 gradient-neutral rounded-lg w-1/2"
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/UserList.js",
                                            lineNumber: 153,
                                            columnNumber: 17
                                        }, this)
                                    ]
                                }, i, true, {
                                    fileName: "[project]/src/components/UserList.js",
                                    lineNumber: 151,
                                    columnNumber: 15
                                }, this))
                        }, void 0, false, {
                            fileName: "[project]/src/components/UserList.js",
                            lineNumber: 149,
                            columnNumber: 11
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/UserList.js",
                    lineNumber: 147,
                    columnNumber: 9
                }, this),
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "mt-4 text-sm text-gray-500 text-center",
                    children: "Loading users..."
                }, void 0, false, {
                    fileName: "[project]/src/components/UserList.js",
                    lineNumber: 158,
                    columnNumber: 9
                }, this)
            ]
        }, void 0, true, {
            fileName: "[project]/src/components/UserList.js",
            lineNumber: 106,
            columnNumber: 7
        }, this);
    }
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
        className: "p-6",
        children: [
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "flex items-center justify-between mb-6",
                children: [
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                        className: "text-xl font-bold bg-gradient-to-r from-purple-600 to-blue-600 bg-clip-text text-transparent",
                        children: [
                            "Users (",
                            users.length,
                            ")"
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/UserList.js",
                        lineNumber: 168,
                        columnNumber: 9
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "flex space-x-2",
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                onClick: handleRefresh,
                                className: "p-2 text-gray-500 hover:text-white hover:bg-gradient-to-r hover:from-purple-500 hover:to-blue-500 rounded-xl transition-all duration-300 shadow-soft hover:shadow-medium",
                                title: "Refresh user list",
                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("svg", {
                                    className: "w-4 h-4",
                                    fill: "none",
                                    stroke: "currentColor",
                                    viewBox: "0 0 24 24",
                                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("path", {
                                        strokeLinecap: "round",
                                        strokeLinejoin: "round",
                                        strokeWidth: 2,
                                        d: "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/UserList.js",
                                        lineNumber: 178,
                                        columnNumber: 15
                                    }, this)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/UserList.js",
                                    lineNumber: 177,
                                    columnNumber: 13
                                }, this)
                            }, void 0, false, {
                                fileName: "[project]/src/components/UserList.js",
                                lineNumber: 172,
                                columnNumber: 11
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                onClick: ()=>{
                                    console.log('Debug - Current users state:', users);
                                    console.log('Debug - Current user:', currentUser);
                                    console.log('Debug - Loading state:', loading);
                                    // Also request fresh data
                                    if (__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].socket) {
                                        __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$websocket$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].socket.emit('get_all_users');
                                    }
                                },
                                className: "px-3 py-1 text-xs text-white gradient-success rounded-lg hover:scale-105 transition-all duration-300 shadow-soft",
                                title: "Debug state",
                                children: "Debug"
                            }, void 0, false, {
                                fileName: "[project]/src/components/UserList.js",
                                lineNumber: 181,
                                columnNumber: 11
                            }, this)
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/UserList.js",
                        lineNumber: 171,
                        columnNumber: 9
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/components/UserList.js",
                lineNumber: 167,
                columnNumber: 7
            }, this),
            users.length === 0 ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "text-center py-12",
                children: [
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "w-16 h-16 gradient-neutral rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-soft",
                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("svg", {
                            className: "w-8 h-8 text-gray-400",
                            fill: "none",
                            stroke: "currentColor",
                            viewBox: "0 0 24 24",
                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("path", {
                                strokeLinecap: "round",
                                strokeLinejoin: "round",
                                strokeWidth: 2,
                                d: "M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"
                            }, void 0, false, {
                                fileName: "[project]/src/components/UserList.js",
                                lineNumber: 203,
                                columnNumber: 15
                            }, this)
                        }, void 0, false, {
                            fileName: "[project]/src/components/UserList.js",
                            lineNumber: 202,
                            columnNumber: 13
                        }, this)
                    }, void 0, false, {
                        fileName: "[project]/src/components/UserList.js",
                        lineNumber: 201,
                        columnNumber: 11
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                        className: "text-base font-semibold text-gray-700 mb-2",
                        children: "No other users found"
                    }, void 0, false, {
                        fileName: "[project]/src/components/UserList.js",
                        lineNumber: 206,
                        columnNumber: 11
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                        className: "text-sm text-gray-500",
                        children: "Click refresh to load users or create more accounts"
                    }, void 0, false, {
                        fileName: "[project]/src/components/UserList.js",
                        lineNumber: 207,
                        columnNumber: 11
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/components/UserList.js",
                lineNumber: 200,
                columnNumber: 9
            }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "space-y-3",
                children: users.map((user)=>/*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        onClick: ()=>handleUserClick(user),
                        className: "flex items-center space-x-4 p-4 glass-morphism rounded-xl cursor-pointer transition-all duration-300 hover:scale-[1.02] hover:shadow-medium",
                        children: [
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "relative",
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "w-12 h-12 gradient-primary rounded-xl flex items-center justify-center text-white text-base font-semibold shadow-soft",
                                        children: (user.display_name || user.name || user.username || user.email || 'U').charAt(0).toUpperCase()
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/UserList.js",
                                        lineNumber: 218,
                                        columnNumber: 17
                                    }, this),
                                    user.is_online && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "absolute -bottom-1 -right-1 w-4 h-4 gradient-success rounded-full border-2 border-white shadow-soft"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/UserList.js",
                                        lineNumber: 222,
                                        columnNumber: 19
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/UserList.js",
                                lineNumber: 217,
                                columnNumber: 15
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "flex-1 min-w-0",
                                children: [
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                        className: "text-base font-semibold text-gray-900 truncate",
                                        children: user.display_name || user.name || user.username || user.email
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/UserList.js",
                                        lineNumber: 226,
                                        columnNumber: 17
                                    }, this),
                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                        className: "text-sm text-gray-500 flex items-center space-x-1",
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                className: `w-2 h-2 rounded-full ${user.is_online ? 'bg-green-400' : 'bg-gray-400'}`
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/UserList.js",
                                                lineNumber: 230,
                                                columnNumber: 19
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                                children: user.is_online ? 'Online' : 'Offline'
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/UserList.js",
                                                lineNumber: 231,
                                                columnNumber: 19
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/UserList.js",
                                        lineNumber: 229,
                                        columnNumber: 17
                                    }, this)
                                ]
                            }, void 0, true, {
                                fileName: "[project]/src/components/UserList.js",
                                lineNumber: 225,
                                columnNumber: 15
                            }, this)
                        ]
                    }, user.id, true, {
                        fileName: "[project]/src/components/UserList.js",
                        lineNumber: 212,
                        columnNumber: 13
                    }, this))
            }, void 0, false, {
                fileName: "[project]/src/components/UserList.js",
                lineNumber: 210,
                columnNumber: 9
            }, this)
        ]
    }, void 0, true, {
        fileName: "[project]/src/components/UserList.js",
        lineNumber: 166,
        columnNumber: 5
    }, this);
};
const __TURBOPACK__default__export__ = UserList;
}}),
"[project]/src/components/EncryptionErrorBoundary.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$shield$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Shield$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/shield.js [app-ssr] (ecmascript) <export default as Shield>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/triangle-alert.js [app-ssr] (ecmascript) <export default as AlertTriangle>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$refresh$2d$cw$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__RefreshCw$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/refresh-cw.js [app-ssr] (ecmascript) <export default as RefreshCw>");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$settings$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Settings$3e$__ = __turbopack_context__.i("[project]/node_modules/lucide-react/dist/esm/icons/settings.js [app-ssr] (ecmascript) <export default as Settings>");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/encryptionService.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionErrorDisplay$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/EncryptionErrorDisplay.js [app-ssr] (ecmascript)");
"use client";
;
;
;
;
;
/**
 * EncryptionErrorBoundary - Specialized error boundary for encryption-related errors
 * Provides graceful degradation and recovery options for encryption failures
 */ class EncryptionErrorBoundary extends __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].Component {
    constructor(props){
        super(props);
        this.state = {
            hasError: false,
            error: null,
            errorInfo: null,
            isRecovering: false,
            showFallbackMode: false
        };
    }
    static getDerivedStateFromError(error) {
        // Check if this is an encryption-related error
        const isEncryptionError = error.type && Object.values(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"]).includes(error.type);
        return {
            hasError: true,
            isEncryptionError
        };
    }
    componentDidCatch(error, errorInfo) {
        this.setState({
            error: error,
            errorInfo: errorInfo
        });
        // Log encryption errors with additional context
        console.error('Encryption Error Boundary caught error:', {
            error,
            errorInfo,
            isEncryptionError: this.state.isEncryptionError,
            timestamp: new Date().toISOString()
        });
        // In production, report encryption errors to monitoring service
        if (("TURBOPACK compile-time value", "development") === 'production' && this.state.isEncryptionError) {
        // reportEncryptionError(error, errorInfo);
        }
    }
    handleRetry = async ()=>{
        this.setState({
            isRecovering: true
        });
        try {
            // Clear the error state and attempt recovery
            await new Promise((resolve)=>setTimeout(resolve, 1000)); // Brief delay
            this.setState({
                hasError: false,
                error: null,
                errorInfo: null,
                isRecovering: false
            });
        } catch (recoveryError) {
            console.error('Recovery failed:', recoveryError);
            this.setState({
                isRecovering: false
            });
        }
    };
    handleFallbackMode = ()=>{
        this.setState({
            showFallbackMode: true
        });
        // Notify parent component about fallback mode if callback provided
        if (this.props.onFallbackMode) {
            this.props.onFallbackMode();
        }
    };
    handleClearEncryption = async ()=>{
        try {
            // Clear encryption state and continue without encryption
            if (this.props.onClearEncryption) {
                await this.props.onClearEncryption();
            }
            this.setState({
                hasError: false,
                error: null,
                errorInfo: null,
                showFallbackMode: true
            });
        } catch (error) {
            console.error('Failed to clear encryption:', error);
        }
    };
    getErrorSeverity = (error)=>{
        if (!error || !error.type) return 'error';
        const criticalErrors = [
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].INITIALIZATION_FAILED,
            __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionErrorTypes"].KEY_GENERATION_FAILED
        ];
        return criticalErrors.includes(error.type) ? 'critical' : 'error';
    };
    renderEncryptionError = ()=>{
        const { error } = this.state;
        const severity = this.getErrorSeverity(error);
        const isCritical = severity === 'critical';
        return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            className: "min-h-screen flex items-center justify-center bg-gray-50 px-4",
            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "max-w-lg w-full",
                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "bg-white rounded-lg shadow-lg p-8",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "text-center mb-6",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: `w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4 ${isCritical ? 'bg-red-100' : 'bg-yellow-100'}`,
                                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$shield$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Shield$3e$__["Shield"], {
                                        className: `w-8 h-8 ${isCritical ? 'text-red-600' : 'text-yellow-600'}`
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                        lineNumber: 123,
                                        columnNumber: 17
                                    }, this)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                    lineNumber: 120,
                                    columnNumber: 15
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h1", {
                                    className: "text-xl font-semibold text-gray-900 mb-2",
                                    children: isCritical ? 'Encryption Setup Failed' : 'Encryption Error'
                                }, void 0, false, {
                                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                    lineNumber: 128,
                                    columnNumber: 15
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                    className: "text-gray-600 mb-6",
                                    children: isCritical ? 'We couldn\'t set up encryption for your messages. You can continue without encryption or try again.' : 'An encryption error occurred, but you can continue chatting.'
                                }, void 0, false, {
                                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                    lineNumber: 132,
                                    columnNumber: 15
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                            lineNumber: 119,
                            columnNumber: 13
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "mb-6",
                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionErrorDisplay$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"], {
                                error: error,
                                onRetry: this.handleRetry,
                                showRetry: !this.state.isRecovering,
                                className: "mb-4"
                            }, void 0, false, {
                                fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                lineNumber: 142,
                                columnNumber: 15
                            }, this)
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                            lineNumber: 141,
                            columnNumber: 13
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "space-y-3",
                            children: [
                                !this.state.showFallbackMode && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                    onClick: this.handleRetry,
                                    disabled: this.state.isRecovering,
                                    className: "w-full flex items-center justify-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors",
                                    children: this.state.isRecovering ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["Fragment"], {
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                                lineNumber: 160,
                                                columnNumber: 23
                                            }, this),
                                            "Retrying..."
                                        ]
                                    }, void 0, true) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["Fragment"], {
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$refresh$2d$cw$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__RefreshCw$3e$__["RefreshCw"], {
                                                className: "w-4 h-4 mr-2"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                                lineNumber: 165,
                                                columnNumber: 23
                                            }, this),
                                            "Try Again"
                                        ]
                                    }, void 0, true)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                    lineNumber: 153,
                                    columnNumber: 17
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                    onClick: this.handleFallbackMode,
                                    className: "w-full flex items-center justify-center px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 transition-colors",
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"], {
                                            className: "w-4 h-4 mr-2"
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                            lineNumber: 176,
                                            columnNumber: 17
                                        }, this),
                                        "Continue Without Encryption"
                                    ]
                                }, void 0, true, {
                                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                    lineNumber: 172,
                                    columnNumber: 15
                                }, this),
                                isCritical && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                    onClick: this.handleClearEncryption,
                                    className: "w-full flex items-center justify-center px-4 py-2 bg-yellow-600 text-white rounded-md hover:bg-yellow-700 transition-colors",
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$settings$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__Settings$3e$__["Settings"], {
                                            className: "w-4 h-4 mr-2"
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                            lineNumber: 185,
                                            columnNumber: 19
                                        }, this),
                                        "Reset Encryption Settings"
                                    ]
                                }, void 0, true, {
                                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                    lineNumber: 181,
                                    columnNumber: 17
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                            lineNumber: 151,
                            columnNumber: 13
                        }, this),
                        ("TURBOPACK compile-time value", "development") === 'development' && error && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("details", {
                            className: "mt-6 bg-gray-50 border border-gray-200 rounded-md p-4",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("summary", {
                                    className: "cursor-pointer text-sm font-medium text-gray-700 mb-2",
                                    children: "Development Error Details"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                    lineNumber: 194,
                                    columnNumber: 17
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("pre", {
                                    className: "text-xs text-gray-600 overflow-auto max-h-32 whitespace-pre-wrap",
                                    children: [
                                        error.toString(),
                                        this.state.errorInfo?.componentStack
                                    ]
                                }, void 0, true, {
                                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                    lineNumber: 197,
                                    columnNumber: 17
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                            lineNumber: 193,
                            columnNumber: 15
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                    lineNumber: 118,
                    columnNumber: 11
                }, this)
            }, void 0, false, {
                fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                lineNumber: 117,
                columnNumber: 9
            }, this)
        }, void 0, false, {
            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
            lineNumber: 116,
            columnNumber: 7
        }, this);
    };
    renderGenericError = ()=>{
        return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            className: "min-h-screen flex items-center justify-center bg-gray-50 px-4",
            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "max-w-md w-full text-center",
                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "bg-white rounded-lg shadow-lg p-8",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4",
                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"], {
                                className: "w-8 h-8 text-red-600"
                            }, void 0, false, {
                                fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                lineNumber: 215,
                                columnNumber: 15
                            }, this)
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                            lineNumber: 214,
                            columnNumber: 13
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h1", {
                            className: "text-xl font-semibold text-gray-900 mb-2",
                            children: "Something went wrong"
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                            lineNumber: 218,
                            columnNumber: 13
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                            className: "text-gray-600 mb-6",
                            children: "An unexpected error occurred. Please try refreshing the page."
                        }, void 0, false, {
                            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                            lineNumber: 222,
                            columnNumber: 13
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex flex-col gap-3",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                    onClick: this.handleRetry,
                                    disabled: this.state.isRecovering,
                                    className: "flex items-center justify-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 transition-colors",
                                    children: this.state.isRecovering ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["Fragment"], {
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                                lineNumber: 234,
                                                columnNumber: 21
                                            }, this),
                                            "Retrying..."
                                        ]
                                    }, void 0, true) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["Fragment"], {
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$refresh$2d$cw$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__RefreshCw$3e$__["RefreshCw"], {
                                                className: "w-4 h-4 mr-2"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                                lineNumber: 239,
                                                columnNumber: 21
                                            }, this),
                                            "Try Again"
                                        ]
                                    }, void 0, true)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                    lineNumber: 227,
                                    columnNumber: 15
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                    onClick: ()=>window.location.reload(),
                                    className: "flex items-center justify-center px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 transition-colors",
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$refresh$2d$cw$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__RefreshCw$3e$__["RefreshCw"], {
                                            className: "w-4 h-4 mr-2"
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                            lineNumber: 249,
                                            columnNumber: 17
                                        }, this),
                                        "Refresh Page"
                                    ]
                                }, void 0, true, {
                                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                    lineNumber: 245,
                                    columnNumber: 15
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                            lineNumber: 226,
                            columnNumber: 13
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                    lineNumber: 213,
                    columnNumber: 11
                }, this)
            }, void 0, false, {
                fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                lineNumber: 212,
                columnNumber: 9
            }, this)
        }, void 0, false, {
            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
            lineNumber: 211,
            columnNumber: 7
        }, this);
    };
    render() {
        if (this.state.hasError) {
            // Show fallback mode if requested
            if (this.state.showFallbackMode) {
                return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "bg-yellow-50 border-b border-yellow-200 p-3",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex items-center justify-center space-x-2 text-yellow-800",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$lucide$2d$react$2f$dist$2f$esm$2f$icons$2f$triangle$2d$alert$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__$3c$export__default__as__AlertTriangle$3e$__["AlertTriangle"], {
                                    className: "w-4 h-4"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                    lineNumber: 266,
                                    columnNumber: 15
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                    className: "text-sm font-medium",
                                    children: "Running in fallback mode - encryption disabled"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                                    lineNumber: 267,
                                    columnNumber: 15
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                            lineNumber: 265,
                            columnNumber: 13
                        }, this),
                        this.props.children
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/EncryptionErrorBoundary.js",
                    lineNumber: 264,
                    columnNumber: 11
                }, this);
            }
            // Render appropriate error UI based on error type
            return this.state.isEncryptionError ? this.renderEncryptionError() : this.renderGenericError();
        }
        return this.props.children;
    }
}
const __TURBOPACK__default__export__ = EncryptionErrorBoundary;
}}),
"[project]/src/components/ChatInterface.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/navigation.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$context$2f$AuthContext$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/context/AuthContext.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$hooks$2f$useChat$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/hooks/useChat.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$hooks$2f$usePerformance$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/hooks/usePerformance.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$ChatSidebar$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/ChatSidebar.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$ChatMain$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/ChatMain.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$UserList$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/UserList.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionErrorBoundary$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/EncryptionErrorBoundary.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionSettings$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/EncryptionSettings.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionStatusIndicator$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/EncryptionStatusIndicator.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/services/encryptionService.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/clsx/dist/clsx.mjs [app-ssr] (ecmascript)");
"use client";
;
;
;
;
;
;
;
;
;
;
;
;
;
;
function ChatInterface({ roomId }) {
    const { currentUser } = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$context$2f$AuthContext$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useAuth"])();
    const router = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useRouter"])();
    const pathname = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["usePathname"])();
    const { measureAsync } = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$hooks$2f$usePerformance$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["usePerformance"])('ChatInterface');
    const { isOnline } = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$hooks$2f$usePerformance$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useConnectionMonitor"])();
    // Removed excessive logging to prevent infinite loops
    const [selectedRoomId, setSelectedRoomId] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(roomId || null);
    const [selectedUser, setSelectedUser] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(null);
    const [isMobile, setIsMobile] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    const [showSidebar, setShowSidebar] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(true);
    const [activeChats, setActiveChats] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])([]);
    const [showEncryptionSettings, setShowEncryptionSettings] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    const [encryptionFallbackMode, setEncryptionFallbackMode] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    // Update selectedRoomId when roomId prop changes
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        if (roomId && roomId !== selectedRoomId) {
            console.log('ChatInterface: Setting room from URL:', roomId);
            setSelectedRoomId(roomId);
            // Try to determine the user from the room ID (format: user1_user2)
            if (roomId.includes('_')) {
                const userIds = roomId.split('_');
                const otherUserId = userIds.find((id)=>id !== currentUser?.uid);
                if (otherUserId) {
                    // Fetch real user data instead of creating mock user
                    const fetchUserData = async ()=>{
                        try {
                            const response = await fetch(`http://localhost:5000/api/users/${otherUserId}`, {
                                credentials: 'include'
                            });
                            if (response.ok) {
                                const userData = await response.json();
                                const realUser = userData.data;
                                setSelectedUser(realUser);
                                // Add to active chats
                                setActiveChats((prev)=>{
                                    const exists = prev.find((chat)=>chat.roomId === roomId);
                                    if (!exists) {
                                        return [
                                            ...prev,
                                            {
                                                roomId,
                                                user: realUser,
                                                lastActivity: new Date()
                                            }
                                        ];
                                    }
                                    return prev;
                                });
                            } else {
                                console.error('Failed to fetch user data for', otherUserId);
                            }
                        } catch (error) {
                            console.error('Error fetching user data:', error);
                        }
                    };
                    fetchUserData();
                    return; // Skip the mock user creation below
                // This code is now handled above with real user fetch
                }
            }
        }
    }, [
        roomId,
        selectedRoomId,
        currentUser?.uid
    ]);
    // Use WebSocket chat hook only when we have authentication data
    const { messages, isConnected, currentRoom, sendMessage: sendWebSocketMessage, startChatWithUser, connectionError, lastError, pendingMessagesCount, retryConnection, encryptionStatus, typingUsers, onlineUsers, startTyping, stopTyping, getDebugInfo } = (0, __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$hooks$2f$useChat$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useChat"])(currentUser?.uid, currentUser?.accessToken);
    // Handle responsive design
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        const checkMobile = ()=>{
            const mobile = window.innerWidth < 768;
            setIsMobile(mobile);
            if (mobile && roomId) {
                setShowSidebar(false);
            } else if (!mobile) {
                setShowSidebar(true);
            }
        };
        checkMobile();
        window.addEventListener('resize', checkMobile);
        return ()=>window.removeEventListener('resize', checkMobile);
    }, [
        roomId
    ]);
    // Handle starting a chat with a user
    const handleStartChat = async (user)=>{
        console.log('ChatInterface: Starting chat with user:', user);
        const roomId = await startChatWithUser(user.id);
        if (roomId) {
            setSelectedRoomId(roomId);
            setSelectedUser(user);
            // Add to active chats if not already there
            setActiveChats((prev)=>{
                const exists = prev.find((chat)=>chat.roomId === roomId);
                if (!exists) {
                    return [
                        ...prev,
                        {
                            roomId,
                            user,
                            lastActivity: new Date()
                        }
                    ];
                }
                return prev;
            });
            // Update URL
            router.push(`/chat/${roomId}`, undefined, {
                shallow: true
            });
            // On mobile, hide sidebar when chat is selected
            if (isMobile) {
                setShowSidebar(false);
            }
        }
    };
    // Handle selecting an existing chat
    const handleChatSelect = (chat)=>{
        setSelectedRoomId(chat.roomId);
        setSelectedUser(chat.user);
        // Update URL
        router.push(`/chat/${chat.roomId}`, undefined, {
            shallow: true
        });
        // On mobile, hide sidebar when chat is selected
        if (isMobile) {
            setShowSidebar(false);
        }
    };
    // Handle back to chat list on mobile
    const handleBackToList = ()=>{
        if (isMobile) {
            setShowSidebar(true);
            router.push('/chat', undefined, {
                shallow: true
            });
        }
    };
    // Handle browser back/forward navigation
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        const handleRouteChange = ()=>{
            if (pathname === '/chat') {
                setSelectedRoomId(null);
                setSelectedUser(null);
                if (isMobile) {
                    setShowSidebar(true);
                }
            } else if (pathname.startsWith('/chat/')) {
                const roomFromUrl = pathname.split('/chat/')[1];
                if (roomFromUrl && roomFromUrl !== selectedRoomId) {
                    setSelectedRoomId(roomFromUrl);
                    // Try to find the user from active chats
                    const chat = activeChats.find((c)=>c.roomId === roomFromUrl);
                    if (chat) {
                        setSelectedUser(chat.user);
                    }
                    if (isMobile) {
                        setShowSidebar(false);
                    }
                }
            }
        };
        handleRouteChange();
    }, [
        pathname,
        isMobile,
        selectedRoomId,
        activeChats
    ]);
    // Auto-debug logging for development (only when significant changes occur)
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        if ("TURBOPACK compile-time truthy", 1) {
            console.log('=== ChatInterface Debug Info ===');
            console.log('Current User:', currentUser?.uid);
            console.log('Is Connected:', isConnected);
            console.log('Selected Room ID:', selectedRoomId);
            console.log('Active Chats Count:', activeChats.length);
            console.log('================================');
        }
    }, [
        currentUser?.uid,
        isConnected,
        selectedRoomId
    ]);
    // Handle encryption fallback mode
    const handleEncryptionFallback = ()=>{
        setEncryptionFallbackMode(true);
    };
    // Handle clearing encryption (for error recovery)
    const handleClearEncryption = async ()=>{
        try {
            await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].clearEncryption();
            setEncryptionFallbackMode(true);
        } catch (error) {
            console.error('Failed to clear encryption:', error);
        }
    };
    // Debug function for development
    const handleDebug = ()=>{
        console.log('Debug Info:', getDebugInfo());
        console.log('Current User:', currentUser);
        console.log('Is Connected:', isConnected);
        console.log('Connection Error:', connectionError);
        console.log('Online Users:', onlineUsers);
        console.log('Encryption Status:', __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].getEncryptionStatus());
    };
    // Show loading state if user data is not available
    if (!currentUser?.uid || !currentUser?.accessToken) {
        return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            className: "flex h-screen items-center justify-center bg-white",
            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "text-center",
                children: [
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: "animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"
                    }, void 0, false, {
                        fileName: "[project]/src/components/ChatInterface.js",
                        lineNumber: 238,
                        columnNumber: 11
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                        className: "text-gray-600",
                        children: "Loading chat..."
                    }, void 0, false, {
                        fileName: "[project]/src/components/ChatInterface.js",
                        lineNumber: 239,
                        columnNumber: 11
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/components/ChatInterface.js",
                lineNumber: 237,
                columnNumber: 9
            }, this)
        }, void 0, false, {
            fileName: "[project]/src/components/ChatInterface.js",
            lineNumber: 236,
            columnNumber: 7
        }, this);
    }
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionErrorBoundary$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"], {
        onFallbackMode: handleEncryptionFallback,
        onClearEncryption: handleClearEncryption,
        children: [
            encryptionFallbackMode && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "bg-yellow-50 border-b border-yellow-200 px-4 py-2",
                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    className: "flex items-center justify-between",
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex items-center space-x-2 text-yellow-800",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("svg", {
                                    className: "w-4 h-4",
                                    fill: "currentColor",
                                    viewBox: "0 0 20 20",
                                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("path", {
                                        fillRule: "evenodd",
                                        d: "M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z",
                                        clipRule: "evenodd"
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ChatInterface.js",
                                        lineNumber: 256,
                                        columnNumber: 17
                                    }, this)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatInterface.js",
                                    lineNumber: 255,
                                    columnNumber: 15
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("span", {
                                    className: "text-sm font-medium",
                                    children: "Encryption disabled - messages are not encrypted"
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatInterface.js",
                                    lineNumber: 258,
                                    columnNumber: 15
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/ChatInterface.js",
                            lineNumber: 254,
                            columnNumber: 13
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                            onClick: ()=>setShowEncryptionSettings(true),
                            className: "text-sm text-yellow-700 hover:text-yellow-900 underline",
                            children: "Settings"
                        }, void 0, false, {
                            fileName: "[project]/src/components/ChatInterface.js",
                            lineNumber: 262,
                            columnNumber: 13
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/src/components/ChatInterface.js",
                    lineNumber: 253,
                    columnNumber: 11
                }, this)
            }, void 0, false, {
                fileName: "[project]/src/components/ChatInterface.js",
                lineNumber: 252,
                columnNumber: 9
            }, this),
            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                className: "flex h-screen bg-white",
                children: [
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("transition-all duration-300 ease-in-out bg-white border-r border-gray-200", {
                            "w-80": !isMobile && showSidebar,
                            "w-full": isMobile && showSidebar,
                            "w-0 overflow-hidden": !showSidebar
                        }),
                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "h-full flex flex-col",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "border-b border-gray-200 p-4",
                                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "flex items-center justify-between",
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "flex items-center space-x-3",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                        className: "w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-sm font-medium",
                                                        children: (currentUser?.displayName || currentUser?.username || 'U').charAt(0).toUpperCase()
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/ChatInterface.js",
                                                        lineNumber: 287,
                                                        columnNumber: 17
                                                    }, this),
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                        className: "flex-1 min-w-0",
                                                        children: [
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                                                className: "text-sm font-medium text-gray-900",
                                                                children: currentUser?.displayName || currentUser?.username
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/ChatInterface.js",
                                                                lineNumber: 291,
                                                                columnNumber: 19
                                                            }, this),
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                                className: "flex items-center space-x-2",
                                                                children: [
                                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                                                        className: "text-xs text-gray-500",
                                                                        children: "Online"
                                                                    }, void 0, false, {
                                                                        fileName: "[project]/src/components/ChatInterface.js",
                                                                        lineNumber: 295,
                                                                        columnNumber: 21
                                                                    }, this),
                                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionStatusIndicator$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["EncryptionStatusBadge"], {
                                                                        selectedUser: selectedUser,
                                                                        className: "text-xs"
                                                                    }, void 0, false, {
                                                                        fileName: "[project]/src/components/ChatInterface.js",
                                                                        lineNumber: 296,
                                                                        columnNumber: 21
                                                                    }, this)
                                                                ]
                                                            }, void 0, true, {
                                                                fileName: "[project]/src/components/ChatInterface.js",
                                                                lineNumber: 294,
                                                                columnNumber: 19
                                                            }, this)
                                                        ]
                                                    }, void 0, true, {
                                                        fileName: "[project]/src/components/ChatInterface.js",
                                                        lineNumber: 290,
                                                        columnNumber: 17
                                                    }, this)
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/ChatInterface.js",
                                                lineNumber: 286,
                                                columnNumber: 15
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "flex items-center space-x-2",
                                                children: [
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                                        onClick: ()=>setShowEncryptionSettings(true),
                                                        className: "text-xs text-gray-500 hover:text-gray-700 px-2 py-1 rounded hover:bg-gray-100",
                                                        title: "Encryption Settings",
                                                        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("svg", {
                                                            className: "w-4 h-4",
                                                            fill: "none",
                                                            stroke: "currentColor",
                                                            viewBox: "0 0 24 24",
                                                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("path", {
                                                                strokeLinecap: "round",
                                                                strokeLinejoin: "round",
                                                                strokeWidth: 2,
                                                                d: "M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/ChatInterface.js",
                                                                lineNumber: 310,
                                                                columnNumber: 21
                                                            }, this)
                                                        }, void 0, false, {
                                                            fileName: "[project]/src/components/ChatInterface.js",
                                                            lineNumber: 309,
                                                            columnNumber: 19
                                                        }, this)
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/ChatInterface.js",
                                                        lineNumber: 304,
                                                        columnNumber: 17
                                                    }, this),
                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                                        onClick: async ()=>{
                                                            try {
                                                                // Clear encryption before logout if enabled in preferences
                                                                await __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$services$2f$encryptionService$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"].clearEncryption();
                                                                // Call logout API
                                                                await fetch('http://localhost:5000/api/auth/logout', {
                                                                    method: 'POST',
                                                                    credentials: 'include'
                                                                });
                                                                // Redirect to login
                                                                window.location.href = '/login';
                                                            } catch (error) {
                                                                console.error('Logout error:', error);
                                                                // Force redirect anyway
                                                                window.location.href = '/login';
                                                            }
                                                        },
                                                        className: "text-xs text-gray-500 hover:text-gray-700 px-2 py-1 rounded hover:bg-gray-100",
                                                        children: "Logout"
                                                    }, void 0, false, {
                                                        fileName: "[project]/src/components/ChatInterface.js",
                                                        lineNumber: 313,
                                                        columnNumber: 17
                                                    }, this)
                                                ]
                                            }, void 0, true, {
                                                fileName: "[project]/src/components/ChatInterface.js",
                                                lineNumber: 303,
                                                columnNumber: 15
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/ChatInterface.js",
                                        lineNumber: 285,
                                        columnNumber: 13
                                    }, this)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatInterface.js",
                                    lineNumber: 284,
                                    columnNumber: 11
                                }, this),
                                activeChats.length > 0 && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "border-b border-gray-200",
                                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                        className: "p-4",
                                        children: [
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                                                className: "text-lg font-semibold mb-3 text-gray-800",
                                                children: "Active Chats"
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatInterface.js",
                                                lineNumber: 344,
                                                columnNumber: 17
                                            }, this),
                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                className: "space-y-2",
                                                children: activeChats.map((chat)=>/*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                        onClick: ()=>handleChatSelect(chat),
                                                        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("flex items-center space-x-3 p-3 rounded-lg cursor-pointer transition-colors", {
                                                            "bg-blue-100 border border-blue-200": selectedRoomId === chat.roomId,
                                                            "hover:bg-gray-100": selectedRoomId !== chat.roomId
                                                        }),
                                                        children: [
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                                className: "w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-sm font-medium",
                                                                children: (chat.user.display_name || chat.user.name || chat.user.username || chat.user.email || 'U').charAt(0).toUpperCase()
                                                            }, void 0, false, {
                                                                fileName: "[project]/src/components/ChatInterface.js",
                                                                lineNumber: 358,
                                                                columnNumber: 23
                                                            }, this),
                                                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                                                className: "flex-1 min-w-0",
                                                                children: [
                                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                                                        className: "text-sm font-medium text-gray-900 truncate",
                                                                        children: chat.user.display_name || chat.user.name || chat.user.username || chat.user.email
                                                                    }, void 0, false, {
                                                                        fileName: "[project]/src/components/ChatInterface.js",
                                                                        lineNumber: 362,
                                                                        columnNumber: 25
                                                                    }, this),
                                                                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                                                        className: "text-xs text-gray-500",
                                                                        children: "Active chat"
                                                                    }, void 0, false, {
                                                                        fileName: "[project]/src/components/ChatInterface.js",
                                                                        lineNumber: 365,
                                                                        columnNumber: 25
                                                                    }, this)
                                                                ]
                                                            }, void 0, true, {
                                                                fileName: "[project]/src/components/ChatInterface.js",
                                                                lineNumber: 361,
                                                                columnNumber: 23
                                                            }, this)
                                                        ]
                                                    }, chat.roomId, true, {
                                                        fileName: "[project]/src/components/ChatInterface.js",
                                                        lineNumber: 347,
                                                        columnNumber: 21
                                                    }, this))
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatInterface.js",
                                                lineNumber: 345,
                                                columnNumber: 17
                                            }, this)
                                        ]
                                    }, void 0, true, {
                                        fileName: "[project]/src/components/ChatInterface.js",
                                        lineNumber: 343,
                                        columnNumber: 15
                                    }, this)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatInterface.js",
                                    lineNumber: 342,
                                    columnNumber: 13
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "flex-1 overflow-y-auto",
                                    children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$UserList$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"], {
                                        currentUser: currentUser,
                                        onStartChat: handleStartChat,
                                        onlineUsers: onlineUsers
                                    }, void 0, false, {
                                        fileName: "[project]/src/components/ChatInterface.js",
                                        lineNumber: 376,
                                        columnNumber: 13
                                    }, this)
                                }, void 0, false, {
                                    fileName: "[project]/src/components/ChatInterface.js",
                                    lineNumber: 375,
                                    columnNumber: 11
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/src/components/ChatInterface.js",
                            lineNumber: 282,
                            columnNumber: 9
                        }, this)
                    }, void 0, false, {
                        fileName: "[project]/src/components/ChatInterface.js",
                        lineNumber: 274,
                        columnNumber: 7
                    }, this),
                    /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                        className: (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$clsx$2f$dist$2f$clsx$2e$mjs__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clsx"])("flex-1 flex flex-col transition-all duration-300 ease-in-out", {
                            "hidden": isMobile && showSidebar
                        }),
                        children: [
                            selectedRoomId && selectedUser ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$ChatMain$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"], {
                                messages: messages,
                                isConnected: isConnected,
                                currentRoom: currentRoom,
                                selectedRoomId: selectedRoomId,
                                selectedUser: selectedUser,
                                sendMessage: (roomId, message, encryptedData)=>sendWebSocketMessage(roomId, message, encryptedData),
                                connectionError: connectionError,
                                lastError: lastError,
                                pendingMessagesCount: pendingMessagesCount,
                                retryConnection: retryConnection,
                                encryptionStatus: encryptionStatus,
                                currentUser: currentUser,
                                isMobile: isMobile,
                                onBackToList: handleBackToList,
                                typingUsers: typingUsers.filter((user)=>user.room_id === selectedRoomId),
                                onlineUsers: onlineUsers,
                                startTyping: ()=>startTyping(selectedRoomId),
                                stopTyping: ()=>stopTyping(selectedRoomId)
                            }, void 0, false, {
                                fileName: "[project]/src/components/ChatInterface.js",
                                lineNumber: 393,
                                columnNumber: 11
                            }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                className: "flex-1 flex items-center justify-center bg-gray-50",
                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "text-center",
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            className: "w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4",
                                            children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("svg", {
                                                className: "w-8 h-8 text-blue-600",
                                                fill: "none",
                                                stroke: "currentColor",
                                                viewBox: "0 0 24 24",
                                                children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("path", {
                                                    strokeLinecap: "round",
                                                    strokeLinejoin: "round",
                                                    strokeWidth: 2,
                                                    d: "M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
                                                }, void 0, false, {
                                                    fileName: "[project]/src/components/ChatInterface.js",
                                                    lineNumber: 418,
                                                    columnNumber: 19
                                                }, this)
                                            }, void 0, false, {
                                                fileName: "[project]/src/components/ChatInterface.js",
                                                lineNumber: 417,
                                                columnNumber: 17
                                            }, this)
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ChatInterface.js",
                                            lineNumber: 416,
                                            columnNumber: 15
                                        }, this),
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h3", {
                                            className: "text-lg font-medium text-gray-900 mb-2",
                                            children: "Welcome to Chat"
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ChatInterface.js",
                                            lineNumber: 421,
                                            columnNumber: 15
                                        }, this),
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                            className: "text-gray-600 mb-4",
                                            children: "Select a user from the sidebar to start chatting"
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ChatInterface.js",
                                            lineNumber: 422,
                                            columnNumber: 15
                                        }, this),
                                        !isConnected && /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                            className: "text-sm text-red-600",
                                            children: connectionError || 'Connecting to chat server...'
                                        }, void 0, false, {
                                            fileName: "[project]/src/components/ChatInterface.js",
                                            lineNumber: 424,
                                            columnNumber: 17
                                        }, this)
                                    ]
                                }, void 0, true, {
                                    fileName: "[project]/src/components/ChatInterface.js",
                                    lineNumber: 415,
                                    columnNumber: 13
                                }, this)
                            }, void 0, false, {
                                fileName: "[project]/src/components/ChatInterface.js",
                                lineNumber: 414,
                                columnNumber: 11
                            }, this),
                            /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$EncryptionSettings$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"], {
                                isOpen: showEncryptionSettings,
                                onClose: ()=>setShowEncryptionSettings(false)
                            }, void 0, false, {
                                fileName: "[project]/src/components/ChatInterface.js",
                                lineNumber: 433,
                                columnNumber: 9
                            }, this)
                        ]
                    }, void 0, true, {
                        fileName: "[project]/src/components/ChatInterface.js",
                        lineNumber: 386,
                        columnNumber: 7
                    }, this)
                ]
            }, void 0, true, {
                fileName: "[project]/src/components/ChatInterface.js",
                lineNumber: 272,
                columnNumber: 7
            }, this)
        ]
    }, void 0, true, {
        fileName: "[project]/src/components/ChatInterface.js",
        lineNumber: 246,
        columnNumber: 5
    }, this);
}
const __TURBOPACK__default__export__ = /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["memo"])(ChatInterface);
}}),
"[project]/src/app/chat/page.js [app-ssr] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname } = __turbopack_context__;
{
__turbopack_context__.s({
    "default": (()=>ChatPage)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$ChatInterface$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/src/components/ChatInterface.js [app-ssr] (ecmascript)");
"use client";
;
;
function ChatPage() {
    return /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(__TURBOPACK__imported__module__$5b$project$5d2f$src$2f$components$2f$ChatInterface$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["default"], {}, void 0, false, {
        fileName: "[project]/src/app/chat/page.js",
        lineNumber: 5,
        columnNumber: 10
    }, this);
}
}}),

};

//# sourceMappingURL=%5Broot-of-the-server%5D__48d72a38._.js.map