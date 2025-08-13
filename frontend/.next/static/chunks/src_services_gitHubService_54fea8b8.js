(globalThis.TURBOPACK = globalThis.TURBOPACK || []).push([typeof document === "object" ? document.currentScript : undefined, {

"[project]/src/services/gitHubService.js [app-client] (ecmascript)": ((__turbopack_context__) => {
"use strict";

var { g: global, __dirname, k: __turbopack_refresh__, m: module } = __turbopack_context__;
{
// githubKeyService.js
__turbopack_context__.s({
    "default": (()=>__TURBOPACK__default__export__)
});
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$sshpk$2f$lib$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/sshpk/lib/index.js [app-client] (ecmascript)");
;
class GitHubKeyService {
    async uploadPublicKey(publicKeyPem, githubToken, keyTitle = 'SecureChat Key') {
        try {
            const sshKey = this.convertPEMtoSSH(publicKeyPem);
            const response = await fetch('https://api.github.com/user/keys', {
                method: 'POST',
                headers: {
                    'Authorization': `token ${githubToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    title: `${keyTitle} - ${new Date().toISOString().split('T')[0]}`,
                    key: sshKey
                })
            });
            if (!response.ok) {
                const error = await response.json();
                throw new Error(`GitHub API error: ${response.status} - ${error.message}`);
            }
            const keyData = await response.json();
            console.log(' Public key uploaded to GitHub:', keyData.id);
            return keyData;
        } catch (error) {
            console.error(' Failed to upload key to GitHub:', error);
            throw error;
        }
    }
    async fetchUserPublicKeys(githubUsername) {
        console.log('[GITHUB] Fetching SSH keys for GitHub user:', githubUsername);
        const url = `https://api.github.com/users/${githubUsername}/keys`;
        console.log('[GITHUB] API URL:', url);
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/vnd.github+json'
            }
        });
        console.log('[GITHUB] Response status:', response.status);
        if (!response.ok) {
            if (response.status === 404) {
                console.error(' [GITHUB] User not found or has no public SSH keys');
                throw new Error(`GitHub user '${githubUsername}' not found or has no public SSH keys`);
            }
            throw new Error(`GitHub responded with ${response.status}`);
        }
        const keysData = await response.json();
        console.log('[GITHUB] Found', keysData.length, 'SSH keys');
        console.log(' [GITHUB] Keys data:', keysData);
        const rsaKeys = keysData.map((k)=>k.key).filter((key)=>key.startsWith('ssh-rsa'));
        console.log('[GITHUB] RSA keys found:', rsaKeys.length);
        if (rsaKeys.length === 0) {
            throw new Error(`GitHub user '${githubUsername}' has no RSA SSH keys`);
        }
        return rsaKeys;
    }
    convertSSHtoPEM(sshKey) {
        try {
            const key = __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$sshpk$2f$lib$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"].parseKey(sshKey, 'ssh');
            return key.toString('pem');
        } catch (error) {
            throw new Error(`Failed to convert SSH to PEM: ${error.message}`);
        }
    }
    convertPEMtoSSH(pemKey) {
        try {
            const key = __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$sshpk$2f$lib$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["default"].parseKey(pemKey, 'pem');
            return key.toString('ssh');
        } catch (error) {
            throw new Error(`Failed to convert PEM to SSH: ${error.message}`);
        }
    }
}
const __TURBOPACK__default__export__ = new GitHubKeyService();
if (typeof globalThis.$RefreshHelpers$ === 'object' && globalThis.$RefreshHelpers !== null) {
    __turbopack_context__.k.registerExports(module, globalThis.$RefreshHelpers$);
}
}}),
}]);

//# sourceMappingURL=src_services_gitHubService_54fea8b8.js.map