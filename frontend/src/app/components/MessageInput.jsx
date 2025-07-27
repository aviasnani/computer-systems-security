"use client";

export default function MessageInput({
  messageInput,
  setMessageInput,
  handleKeyPress,
  sendMessage,
  isConnected,
}) {
  return (
    <div className="input-container">
      <input
        type="text"
        value={messageInput}
        onChange={(e) => setMessageInput(e.target.value)}
        onKeyPress={handleKeyPress}
        placeholder="Type a message..."
        className="w-full bg-gray-800 text-white rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
        disabled={!isConnected}
      />
      <button
        onClick={sendMessage}
        disabled={!isConnected || !messageInput.trim()}
        className="bg-blue-500 hover:bg-blue-600 text-white px-6 py-3 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        Send
      </button>
    </div>
  );
}
