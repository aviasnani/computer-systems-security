"use client";

export default function ChatMessage({ message }) {
  const isMe = message.sender === "me";

  return (
    <div className={`message ${isMe ? "me" : "other"} animate-fade-in`}>
      <div className="message-content">
        <p className="text-sm md:text-base">{message.text}</p>
        <span className="timestamp text-xs opacity-75">
          {message.timestamp}
        </span>
      </div>
    </div>
  );
}
