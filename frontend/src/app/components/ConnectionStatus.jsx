"use client";

export default function ConnectionStatus({
  isConnected,
  connectionError,
  lastError,
  pendingMessagesCount,
  retryConnection,
}) {
  return (
    <div className="space-y-2">
      {/* Connection Status */}
      <div className="flex items-center space-x-2 p-2 bg-gray-800 rounded-lg">
        <div
          className={`w-2 h-2 rounded-full ${
            isConnected ? "bg-green-500" : "bg-red-500"
          }`}
        />
        <span className="text-sm text-gray-300">
          {isConnected ? "Connected" : "Disconnected"}
        </span>
        {!isConnected && (
          <button
            onClick={retryConnection}
            className="ml-auto text-sm text-blue-400 hover:text-blue-300"
          >
            Retry
          </button>
        )}
      </div>

      {/* Error Messages */}
      {(connectionError || lastError) && (
        <div className="p-2 bg-red-900/50 text-red-200 rounded-lg text-sm">
          {connectionError || lastError?.message}
        </div>
      )}

      {/* Pending Messages */}
      {pendingMessagesCount > 0 && (
        <div className="p-2 bg-yellow-900/50 text-yellow-200 rounded-lg text-sm">
          {pendingMessagesCount} message{pendingMessagesCount !== 1 ? "s" : ""}{" "}
          waiting to be sent
        </div>
      )}
    </div>
  );
}
