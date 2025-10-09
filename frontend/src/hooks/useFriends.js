import { useState, useEffect, useCallback } from "react";

export const useFriends = (userId) => {
  const [friends, setFriends] = useState([]);
  const [pendingRequests, setPendingRequests] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  // Fetch friends list
  const fetchFriends = useCallback(async () => {
    if (!userId) return;
    
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await fetch("http://localhost:5001/api/friends", {
        credentials: 'include' // Include session cookies
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.status === 'success') {
          setFriends(data.friends || []);
        }
      }
    } catch (error) {
      console.error('Failed to fetch friends:', error);
      setError('Failed to load friends');
    } finally {
      setIsLoading(false);
    }
  }, [userId]);

  // Fetch pending friend requests
  const fetchPendingRequests = useCallback(async () => {
    if (!userId) return;
    
    try {
      const response = await fetch("http://localhost:5001/api/friends/requests", {
        credentials: 'include' // Include session cookies
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.status === 'success') {
          setPendingRequests(data.requests || []);
        }
      }
    } catch (error) {
      console.error('Failed to fetch pending requests:', error);
    }
  }, [userId]);

  // Send friend request
  const sendFriendRequest = async (targetEmail) => {
    if (!userId) return false;
    
    try {
      const response = await fetch("http://localhost:5001/api/friends/request", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        credentials: 'include', // Include session cookies
        body: JSON.stringify({
          target_email: targetEmail
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        return data.status === 'success';
      }
      return false;
    } catch (error) {
      console.error('Failed to send friend request:', error);
      return false;
    }
  };

  // Accept friend request
  const acceptFriendRequest = async (requestId) => {
    if (!userId) return false;
    
    try {
      const response = await fetch(`http://localhost:5001/api/friends/accept/${requestId}`, {
        method: "POST",
        credentials: 'include' // Include session cookies
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.status === 'success') {
          // Refresh friends and pending requests
          fetchFriends();
          fetchPendingRequests();
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error('Failed to accept friend request:', error);
      return false;
    }
  };

  // Reject friend request
  const rejectFriendRequest = async (requestId) => {
    if (!userId) return false;
    
    try {
      const response = await fetch(`http://localhost:5001/api/friends/reject/${requestId}`, {
        method: "POST",
        credentials: 'include' // Include session cookies
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.status === 'success') {
          // Refresh pending requests
          fetchPendingRequests();
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error('Failed to reject friend request:', error);
      return false;
    }
  };

  // Remove friend
  const removeFriend = async (friendId) => {
    if (!userId) return false;
    
    try {
      const response = await fetch(`http://localhost:5001/api/friends/remove/${friendId}`, {
        method: "DELETE",
        credentials: 'include' // Include session cookies
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.status === 'success') {
          // Refresh friends list
          fetchFriends();
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error('Failed to remove friend:', error);
      return false;
    }
  };

  // Search users
  const searchUsers = async (query) => {
    if (!userId || !query) return [];
    
    try {
      const response = await fetch(`http://localhost:5001/api/users/search?q=${encodeURIComponent(query)}`, {
        credentials: 'include' // Include session cookies
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.status === 'success') {
          return data.users || [];
        }
      }
      return [];
    } catch (error) {
      console.error('Failed to search users:', error);
      return [];
    }
  };

  // Load data on mount
  useEffect(() => {
    fetchFriends();
    fetchPendingRequests();
  }, [fetchFriends, fetchPendingRequests]);

  return {
    friends,
    pendingRequests,
    isLoading,
    error,
    fetchFriends,
    fetchPendingRequests,
    sendFriendRequest,
    acceptFriendRequest,
    rejectFriendRequest,
    removeFriend,
    searchUsers
  };
};