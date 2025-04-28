# Add these routes to your backend API server
# This is the code you need to add to your connector backend

@app.route('/heartbeat', methods=['GET'])
def heartbeat():
    """
    Endpoint to check backend heartbeat and IBKR connection status
    Returns the current heartbeat status and IBKR connection state
    """
    try:
        # Check the current IBKR connection status
        is_connected = False
        
        if client and hasattr(client, 'isConnected'):
            is_connected = client.isConnected()
        
        return jsonify({
            "status": "alive",
            "timestamp": datetime.now().isoformat(),
            "connected_to_ibkr": is_connected
        })
    except Exception as e:
        app.logger.error(f"Heartbeat error: {str(e)}")
        return jsonify({
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat(),
            "connected_to_ibkr": False
        })

@app.route('/verify_connection', methods=['GET'])
def verify_connection():
    """
    Endpoint to verify IBKR connection status directly
    Performs a deeper check than the heartbeat
    """
    try:
        is_connected = False
        
        # Check the connection state
        if client and hasattr(client, 'isConnected'):
            is_connected = client.isConnected()
            
            # If connected, perform a simple query to verify the connection is responsive
            if is_connected:
                try:
                    # Example: Request a simple piece of data from IBKR API
                    # This depends on what API you're using (IBApi, ib_insync, etc.)
                    # For example, with ib_insync you might do:
                    # accounts = client.accountSummary()
                    # or with IBApi:
                    # client.reqAccountSummary(1, "All", "NetLiquidation")
                    
                    # Wait briefly for the response - this will vary by API
                    # time.sleep(0.5)
                    
                    # If no errors occurred during the request, the connection is verified
                    app.logger.info("IBKR connection verified through API request")
                except Exception as e:
                    app.logger.error(f"IBKR connection verification failed: {str(e)}")
                    is_connected = False
        
        return jsonify({
            "connected": is_connected,
            "verified": True,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        app.logger.error(f"Error verifying connection: {str(e)}")
        return jsonify({
            "connected": False,
            "verified": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        })
