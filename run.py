from app import app, socketio

if __name__ == "__main__":
    # Use socketio.run (not app.run) so the Flask-SocketIO websocket/polling
    # transport is actually served -- plain app.run() ignores SocketIO and
    # your real-time balance_update events will silently never reach clients.
    socketio.run(app, debug=True)
