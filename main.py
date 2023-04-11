from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from passlib.hash import sha256_crypt

# Create Flask app
app = Flask(__name__)
# Simply used for signed cookies to prevent cookie tampering, needed to use sessions
app.config["SECRET_KEY"] = "notreallyasecret"
# Make Flask app into a SocketIO app
socketio = SocketIO(app)

# Store password
stored_password = None

# Keep track of members in room, max 2
members = []

# Store public keys to exchange between members
publicKeys = []

# Set up routing for start page
@app.route("/", methods=["GET", "POST"])
def start():
    # Clear session data upon entering start page
    session.clear()

    # Handle if request is to log into the chat
    if request.method == "POST":
        name = request.form.get("name")
        password = request.form.get("password")
        # Set default values of these to False if no response
        new_chat = request.form.get("new-chat", False)
        join_chat = request.form.get("join-chat", False)

        # Use the global variables
        global stored_password

        print(name)
        print(password)
        print(stored_password)

        # Print errors for missing fields
        if not name:
            return render_template("start.html", error="Please enter a name", name=name)
        
        if not password:
            return render_template("start.html", error="Please enter a password", name=name)
        
        # Make a new chat
        if new_chat != False:
            if stored_password == None:
                # This will salt with 96 bits and hash with SHA256
                stored_password = sha256_crypt.hash(password)
            else:
                # Prompt user to join instead if there is already a chat
                return render_template("start.html", error="A chat is already in session", name=name)
        # Checks for joining
        elif join_chat != False:
            # Check if room has been created or whether password is correct
            if stored_password is None or not sha256_crypt.verify(password, stored_password):
                return render_template("start.html", error="Invalid password", name=name)
            # This chat only accepts 2 users at a time
            elif len(members) >= 2:
                return render_template("start.html", error="2 people are already chatting, please join later", name=name)
        
        # Store user's name in current session
        session["name"] = name
        
        # Redirect to chat page if successful
        return redirect(url_for("chat"))
        

    # Change page to start.html
    return render_template("start.html")

# Function to make checks for routing to chat room
@app.route("/chat")
def chat():
    global stored_password
    # Prevent a user from accessing the chat from outside
    if stored_password is None or session.get("name") is None:
        return redirect(url_for("start"))
    
    return render_template("chat.html")

# Receive encrypted message, send proper messages to clients
@socketio.on("message")
def message(data):
    global stored_password
    
    # If chat is not in session, prevent further output
    if stored_password is None:
        return
    
    print(data["data"])
    
    # Make dictionary for important aspects of the message
    msg = {"name": session.get("name"), 
           "message": data["data"], 
           "iv": data["iv"], 
           "type": "msg"}
    
    msg["type"] = "msgSend"

    # Check who the message is coming from to personalize outputs
    if request.sid == members[0]:
        # Send message to receiver if there is one
        if len(members) == 2:
            msg["type"] = "msgRecv"
            send(msg, to=members[1])
        
        # Send ciphertext back to sender
        msg["type"] = "msgSend"
        send(msg, to=members[0])
    elif request.sid == members[1]:
        msg["type"] = "msgRecv"
        send(msg, to=members[0])

        msg["type"] = "msgSend"
        send(msg, to=members[1])

# Exchange public keys between clients
@socketio.on("exchange")
def exchange(data):

    publicKeys.append(data["data"])

    # If both keys have been received, exchange them
    if len(publicKeys) == 2:
        # If second key sent is by first member
        if (request.sid == members[0]):
            emit("recvKey", {"publicKey": publicKeys[0]}, to=members[0])
            emit("recvKey", {"publicKey": publicKeys[1]}, to=members[1])
        # If second key sent is by second member
        elif (request.sid == members[1]):
            emit("recvKey", {"publicKey": publicKeys[0]}, to=members[1])
            emit("recvKey", {"publicKey": publicKeys[1]}, to=members[0])

        # Clear list of public keys to prevent extraneous keys
        publicKeys.clear()

# Generate a new set of public and private keys
@socketio.on("keygen")
def keygen():
    emit("keygen", broadcast=True)

# Handle connection to the chat room
@socketio.on("connect")
def connect(auth):
    global stored_password

    name = session.get("name")

    # Exit function if this is called incorrectly
    if not name:
        return
    if stored_password is None:
        return
    
    # Add member to member list
    members.append(request.sid)
    # Have each person join their own room using sid as the name
    session["room"] = request.sid
    join_room(request.sid)
    print("SID:", request.sid)
    print("Room:", session["room"])

    # Send join message to all members
    for member in members:
        send({"name": name, "message": "has entered", "type": "status"}, to=member)

    print(len(members))

    # If both members have joined, generate a new set of keys for both
    if len(members) == 2:
        emit("keygen", broadcast=True)
    
    print(f"{name} has joined the chat")

# Handle disconnect from the chat room
@socketio.on("disconnect")
def disconnect():
    name = session.get("name")

    # Use global variables
    global stored_password

    # Leave the room
    members.remove(request.sid)
    leave_room(request.sid)
    # If no members in chat room, delete it by clearing the password
    if len(members) == 0:
        stored_password = None
        print("All members have left")
    # Else, send leaving message to remaining member and clear their keys
    else:
        send({"name": name, "message": "has left", "type": "status"}, to=members[0])
        emit("clear", to=members[0])
    
    print(f"{name} has left the room")



if __name__ == "__main__":
    socketio.run(app, debug=True, host='0.0.0.0')
