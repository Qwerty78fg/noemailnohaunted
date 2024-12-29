import asyncio
import requests
from flask import Flask, redirect, request, jsonify, render_template, session
import discord
from threading import Thread
from functools import wraps
import logging
import sys
import json
import os
from discord import ui, app_commands

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, encoding='utf-8')
logger = logging.getLogger()

app = Flask(__name__)
app.secret_key = 'your_secret_key'

authorized_users = {}
#user_id_global = None  #Global variable
user_ids_global = []  #Global list
deauthorized_users = []


with open("token.txt", "r") as f:
    token = f.read().strip()

CLIENT_ID = "1305178785259196458"
CLIENT_SECRET = "u6SBQgJwdXqDbGzAgW5l6pEt1Dggc14F"
REDIRECT_URI = "http://localhost:5000/callback"
FINAL_REDIRECT_URL = REDIRECT_URI  # http://localhost:5000/callback

intents = discord.Intents.default()
intents.members = True
intents.message_content = True
bot = discord.Client(intents=intents)
tree = discord.app_commands.CommandTree(bot)

# Global variables
data_ready_event = asyncio.Event()
members_data = []
roles_data = []
user_access_tokens = {}

# OAuth2 URL to authorize the bot
OAUTH2_URL = (
    f"https://discord.com/oauth2/authorize"
    f"?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code"
    f"&scope=identify+guilds+guilds.join&prompt=none"
)

def save_tokens():
    with open('user_access_tokens.json', 'w') as f:
        json.dump(user_access_tokens, f)

def load_tokens():
    global user_access_tokens
    if os.path.exists('user_access_tokens.json') and os.path.getsize('user_access_tokens.json') > 0:
        try:
            with open('user_access_tokens.json', 'r') as f:
                user_access_tokens = json.load(f)
                print(f"loaded{user_access_tokens})")
        except json.JSONDecodeError:
            print('[ERROR] Failed to decode JSON. The file may be corrupted or empty.')
            user_access_tokens = {}  # Initialize to an empty dictionary if there's an error
    else:
        user_access_tokens = {}

load_tokens()
for user_id in user_access_tokens.keys():
    if user_id not in user_ids_global:
        user_ids_global.append(user_id)

    
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f'[DEBUG] Checking login status: {session.get("logged_in")}')
        if not session.get('logged_in'):
            return redirect('/')  # Redirect to the login page if not logged in
        return f(*args, **kwargs)
    return decorated_function

@bot.event
async def on_ready():
    await tree.sync()
    print(f'[DEBUG] Bot is logged in as {bot.user}')
    global members_data, roles_data
    if bot.guilds:
        # Get members from all guilds
        all_members = []
        for guild in bot.guilds:
            guild_members = [{"name": member.name, "id": member.id} for member in guild.members]
            all_members.extend(guild_members)
        # Remove duplicates
        seen_ids = set()
        members_data = [member for member in all_members 
                       if member['id'] not in seen_ids and not seen_ids.add(member['id'])]
        roles_data = [{"name": role.name, "id": role.id} for role in bot.guilds[0].roles]
    print(f'[DEBUG] Members data fetched: {len(members_data)} members')
    print(f'[DEBUG] Roles data fetched: {len(roles_data)} roles')
    data_ready_event.set()
    print('[DEBUG] data_ready_event set')

@app.route('/')
def home():
    return render_template('login.html')





@app.route('/invite')
def invite():
    print('[DEBUG] /invite route accessed')
    return redirect(OAUTH2_URL)  # Redirect to the OAuth2 URL for verification

@app.route('/callback')
def callback():
    global user_ids_global
    code = request.args.get("code")
    print(f'[DEBUG] Callback route accessed with code: {code}')
    if not code:
        return jsonify({"error": "No code provided"}), 400

    # Exchange the code for an access token
    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    token_response = requests.post("https://discord.com/api/oauth2/token", data=token_data)
    if token_response.status_code != 200:
        return jsonify({"error": "Failed to exchange code for token"}), 400

    user_data = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"}
    ).json()

    # Store the user ID and token
    user_id = user_data.get("id")
    user_ids_global.append(user_id)
    user_access_tokens[user_id] = token_response.json()['access_token']
    print(f"[DEBUG] Access token stored for user {user_id}")

    # Get the guild and member
    guild = bot.guilds[0]
    member = guild.get_member(int(user_id))

    if member:
        # Get the Member role
        role = discord.utils.get(guild.roles, name="Member")
        if role:
            try:
                # Debug information for role hierarchy
                bot_role = discord.utils.get(guild.roles, name="BOT")  # Get the BOT role
                bot_member = guild.get_member(bot.user.id)
                
                print(f"[DEBUG] Bot Name: {bot.user.name}")
                print(f"[DEBUG] Bot Role: {bot_role.name if bot_role else 'Not found'}")
                print(f"[DEBUG] Bot Role Position: {bot_role.position if bot_role else 'N/A'}")
                print(f"[DEBUG] Member Role Position: {role.position}")
                print(f"[DEBUG] Bot Permissions: {bot_member.guild_permissions.manage_roles}")
                
                # Check if bot has the BOT role
                if not bot_role:
                    print("[ERROR] BOT role not found!")
                    return jsonify({"error": "Bot role not found"}), 403

                # Check if bot can manage roles
                if not bot_member.guild_permissions.manage_roles:
                    print("[ERROR] Bot doesn't have manage roles permission!")
                    return jsonify({"error": "Bot missing permissions"}), 403

                # Check role hierarchy
                if bot_role.position <= role.position:
                    print("[ERROR] BOT role is not high enough in the hierarchy!")
                    return jsonify({"error": "Bot role hierarchy issue"}), 403

                # Use bot.loop to run the coroutine
                bot.loop.create_task(member.add_roles(role))
                print(f"[DEBUG] Role assignment task created for {member.name}")
            except Exception as e:
                print(f"[ERROR] Failed to assign role: {str(e)}")
                return jsonify({"error": str(e)}), 403
        else:
            print("[ERROR] Member role not found")
            return jsonify({"error": "Role not found"}), 404
    else:
        print(f"[ERROR] Member {user_id} not found in guild")
        return jsonify({"error": "Member not found"}), 404

    # Add user to guild if not already present
    add_user_response = requests.put(
        f"https://discord.com/api/guilds/{guild.id}/members/{user_id}",
        headers={"Authorization": f"Bot {token}"},
        json={"access_token": token_response.json()['access_token']}
    )

    print(f'[DEBUG] Add user to guild response status: {add_user_response.status_code}')
    
    # Return success response
    return jsonify({"success": True}), 200

@app.route('/members')
@login_required
def get_members():
    print('[DEBUG] /members route accessed')
    asyncio.run(data_ready_event.wait())
    print(f'user IDDDDDDDDDDDDDDDDDDDDD{user_ids_global}')
    print(jsonify(members_data))
    return jsonify(members_data)

@app.route('/roles')
@login_required
def get_roles():
    print('[DEBUG] /roles route accessed')
    asyncio.run(data_ready_event.wait())
    return jsonify(roles_data)

@app.route('/servers')
@login_required
def get_servers():
    servers = [{"id": guild.id, "name": guild.name} for guild in bot.guilds]
    return jsonify(servers)

@app.route('/add_user_to_second_server', methods=['POST'])
@login_required
def add_user_to_second_server():
    global user_ids_global  # Use the global list
    data = request.json
    user_index = data.get('user_index')  # Get the index of the user from the request
    server_index = data.get('server_index')  # Get server index from request

    # Convert user_index to integer
    try:
        user_index = int(user_index)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid user index"}), 400

    print(f'[DEBUG] Attempting to add user {user_ids_global[user_index]} to server index {server_index}')
    
    if user_index is None or server_index is None or user_index >= len(user_ids_global):
        return jsonify({"error": "Missing user_index or server_index"}), 400

    user_id = user_ids_global[user_index]  # Get the user ID from the global list

    # Check if we have the user's access token
    if user_id not in user_access_tokens:
        return jsonify({"error": "User hasn't authenticated yet"}), 401

    user_in_guild_0 = None
    for member in bot.guilds[0].members:
        if str(member.id) == user_id:
            user_in_guild_0 = member
            break
    
    if not user_in_guild_0:
        return jsonify({"error": "User not found in the first guild"}), 404

    headers = {"Authorization": f"Bot {token}"}
    add_user_response = requests.put(
        f"https://discord.com/api/guilds/{bot.guilds[1].id}/members/{user_in_guild_0.id}",
        headers=headers,
        json={"access_token": user_access_tokens[user_id]}  # Use stored access token
    )

    if add_user_response.status_code == 201:
        return jsonify({"success": True}), 201
    else:
        print(f'[DEBUG] Failed to add user: {add_user_response.status_code}, Response: {add_user_response.text}')
        return jsonify({"error": f"Failed to add user: {add_user_response.status_code}"}), add_user_response.status_code



@app.route('/guilds', methods=['GET'])
def guilds():
    global user_ids_global  # Use the global list
    user_index = request.args.get('user_index')

    # Convert user_index to integer
    try:
        user_index = int(user_index)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid user index"}), 400

    print(f'[DEBUG] Attempting to get user guilds')
    
    user_id = user_ids_global[user_index]  # Get the user ID from the global list

    # Check if we have the user's access token
    if user_id not in user_access_tokens:
        return jsonify({"error": "User hasn't authenticated yet"}), 401

    access_token = user_access_tokens[user_id]
    if not access_token:
        return redirect('/invite')

    headers = {'Authorization': f"Bearer {access_token}"}
    response = requests.get("https://discord.com/api/users/@me/guilds", headers=headers)
    
    if response.status_code != 200:
        return jsonify({"error": "Failed to fetch guilds"}), response.status_code

    guilds = response.json()
    logger.debug(guilds)
    return jsonify(guilds)





@app.route('/get_user_ids', methods=['GET'])
def get_user_ids():
    global user_ids_global, bot
    user_info = []
    
    for user_id in user_ids_global:
        if user_id in user_access_tokens:
            username = None
            for guild in bot.guilds:
                member = guild.get_member(int(user_id))
                if member:
                    username = f"{member.name}#{member.discriminator}"
                    break
            
            if username:
                user_info.append({
                    "id": user_id,
                    "name": username
                })
            else:
                user_info.append({
                    "id": user_id,
                    "name": f"User {user_id}"  # Fallback if username not found
                })
    
    return jsonify(user_info)

def run_flask():
    print('[DEBUG] Flask app is starting...')
    app.run(debug=True, use_reloader=False)

@bot.event
async def on_member_join(member):
    print(f'[DEBUG] New member joined: {member.name}')
    global members_data

    # Create the "Member" role if it doesn't exist
    guild = member.guild
    role_name = "Member"
    role = discord.utils.get(guild.roles, name=role_name)
    if role is None:
        role = await guild.create_role(name=role_name)
        print(f'[DEBUG] Created role: {role_name}')

@tree.command(name="create-verify", description="Creates a verification embed in the current channel")
async def create_verify(interaction: discord.Interaction):

    await interaction.response.defer()
        
    embed = discord.Embed(
        title="Welcome!", 
        description="Please verify your account by clicking the button below.", 
        color=0xFFFFFF
    )
    
    class VerifyButton(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=None)
            
            self.add_item(discord.ui.Button(
                label="Verify Here", 
                style=discord.ButtonStyle.gray, 
                url=OAUTH2_URL
            ))

    await interaction.followup.send(embed=embed, view=VerifyButton())
    print(f'[DEBUG] Created verification embed in channel {interaction.channel.name}')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    password = data.get('password')

    # Check if the password is correct
    if password == "1234":
        session['logged_in'] = True  # Set session variable
        print('[DEBUG] User logged in successfully.')
        return jsonify({"success": True}), 200
    else:
        return jsonify({"success": False, "error": "Incorrect password"}), 401

@app.route('/admin')
def admin_panel():
    if not session.get('logged_in'):
        return redirect('/')  # Redirect to the login page if not logged in
    return render_template('index.html')  # Render the admin panel

@app.route('/ban_user', methods=['POST'])
@login_required
def ban_user():
    data = request.json
    user_id = data.get('user_id')

    # Debugging
    print(f'[DEBUG] Attempting to ban user: {user_id}')
    print(f'[DEBUG] Current user_access_tokens: {user_access_tokens}')

    # (string or integer)
    if user_id in user_access_tokens:
        del user_access_tokens[user_id]
        print(f'[DEBUG] User {user_id} has been banned and removed from access tokens.')
        save_tokens()
        return jsonify({"success": True}), 200
        
    else:
        return jsonify({"error": "User not found in access tokens"}), 404

print(user_access_tokens)
print(user_ids_global)


if __name__ == "__main__":
    print('[DEBUG] Starting Flask in a separate thread...')
    flask_thread = Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    print('[DEBUG] Starting bot...')
    bot.run(token)