import asyncio
import requests
import json
import os


user_access_tokens = {}
deauthorized_users = []

def load_tokens():
    global user_access_tokens
    if os.path.exists('user_access_tokens.json') and os.path.getsize('user_access_tokens.json') > 0:
        try:
            with open('user_access_tokens.json', 'r') as f:
                user_access_tokens = json.load(f)
        except json.JSONDecodeError:
            print('[ERROR] Failed to decode JSON. The file may be corrupted or empty.')
            user_access_tokens = {}
    else:
        user_access_tokens = {}

async def check_token_validity():
    load_tokens()  # Load at the start
    while True:
        await asyncio.sleep(3600)  # Wait for 1 hour


        for user_id, access_token in list(user_access_tokens.items()):
            response = requests.get("https://discord.com/api/users/@me", headers={"Authorization": f"Bearer {access_token}"})
            if response.status_code != 200:
                # Token is invalid
                deauthorized_users.append(user_id)
                del user_access_tokens[user_id]


        with open('deauthorized_users.json', 'w') as f:
            json.dump(deauthorized_users, f)

        # Save to the file
        save_tokens()

def save_tokens():
    with open('user_access_tokens.json', 'w') as f:
        json.dump(user_access_tokens, f)

if __name__ == "__main__":
    asyncio.run(check_token_validity())
