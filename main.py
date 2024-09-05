import discord
import imaplib
import email
import re
from bs4 import BeautifulSoup
from discord.ext import commands
from datetime import datetime, timedelta
import asyncio
import random

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True

client = commands.Bot(command_prefix='/', intents=intents)

IMAP_SERVERS = {
    "megastoreloja.shop": {
        "host": "imap.titan.email",
        "port": 993
    },
    "superstoreloja.shop": {
        "host": "imap.titan.email",
        "port": 993
    },
    "grupostore.shop": {
        "host": "imap.titan.email",
        "port": 993
    },
    "grupostore.online": {
        "host": "imap.titan.email",
        "port": 993
    },
    "grupostore.top": {
        "host": "imap.titan.email",
        "port": 993
    },
    "rambler.ru": {
        "host": "imap.rambler.ru",
        "port": 993
    },
    "outlook.com": {
        "host": "outlook.office365.com",
        "port": 993
    }
}

SMTP_SERVERS = {
    "megastoreloja.shop": {
        "host": "smtp.titan.email",
        "port": 465
    },
    "superstoreloja.shop": {
        "host": "smtp.titan.email",
        "port": 465
    },
    "grupostore.shop": {
        "host": "smtp.titan.email",
        "port": 465
    },
    "grupostore.online": {
        "host": "smtp.titan.email",
        "port": 465
    },
    "grupostore.top": {
        "host": "smtp.titan.email",
        "port": 465
    },
    "rambler.ru": {
        "host": "smtp.rambler.ru",
        "port": 465
    },
    "outlook.com": {
        "host": "smtp-mail.outlook.com",
        "port": 587
    }
}

verification_cache = {}

async def exponential_backoff(retries):
    wait_time = (2 ** retries) + (random.randint(0, 1000) / 1000)
    await asyncio.sleep(wait_time)

def get_verify_code(email_address, password, domain):
    try:
        imap_server_info = IMAP_SERVERS.get(domain)
        smtp_server_info = SMTP_SERVERS.get(domain)
        
        if not imap_server_info or not smtp_server_info:
            print(f"Domain '{domain}' is not configured.")
            return None

        mail = imaplib.IMAP4_SSL(imap_server_info['host'], imap_server_info['port'])
        mail.login(email_address, password)
        mail.select('INBOX')

        status, messages = mail.search(None, 'ALL')
        messages_ids = messages[0].split()

        if messages_ids:
            latest_email_id = messages_ids[-1]

            status, msg_data = mail.fetch(latest_email_id, '(RFC822)')
            raw_email = msg_data[0][1]

            email_message = email.message_from_bytes(raw_email)

            for part in email_message.walk():
                if part.get_content_type() == 'text/plain':
                    text_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    match = re.search(r'Origem da solicitação:.*\n.*\n\s*([A-Z0-9]{5})', text_content, re.DOTALL)
                    if match:
                        verify_code = match.group(1)
                        print(f"Verification/authentication code found: {verify_code}")
                        mail.logout()
                        return verify_code

        mail.logout()
        return None

    except Exception as e:
        print(f"Error retrieving emails: {e}")
        return None

def extract_verify_code(email_message):
    if email_message.is_multipart():
        for part in email_message.walk():
            if part.get_content_type() == 'text/html':
                html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                soup = BeautifulSoup(html_content, 'html.parser')
                verify_code_element = soup.find(text=re.compile(r'^\d{6}$'))  
                if verify_code_element:
                    return verify_code_element.strip()
    else:
        text_content = email_message.get_payload(decode=True).decode('utf-8', errors='ignore')
        verify_code_match = re.search(r'\b\d{6}\b', text_content)  
        if verify_code_match:
            return verify_code_match.group(0)
    return None

def get_verify_codes(email_address, password, domain):
    try:
        imap_server_info = IMAP_SERVERS.get(domain)
        if not imap_server_info:
            print(f"Domain '{domain}' is not configured.")
            return None

        mail = imaplib.IMAP4_SSL(imap_server_info['host'], imap_server_info['port'])
        mail.login(email_address, password)

        folders = ['INBOX']
        if domain == "outlook.com":
            folders.append('Junk')
        elif domain == "rambler.ru":
            folders.append('Spam')  

        codes = {}

        for folder in folders:
            mail.select(folder)
            status, messages = mail.search(None, 'ALL')
            messages_ids = messages[0].split()

            for email_id in messages_ids[::-1]:
                status, msg_data = mail.fetch(email_id, '(RFC822)')
                raw_email = msg_data[0][1]

                email_message = email.message_from_bytes(raw_email)
                verify_code = extract_verify_code(email_message)

                if verify_code:
                    date_tuple = email.utils.parsedate_tz(email_message['Date'])
                    if date_tuple:
                        local_date = datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
                        if folder not in codes or local_date > codes[folder]['date']:
                            codes[folder] = {'code': verify_code, 'date': local_date}

        mail.logout()

        return [{'code': data['code'], 'folder': folder} for folder, data in codes.items()]

    except imaplib.IMAP4.error as e:
        error_message = str(e).lower()
        if "login failure" in error_message:
            print(f"Error processing /code command: Invalid email password for {email_address}")
            raise ValueError("Invalid email password")
        elif "no such command" in error_message:
            print(f"Error processing /code command: Email not found for {email_address}")
            raise ValueError("Email not found")
        else:
            print(f"Error processing /code command: {e} for {email_address}")
            raise e

    except Exception as e:
        print(f"Error retrieving emails: {e} for {email_address}")
        raise e

@client.event
async def on_ready():
    print('Bot is ready.')

@client.command(name='steam')
async def steam(ctx, email_password: str):
    try:
        email_address, password = email_password.split(':')
        domain = email_address.split('@')[-1]
        verify_code = get_verify_code(email_address, password, domain)

        if verify_code:
            author_id = ctx.author.id
            email_address = email_address
            password = password
            code = verify_code

            embed = discord.Embed(
                title=f'{domain.capitalize()} - Code',
                color=0x00FF00
            )
            embed.add_field(name='[●] Author :', value=f'<@{author_id}>', inline=True)
            embed.add_field(name='[●] Email :', value=f'||{email_address}||', inline=False)
            embed.add_field(name='[●] Password :', value=f'||{password}||', inline=False)
            embed.add_field(name='[●] Code :', value=f'```css\n{code}```', inline=False)
            embed.set_footer(text=f'{domain.capitalize()} | {datetime.now().strftime("%d/%m/%Y | %H:%M:%S")}',
                             icon_url='https://cdn.discordapp.com/attachments/1257015663449477120/1275755202028503153/mgsore.png?ex=66c85c9e&is=66c70b1e&hm=f1c95924a0bc454111577de0e8b8d7db5534ab3f9dcb242e0b2aa04e202ee123&')
            await ctx.send(embed=embed)
        else:
            error_embed = discord.Embed(
                title='**Failed**',
                description=f'No email message with Verify/Auth-Code or incorrect email message format for {domain.capitalize()}.',
                color=0xff0000
            )
            error_embed.set_footer(text='Bot Command Executed',
                                   icon_url='https://cdn.discordapp.com/attachments/1257015663449477120/1275755202028503153/mgsore.png?ex=66c85c9e&is=66c70b1e&hm=f1c95924a0bc454111577de0e8b8d7db5534ab3f9dcb242e0b2aa04e202ee123&')
            await ctx.send(embed=error_embed)
    except ValueError:
        error_embed = discord.Embed(
            title='**Format Error**',
            description='Invalid format. Use `/steam email:password`.',
            color=0xff0000
        )
        error_embed.set_footer(text='Bot Command Executed',
                               icon_url='https://cdn.discordapp.com/attachments/1257015663449477120/1275755202028503153/mgsore.png?ex=66c85c9e&is=66c70b1e&hm=f1c95924a0bc454111577de0e8b8d7db5534ab3f9dcb242e0b2aa04e202ee123&')
        await ctx.send(embed=error_embed)
    except Exception as e:
        print(f"Error processing /steam command: {e}")
        await ctx.send("An error occurred while processing the command.")

@client.command(name='code')
async def code(ctx, account: str):
    try:
        parts = account.split(':', 2)
        email = parts[0]
        password1 = parts[1] if len(parts) > 1 else ''
        password2 = parts[2] if len(parts) > 2 else ''

        
        if 'rockstar.com' in email:
            password1 = ''  

        domain = email.split('@')[-1]

        if email in verification_cache:
            last_verification_time = verification_cache[email]['time']
            time_difference = datetime.now() - last_verification_time
            if time_difference.total_seconds() < 60:  
                error_embed = discord.Embed(
                    title='**Wait a moment**',
                    description='``Wait 1 minute before checking again.``',
                    color=0xff0000
                )
                await ctx.send(embed=error_embed)
                return

        print(f"Attempting to get verification code for {email}")
        verify_codes = get_verify_codes(email, password1, domain)

        if verify_codes:
            print(f"Codes retrieved for {email}: {verify_codes}")  
            author_id = ctx.author.id
            embed = discord.Embed(
                title='Mango - Code',
                color=0x00FF00
            )
            code_found = False
            for idx, code_data in enumerate(verify_codes):
                code = code_data['code']
                folder = code_data['folder']
                if code:
                    code_found = True
                    embed.add_field(name=f'[●] Code {idx+1} ({folder}):', value=f'```css\n{code}```', inline=False)
                else:
                    embed.add_field(name=f'[●] Code {idx+1} ({folder}):', value=f'```css\nNo Code Found```', inline=False)
            embed.add_field(name='[●] Author :', value=f'<@{author_id}>', inline=True)
            embed.add_field(name='[●] Email :', value=f'||{email}||', inline=False)
            embed.add_field(name='[●] Password :', value=f'||{password1}||', inline=False)
            embed.set_footer(text=f'API Mango| {datetime.now().strftime("%d/%m/%Y | %H:%M:%S")}',
                             icon_url='https://cdn.discordapp.com/attachments/1257015663449477120/1275755202028503153/mgsore.png?ex=66c85c9e&is=66c70b1e&hm=f1c95924a0bc454111577de0e8b8d7db5534ab3f9dcb242e0b2aa04e202ee123&')
            await ctx.send(embed=embed)
        else:
            error_embed = discord.Embed(
                title='**Login to the Fivem Account First**',
                description="``No Code Found.``",
                color=0xff0000
            )
            await ctx.send(embed=error_embed)

        verification_cache[email] = {'codes': verify_codes, 'time': datetime.now()}
        
    except ValueError:
        error_embed = discord.Embed(
            title='**Formato Invalid**',
            description='Formato invalid. Use `/code email:pass`.',
            color=0xff0000
        )
        error_embed.set_footer(text='Bot Command Executed',
                               icon_url='https://cdn.discordapp.com/attachments/1257015663449477120/1275755202028503153/mgsore.png?ex=66c85c9e&is=66c70b1e&hm=f1c95924a0bc454111577de0e8b8d7db5534ab3f9dcb242e0b2aa04e202ee123&')
        await ctx.send(embed=error_embed)
    except ValueError as ve:
        if str(ve) == "Invalid email password":
            error_embed = discord.Embed(
                title='**Password error**',
                description='``Incorrect e-mail password. Check and try again.``',
                color=0xff0000
            )
            error_embed.set_footer(text='Incorrect password',
                                   icon_url='https://cdn.discordapp.com/attachments/1257015663449477120/1275755202028503153/mgsore.png?ex=66c85c9e&is=66c70b1e&hm=f1c95924a0bc454111577de0e8b8d7db5534ab3f9dcb242e0b2aa04e202ee123&')
            await ctx.send(embed=error_embed)
        elif str(ve) == "Email not found":
            error_embed = discord.Embed(
                title='**No Code Found**',
                description="No Code Found.",
                color=0xff0000
            )
            await ctx.send(embed=error_embed)
        else:
            await ctx.send("Format invalid. Use `/code email:password`.")
    except Exception as e:
        print(f"Error processing /code command: {e}")
        error_embed = discord.Embed(
            title='**Incorrect password**',
            description='``Incorrect e-mail password. Check and try again.``',
            color=0xff0000
        )
        error_embed.set_footer(text='API Mango',
                               icon_url='https://cdn.discordapp.com/attachments/1257015663449477120/1275755202028503153/mgsore.png?ex=66c85c9e&is=66c70b1e&hm=f1c95924a0bc454111577de0e8b8d7db5534ab3f9dcb242e0b2aa04e202ee123&')
        await ctx.send(embed=error_embed)

@client.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        error_embed = discord.Embed(
            title='**Command not found**',
            description="Use the command `/code email:password` or `/steam email:password`.",
            color=0xff0000
        )
        await ctx.send(embed=error_embed)
    else:
        error_embed = discord.Embed(
            title='**Processing error**',
            description=f"An error occurred while processing the command: {error}",
            color=0xff0000
        )
        await ctx.send(embed=error_embed)

TOKEN = 'MTI3NjI5ODExNTY2NTg5MTQ2OQ.GDagSK.6sidUCZHWrKLUGNVVaT9pp0Iu-5qopvePVVrDQ'
client.run(TOKEN)