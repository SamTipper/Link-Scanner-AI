import discord
from discord.ext import commands
import validators
import requests
from keep_alive import keep_alive
from replit import db

# Instantiate the Discord client
client = commands.Bot(command_prefix = "v.")

Veto_Websites = ["youtube", "twitter", "facebook", "instagram","etc"]

Veto_Words = ["www", "www.", "com", ".com", "http", "https", ":", "/", "@", "=", "-"]

url = "https://www.virustotal.com/vtapi/v2/url/report"
params = {"apikey": "KEY", "resource": scan_id}

# Gets the bot ready
@client.event
async def on_ready():
  await client.change_presence(activity=discord.Activity(type=discord.ActivityType.listening, name="All Links | "
                                                                                                   "v.help"))
  print('You have logged in as {0.user}'.format(client))


async def sendembed(message, permalink, total_scans, positives, sus):
  channel = client.get_channel(ID)

  # Uses our sus variable to change the colour of the embed
  if sus == 0:
    colour = discord.Colour.green()
  elif sus == 1:
    colour = discord.Colour.red()

  embed = discord.Embed(
    title = '**Virus Total Link Scan Result**',
    description = f'Website in question: \n{message.content}',
    colour = colour
  )
  embed.set_footer(text='Virus Total Bot',icon_url='https://res.cloudinary.com/crunchbase-production/image/upload/'
                                                   'c_lpad,h_256,w_256,f_auto,q_auto:eco,dpr_1/vxwo4yr27optg1jldgjf')
  embed.add_field(name='Total Amount of Scans:', value=f'{total_scans}', inline=False)
  embed.add_field(name='Positives:', value=f'{positives}', inline=False)
  embed.add_field(name='Virus Total Link:', value=f'{permalink}', inline=False)
  await channel.send(embed=embed)


async def getreport(message, scan_id):
  channel = client.get_channel(ID)

  # Variable to track how many antivirus programs scanned this link
  total_scans = 0
  try:

    # We use this while loop to wait until we have at least 1 scan
    while total_scans == 0:
      url = "https://www.virustotal.com/vtapi/v2/url/report"

      # Our scan id comes in handy here to return us the scan we issued
      params = {"apikey": "KEY", "resource": scan_id}
      response = requests.get(url, params=params)
      response = response.json()
      permalink = response.get("permalink")
      total_scans = response.get("total")
      positives = response.get("positives")

    # Checks to see if one antivirus found this link suspicious. If so, we tell our embed that it's suspicious with the
    # "sus" variable
    if positives > 0:
      await sendembed(message, permalink, total_scans, positives, sus=1)
    else:
      await sendembed(message, permalink, total_scans, positives, sus=0)
  except:
    await channel.send(f"Couldn't scan '{message.content}' please be careful.")


# This event checks every message in a server for a link
@client.event
async def on_message(message):
  # Allows other commands to work
  await client.process_commands(message)
  answer = []
  channel = client.get_channel(ID)
  id = message.author.id

  # Checks to see if the message sent was not the bot
  if id != (the_bots_id):

    # An unorthidox way of checking if our link has any words we don't want
    for substring in db['blacklist']:
      if not substring in message.content:
        answer.append("no")
      else:
        answer.append("yes")

    # This way we can see if we have any vetoes in our link
    if "yes" not in answer:
      try:
        if message.content.startswith("https://"):
          await channel.send(f"**SCANNING URL, PLEASE WAIT**")

          # A check to see if the message beginning wth "https://" is a valid link
          check = validators.url(message.content)
          if check == True:
            params.update({"url": message.content})
            response = requests.post(url, data=params)
            response = response.json()

            # Grabbing the ID of the scan so we can use it to see the results
            scan_id = response.get("scan_id")
            await getreport(message, scan_id)

        # Warning the user if the url starts with "http://", regardless if it's valid or not
        elif message.content.startswith("http"):
          check = validators.url(message.content)
          if check == True:
            await channel.send("**Link starts with 'http://' this site could be insecure, Scanning now.**")
            params.update({"url": message.content})
            response = requests.post(url, data=params)
            response = response.json()
            scan_id = response.get("scan_id")
            await getreport(message, scan_id)
      except:
        await channel.send(f"Couldn't scan '{message.content}' please be careful.")


@client.command()
async def vetosite(ctx, *, arg=None):
  if arg != None:
    answer = []
    # checks to see if we've already added our keyword to the veto list
    for substring in Veto_Words:
      if not substring in arg:
        answer.append("no")
      else:
        answer.append("yes")

    # Appending to DB
    if "yes" not in answer:
      if arg.lower() not in db['blacklist']:
        db['blacklist'].append(arg.lower())
        db['blacklistbackup'].append(arg.lower())
        await ctx.send(f"'{arg.lower()}' added to the veto list.")

      # Messages prompting the user how to use this command upon failed attempt
      else:
        await ctx.send(f"{arg.lower()} has already been blacklisted.")
    else:
      await ctx.send("Use only the key word of the website for example just 'youtube' instead of 'https://www."
                     "youtube.com'")
  else:
    await ctx.send("(v.vetosite [site keyword]) Use only the key word of the website for example just 'youtube' "
                   "instead of 'https://www.youtube.com")


# Sends the blacklist in a readable way
@client.command()
async def blacklist(ctx):
  blacklist = str(db['blacklist'])
  blacklist = blacklist.replace("[", "")
  blacklist = blacklist.replace("]", "")
  blacklist = blacklist.replace(")", "")
  blacklist = blacklist.replace("'", "")
  blacklist = blacklist[19:]
  await ctx.send(blacklist)


# Remove the last veto in the db
@client.command()
async def remveto(ctx):
  length = len(db['blacklist'])
  if length > 0:
    db['blacklist'].pop(length-1)
    await ctx.send("Removed the last veto from the blacklist.")
  else:
    await ctx.send("There are no values in the blacklist.")

keep_alive()
client.run(TOKEN)
