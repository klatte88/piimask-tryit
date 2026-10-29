# Try the masker

## 1. Install uv (once)

uv is a small free tool that downloads and runs the masker for you.

On Windows, open PowerShell and paste this line:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/0.13.5/install.ps1 | iex"
```

On a Mac, open Terminal and paste this line:

```sh
curl -LsSf https://astral.sh/uv/0.13.5/install.sh | sh
```

Then close that window and open a NEW one.
The new command is only found in a new window.

## 2. Start the masker

Paste this line into the new window:

```sh
uvx --python 3.12 --from git+https://github.com/klatte88/piimask-tryit piimask-tryit
```

The first start downloads what it needs, so it can take a minute.
The window then shows:

```text
The masker is running. Close this window to stop it.
De verberger draait. Sluit dit venster om te stoppen.
```

The page opens in your browser on its own.
Start it the same way each time.
A bookmark won't work: the address changes every start.
If the masker is already running, the same line opens its page again.

To stop it, close the window.
When you stop it, your text and the codes are gone.

The page is in English.
Click "Nederlands" at the top to switch to Dutch, and "English" to switch back.

## 3. Try it with made-up names first

The masker was built and tested on Dutch text.
On English it will likely miss more names.
It only recognises Dutch phone and VAT number formats.
It recognises IBANs from any country.

1. In "1. Paste your question", paste a short text with made-up names, an email address and a phone number.
2. Click "Hide personal data".
3. In "2. Copy to your AI", click "Copy" and paste the hidden version into your AI.
4. In "3. Paste the answer back", paste your AI's answer and click "Put the real names back".

## 4. Use it on your real kind of work for a week

Use it for the kind of questions you really ask your AI.
After each question, check what the masker did.

1. Under "Check your original text", select anything the masker missed, choose what it is under "What is it?" and click "This is personal too (missed)".
2. Click a highlighted piece that didn't need hiding, tick "This is not personal data" and click "This didn't need hiding".
3. In "Answer with the real details", click a restored piece if it is wrong.
4. Under "Your checks for this question", answer "Was the answer useful?" with "Yes", "Partly" or "No".
5. Tick "I checked everything" once you have read the whole text and marked everything the masker got wrong.
6. Write what you noticed under "What did you notice?", if anything.
7. Click "Save my checks".

Click "New question" for the next one.

## 5. Send your feedback to Chris

1. Under "Logbook", click "Make feedback package".
2. Read every question in the list.
   It holds the hidden version of your text.
   Anything the masker didn't recognise and you didn't mark is still in it.
3. Tick "Include the full text" for each question that may go in.
   Questions without a tick go in as counts only.
4. Click "Save as zip".
   The zip lands in your Downloads folder, with a name that starts with `piimask-feedback-`.
5. Email the zip to Chris.

## What happens to your text

Your text stays on your computer.
Nothing is sent anywhere.
Only the hidden version of each question is kept in the log, never your original text.
Log files older than 30 days are deleted the next time you start the masker.

To see where the log is kept, paste this line:

```sh
uvx --python 3.12 --from git+https://github.com/klatte88/piimask-tryit piimask-tryit where
```

To wipe the log and everything else the masker keeps, stop the masker first and paste this line:

```sh
uvx --python 3.12 --from git+https://github.com/klatte88/piimask-tryit piimask-tryit forget
```

It asks you to type `yes` (or `ja`) before it deletes anything.
Anything else deletes nothing.
While the masker is running it refuses and asks you to stop it first.

There is no double-click file to start the masker.
A file sent by email or Drive loses its permission to run on a Mac and gets blocked.
If you want one, ask Chris and he sets it up with you on a call.

Licence: MIT (see LICENSE).
The word lists keep their own licences (see `src/piimask/detect/data/LICENSES.md`).
