# Probeer de verberger

## 1. Installeer uv (één keer)

uv is een klein, gratis programma dat de verberger voor je downloadt en start.

Op Windows open je PowerShell en plak je deze regel:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/0.13.5/install.ps1 | iex"
```

Op een Mac open je Terminal en plak je deze regel:

```sh
curl -LsSf https://astral.sh/uv/0.13.5/install.sh | sh
```

Sluit daarna dat venster en open een NIEUW venster.
Het nieuwe commando werkt pas in een nieuw venster.

## 2. Start de verberger

Plak deze regel in het nieuwe venster:

```sh
uvx --python 3.12 --from git+https://github.com/klatte88/piimask-tryit piimask-tryit
```

De eerste keer downloadt hij wat hij nodig heeft, dus dat kan een minuut duren.
Daarna staat er in het venster:

```text
The masker is running. Close this window to stop it.
De verberger draait. Sluit dit venster om te stoppen.
```

De pagina opent vanzelf in je browser.
Start hem elke keer op dezelfde manier.
Een bladwijzer werkt niet: het adres verandert bij elke start.
Draait de verberger al, dan opent dezelfde regel zijn pagina opnieuw.

Stoppen doe je door het venster te sluiten.
Stop je de verberger, dan zijn je tekst en de codes weg.

De pagina is in het Engels.
Klik bovenaan op "Nederlands" voor Nederlands, en op "English" om terug te gaan.

## 3. Probeer het eerst met verzonnen namen

De verberger is gebouwd en getest op Nederlandse tekst.
Bij Engels mist hij waarschijnlijk meer namen.
Hij herkent alleen Nederlandse telefoon- en btw-nummers.
IBAN's herkent hij uit elk land.

1. Plak bij "1. Plak je vraag" een korte tekst met verzonnen namen, een e-mailadres en een telefoonnummer.
2. Klik op "Verberg persoonsgegevens".
3. Klik bij "2. Kopieer naar je AI" op "Kopieer" en plak de verborgen versie in je AI.
4. Plak bij "3. Plak het antwoord terug" het antwoord van je AI en klik op "Zet de echte namen terug".

## 4. Gebruik hem een week voor je echte soort werk

Gebruik hem voor het soort vragen dat je echt aan je AI stelt.
Kijk na elke vraag wat de verberger deed.

1. Selecteer onder "Controleer je oorspronkelijke tekst" wat de verberger heeft gemist, kies bij "Wat is het?" wat het is en klik op "Dit is ook persoonlijk (gemist)".
2. Klik op een gemarkeerd stuk dat niet verborgen hoefde, vink "Dit is geen persoonsgegeven" aan en klik op "Dit hoeft niet verborgen".
3. Klik bij "Antwoord met de echte gegevens" op een teruggezet stuk als het niet klopt.
4. Beantwoord onder "Jouw controle van deze vraag" de vraag "Was het antwoord bruikbaar?" met "Ja", "Deels" of "Nee".
5. Vink "Ik heb alles nagelopen" aan als je de hele tekst hebt gelezen en alles hebt gemarkeerd wat de verberger fout deed.
6. Schrijf bij "Wat viel je op?" wat je opviel, als er iets was.
7. Klik op "Bewaar mijn controle".

Klik op "Nieuwe vraag" voor de volgende.

## 5. Stuur je feedback naar Chris

1. Klik onder "Logboek" op "Maak feedbackpakket".
2. Lees elke vraag in de lijst.
   Hierin staat de verborgen versie van je tekst.
   Wat de verberger niet heeft herkend en jij niet hebt aangevinkt, staat er nog wél in.
3. Vink "Neem de hele tekst mee" aan bij elke vraag die mee mag.
   Vragen zonder vinkje gaan alleen als aantallen mee.
4. Klik op "Bewaar als zip".
   De zip komt in je map Downloads, met een naam die begint met `piimask-feedback-`.
5. Mail de zip naar Chris.

## Wat er met je tekst gebeurt

Je tekst blijft op je eigen computer.
Er wordt niets verstuurd.
In het logboek staat alleen de verborgen versie van elke vraag, nooit je oorspronkelijke tekst.
Logbestanden ouder dan 30 dagen worden gewist zodra je de verberger weer start.

Wil je zien waar het logboek staat, plak dan deze regel:

```sh
uvx --python 3.12 --from git+https://github.com/klatte88/piimask-tryit piimask-tryit where
```

Wil je het logboek en alles wat de verberger bewaart wissen, stop dan eerst de verberger en plak deze regel:

```sh
uvx --python 3.12 --from git+https://github.com/klatte88/piimask-tryit piimask-tryit forget
```

Hij vraagt je eerst `ja` (of `yes`) te typen voordat hij iets wist.
Typ je iets anders, dan wordt er niets gewist.
Draait de verberger nog, dan weigert hij en vraagt hij je eerst te stoppen.

Er is geen bestand om de verberger met een dubbelklik te starten.
Een bestand dat je via e-mail of Drive krijgt, verliest op een Mac zijn toestemming om te starten en wordt geblokkeerd.
Wil je er toch een, vraag het Chris, dan zet hij het samen met je op tijdens een gesprek.

Licentie: MIT (zie LICENSE).
De woordenlijsten houden hun eigen licenties (zie `src/piimask/detect/data/LICENSES.md`).
