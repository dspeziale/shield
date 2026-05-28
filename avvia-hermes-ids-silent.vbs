' avvia-hermes-ids-silent.vbs
' Avvia hermes-ids senza finestra visibile (per Task Scheduler / avvio automatico)
' NOTA: richiede Npcap installato. Per packet capture reale serve avvio come Amministratore.
' Per mock mode (test), cambia il comando qui sotto aggiungendo --mock-capture

Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\Users\marco.bellomo\Desktop\JobArea\Codice\Ranger\hermes"

' Avvio con cattura reale (richiede admin + Npcap)
cmd = "python -m src.main --config config\config.yaml"

' OPPURE avvio in mock mode (no admin necessario):
' cmd = "python -m src.main --config config\config.yaml --mock-capture"

WshShell.Run "cmd /c " & cmd & " >> logs\hermes-ids.log 2>&1", 0, False

Set WshShell = Nothing
