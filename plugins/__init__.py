"""
Plugin directory per detector IDS custom.

Ogni file .py in questa directory viene caricato automaticamente
se plugins.enabled=true nella configurazione.

Requisiti per un plugin valido:
    1. Definire una classe che eredita da BaseDetector
    2. Impostare il class attribute `detector_name` (stringa unica)
    3. Applicare il decorator @register_detector
    4. Implementare process_packet() e opzionalmente process_arp_table()

Vedi plugins/example_detector.py per un template completo.
"""
