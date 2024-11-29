# Mailer Pro

# 1 Client- und Serverarchitektur

## 1.1 Client
Der Client verbindet sich durch Ausführung des Kommandos `./client <ip> <port>` mit dem Server. Nach erfolgreichem Verbindungsaufbau stehen dem Client zunächst nur die Befehle `LOGIN` und `QUIT` zur Verfügung. Um die weiteren Befehle `SEND`, `LIST`, `READ` und `DEL` verwenden zu können, muss sich der Client zuerst mit dem Befehl `LOGIN` authentifizieren. 

Die Anmeldung erfolgt über die FHTW-Zugangsdaten (Kürzel `if23****` und Passwort). Bereits auf der Client-Seite werden die Eingaben auf Richtigkeit geprüft, und der Benutzer erhält unmittelbar Rückmeldungen im Terminal bei fehlerhaften Eingaben. Weiters wird vom Client überprüft, ob die Nachrichtenlänge die Buffergröße übersteigt. Sollte dies der Fall sein, wird eine Fehlermeldung ausgegeben, und die Nachricht wird nicht gesendet.

## 1.2 Server
Der Server wird durch Ausführung von `./server <port> <mail-spool-directoryname>` gestartet. Nach dem Start lauscht er auf eingehende Verbindungen von Clients. Für jeden verbundenen Client wird ein eigener Thread erstellt, um Parallelisierung zu ermöglichen.

Für den Login- und Autorisierungsprozess des Clients wird der LDAP-Server der FH Technikum Wien verwendet. Bevor sich der Client erfolgreich eingeloggt hat, sind ihm nur die Befehle `LOGIN` und `QUIT` erlaubt. Gibt ein Client dreimal hintereinander falsche Zugangsdaten ein, wird seine IP-Adresse zusammen mit einem Zeitstempel in einer Map gespeichert, wodurch die IP-Adresse für 60 Sekunden gesperrt wird. Während dieser Zeit wird bei einer neuen Verbindungsanfrage geprüft, ob die Sperrzeit abgelaufen ist. Solange die Sperre aktiv ist, wird die Verbindung abgelehnt, und der Client erhält keine weiteren Zugriffsmöglichkeiten.

Nach erfolgreichem Login kann der Server die Befehle `SEND`, `LIST`, `READ`, `DEL` und `QUIT` verarbeiten. Alle Befehle werden dabei gemäß den vorgegebenen Spezifikationen überprüft.

Die Nachrichten des Mail-Systems werden in dem beim Serverstart angegebenen Verzeichnis gespeichert. Für jeden Benutzer wird ein eigenes Verzeichnis erstellt, und jede Nachricht wird als separate `.txt`-Datei abgelegt. Der Dateiname folgt dem Format `<username>_<unix-timestamp>`, um die Nachrichten eindeutig zu identifizieren. 

Weiters wird im Server überprüft, ob die Nachricht die Buffergröße von 64KB übersteigt. Sollte dies der Fall sein, wird der Empfangsvorgang abgebrochen und `ERR` an den Client gesendet. 

Bei Fehleingaben oder fehlgeschlagenen Ausführungen sendet der Server `ERR` an den Client zurück.

# 2 Verwendete Technologien und Bibliotheken
Das System verwendet eine Mischung aus C und C++. Dabei werden unter anderem folgende Bibliotheken verwendet:
- `<ldap.h>`: Für die Benutzerauthentifizierung über den FHTW-LDAP-Server.
- `<thread>`: Zur Parallelisierung der Client-Verbindungen.
- `<fstream>`, `<sstream>` und `<filesystem>`: Zum Erstellen von Verzeichnissen, Bearbeiten von `.txt`-Dateien sowie zum Lesen und Schreiben in diese.
- `<mutex>`: Zur Vermeidung von Race-Conditions.
- `<chrono>`: Für die Erstellung eindeutiger Zeitstempel (Timestamps) der Nachrichten und für das Sperren von IP-Adressen nach dreimaliger falscher Eingabe der Benutzerdaten.
- `<map>`: Für die Liste der ungültigen Anmeldeversuche und der gesperrten IP-Adressen.

# 3 Entwicklungsstrategie
Der Entwicklungsprozess folgte einer iterativen Vorgehensweise. Die Arbeit wurde stets zu zweit online durchgeführt, wobei die Live-Share-Extension von Visual Studio Code zum Einsatz kam. 

Zu Beginn wurde die grundlegende Kommunikation zwischen Server und Client implementiert. Darauf aufbauend wurde der Server durch den Einsatz von Threads parallelisiert. Abschließend wurde die Benutzerauthentifizierung über den FHTW-LDAP-Server integriert.
