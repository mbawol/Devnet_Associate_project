# Devnet_Associate_project
Skrypt w Pythonie do automatycznej konfiguracji adresacji IPv4 na interfejsach sieciowych urządzeń Cisco IOS XE. Wykorzystuje protokół RESTCONF oraz modele danych YANG (`ietf-interfaces`, `ietf-ip`).
Projekt skupia się na konfiguracji i testach interfejsów logicznych typu Loopback.

## Cel projektu
* **Tworzenie/Aktualizacja:** Wysyła żądanie `PUT` w celu utworzenia lub nadpisania konfiguracji interfejsu.
* **Walidacja:** Weryfikuje poprawność adresu IP oraz maski podsieci przed wysłaniem.
* **Bezpieczeństwo:** Nie wymaga wpisywania hasła w komendzie (obsługa `getpass` oraz zmiennych środowiskowych).
* **Weryfikacja:** Po konfiguracji skrypt automatycznie pobiera dane (`GET`), aby potwierdzić sukces operacji.

##  Wymagania
* Python 3.6+
* Dostęp do **Cisco DevNet Sandbox**
* Aktywne połączenie VPN z Sandboxem

##  Konfiguracja środowiska (VPN)

Skrypt wymaga bezpośredniego połączenia z siecią zarządzającą urządzenia.

1.  Zarezerwuj **IOS XE on Catalyst 8000v** w Cisco DevNet Sandbox.
2.  Połącz się przez VPN (dane znajdziesz w zakładce *Quick Access* w panelu Sandboxa).

**(OpenConnect):**  
  ```bash
 sudo openconnect --protocol=anyconnect --user=<VPN_USER> <VPN_ADDRESS>
  ```

##  Użycie

### Podstawowe uruchomienie
Skrypt zapyta interaktywnie o hasło (nie będzie widoczne podczas wpisywania).

```bash
python3 Devnet_zaliczenie.py --intf Loopback101 --ip 172.16.101.1
```


### Pełna konfiguracja (Maska + Opis)
Ustawienie niestandardowej maski podsieci oraz opisu interfejsu.
```bash
python3 Devnet_zaliczenie.py \
  --intf Loopback200 \
  --ip 10.2.2.1 \
  --netmask 255.255.255.252 \
  --desc "Link do oddzialu w Krakowie"
```

### Wyłączenie interfejsu (Shutdown)
  Utworzenie interfejsu w stanie admin down(wyłączony)
  ```bash
  python3 Devnet_zaliczenie.py --intf Loopback99 --ip 192.168.99.1 --shutdown
  ```
