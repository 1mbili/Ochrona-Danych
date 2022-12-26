## Architektura ogólna

Docker Compose będzie zawierał poniższe kontenery:
 + Nginx : reverse proxy dla api w pythonie i obsługa ssl (https)
 + Flask : Obsługa aplikacji
 + Mysql : Baza danych
 + Adminer : Do debugu i przeglądania bazy danych, dla admina

## Funkcjonalność aplikacji

 + Użytkownik może dodać notatki w markdown
 + Użytkownik może zaznaczyć checkbox przy każdej notatce, aby zrobić ją publiczną.
 + Użytkownik może zaznaczyć checkbox przy każdej notatce, aby ją zaszyfrować. Szyfrowanie szyfrem blokowym AES w trybie CBC. Użytkownik ma pole do podania tajnego hasła do notatki, albo jest wykorzystywane hasło użytkownika do aplikacji w przypadku braku podania hasła dla konretnej notatki.
 - Dostęp do notatek publicznych poprzez uri z nazwą szukanego użytkownika np.: notes/public/marek
 - (Opcjonalna) Okno do wyszukiwania publicznych notatek po tytule lub/albo zawartości


## Logowanie i Rejestracja

 + Użytkownik podaje login, e-mail i hasło. Podstawowa walidacja hasła po stronie html w obiekcie ,,form". Właściwa walidacja hasła po stronie backendu.
 + Hasło -> od 10 do 20 znaków, musi być duża i mała litera oraz znak specjalny. Dodatkowo sprawdzana entropia hasła musi być większa od 70. Przy zamałej entropi użytkownik jest proszony o zmianę hasła.
 + Hasło jest kodowane za pomocą funkcji bcrypt, sól jest wybierana losowo przez bcrypt, pieprz jest zapisany w sekretnym pliku .env
 + Hasła i loginy są zapisywane w bazie danych
 + Przy logowaniu generowany jest token jwt, który jest używany później do uwierzytelniania użytkownika przy requestach api i zabezpieczania dostępu do zasobów. JWT_Secret zapisany w pliku .env, jwt w trybie symetrycznym hs256. Token jwt ulega przedawnieniu po 30 minutach.
 + Możliwe odzyskanie odstępu do konta poprzez otrzymanie e-maila z nowym hasłem.
  

## Zabezpieczenie przed próbami nieuprawnionego logowania.

 + Zapisywanie w bazie danych ostatich 10 prób logowania. Po 10 nieudanych próbach logowania w ciągu 5 minut, timeout na 3 minuty. Licznik jest resetowany poprzez poprawne logowwanie oraz po upłynięciu timeouta.
 + Dodanie opóźnienia 0.5 sec do logowania.
 - Honypot na hackera. Po próbie logowania z danymi login:admin, passwd: admin123, wyświetlenie filmiku ,Britney Spears - Oh baby one more time" i zapisanie IP próbującego.
 - Honypot na hackera. Po próbie logowania z prostym sql injection typu login:admin'-- wyświetlenie filmiku ,Britney Spears - Oops!...I Did It Again" i zapisanie IP atakującego i dodanie go do blacklisty IP.
 + Brak informacji o przyczynie nieudanego logowania dla użytkownika. 


## Inne zabepieczenia

 + Ochrona przed XSS poprzez sanityzację inputów od usera przy użyciu bleach
 + Ochrona przed SQL injection poprzez przekazywanie bezpiecznych parametrów np.:
   cur.execute("select * from lang where date=:year", {"year": 1972})
 + Przy nowym logowaniu wysłanie informacji e-mailem o nowym użądzeniu użytym do logowania
 + Wyłączenie w nginx informacji o serverze ( header `server`)
