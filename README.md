# Ochrona-Danych
Aplikacja na przedmiot ochrona danych

# Inicjacja Bazy danych do testów

docker compose run --rm -it -v ./backend/app:/var/www/app backend python app/db_create.py \n
przykładowe login hasło
Jarek bob
admin admin


# Odpalenie aplikacji
Docker compose up

http://localhost

Wysyłanie e-maili nie działa bo nie chciałem wrzucać moim credentiali do gmaila do pliku .env 
