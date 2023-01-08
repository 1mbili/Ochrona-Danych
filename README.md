# Ochrona-Danych
Aplikacja na przedmiot ochrona danych

# Inicjacja Bazy danych do testów

docker compose run --rm -it -v ./backend/app:/var/www/app backend python app/db_create.py <br />
przykładowe login hasło <br />
Jarek bob <br />
admin admin <br /> 

# Inicjalizacja Bazy danych bez testowych użytkowników

docker compose run --rm -it -v ./backend/app:/var/www/app backend python app/db_prod.py <br />

# Odpalenie aplikacji

Docker compose up

http://localhost