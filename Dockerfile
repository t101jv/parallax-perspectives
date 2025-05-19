FROM php:8.3-apache

COPY ./.content.nO7s6V32/ /var/www/html/.content.nO7s6V32/
COPY ./.htaccess /var/www/html/.htaccess
COPY ./index.php /var/www/html/index.php

RUN chmod -R 777 /var/www
