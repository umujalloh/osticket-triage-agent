FROM php:8.2-apache

RUN apt-get update && apt-get install -y \
    libpng-dev libjpeg-dev libfreetype6-dev \
    libicu-dev libzip-dev unzip curl \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd mysqli intl opcache

RUN a2enmod rewrite

RUN curl -L -o /tmp/osticket.zip \
    https://github.com/osTicket/osTicket/releases/download/v1.18.4/osTicket-v1.18.4.zip \
    && unzip /tmp/osticket.zip -d /tmp/osticket \
    && cp -r /tmp/osticket/upload/* /var/www/html/ \
    && rm -rf /tmp/osticket /tmp/osticket.zip

RUN cp /var/www/html/include/ost-sampleconfig.php /var/www/html/include/ost-config.php \
    && chown -R www-data:www-data /var/www/html \
    && chmod 0666 /var/www/html/include/ost-config.php \
    && chmod -R 0755 /var/www/html/include/i18n \
    && mkdir -p /var/www/html/attachments \
    && chmod -R 0755 /var/www/html/attachments

COPY osticket-plugin/ /var/www/html/include/plugins/triage-webhook/

# Comment out the rm -rf line below for the first build so the osTicket
# installer is reachable, then uncomment and rebuild once install is done.
RUN rm -rf /var/www/html/setup \
    && chown -R www-data:www-data /var/www/html/include/plugins/triage-webhook 
