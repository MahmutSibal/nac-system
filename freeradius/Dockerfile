FROM freeradius/freeradius-server:latest-3.2

# Config dosyalarını image içine kopyala ve doğru izinleri ver
# (Windows bind-mount 0777 izni verdiği için FreeRADIUS reddediyor)
COPY clients.conf      /etc/freeradius/clients.conf
COPY mods-enabled/sql  /etc/freeradius/mods-enabled/sql
COPY mods-enabled/rest /etc/freeradius/mods-enabled/rest
COPY sites-enabled/default /etc/freeradius/sites-enabled/default

# FreeRADIUS güvenlik gereği config dosyaları group/other yazılabilir olmamalı
RUN chmod 640 /etc/freeradius/clients.conf \
              /etc/freeradius/mods-enabled/sql \
              /etc/freeradius/mods-enabled/rest \
              /etc/freeradius/sites-enabled/default \
 && chown freerad:freerad \
              /etc/freeradius/clients.conf \
              /etc/freeradius/mods-enabled/sql \
              /etc/freeradius/mods-enabled/rest \
              /etc/freeradius/sites-enabled/default
