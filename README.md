# basic-docker-wordpress

## Setup

### Make .env

```
cp .env.default .env
```

### Make wp-config.php

```
cd src
cp wp-config.php.default wp-config.php
```

## Development

Run nginx, php, mariaDB and Mailhog in Docker locally.

```
docker-componse up
```

Open page

```
http://localhost:8080
```

### Access docker containers

```
docker exec -it bdw_nginx bash
docker exec -it bdw_php bash
docker exec -it bdw_db bash
docker exec -it bdw_smtp bash
```

## DB operation tips

### Dump data

```
mysqldump -u root -p -h 127.0.0.1 bdwdb > /var/lib/mysql/bdwdb.backup
```

### Import db
```
mysql -u root -p -h 127.0.0.1 bdwdb < /var/lib/mysql/bdwdb.backup
```

## Production

1. Upload `src` to the server
2. Replace `src/wp-config.php` with production one.

### Checklist
- Check if `wp-login.php` is not accesable
