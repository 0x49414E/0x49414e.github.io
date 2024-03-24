---
title: SafeHarbor | CTF Writeup - VulnHub
date: 2024-03-20 20:17:00 +/-TTTT
categories: [PENTESTING, CTF]
tags: [vulnhub,writeup,sqli, lfi, rfi, rce, pivoting, dockerbreakout]
---

# SafeHarbor

>Iniciamos nuestro ataque enumerando la red local y buscando la IP de la máquina con `netdiscover`.

```bash
> netdiscover -r 192.168.216.0/24 -P > discover.txt

   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.216.1   00:50:56:c0:00:08      1      60  VMware, Inc.
 192.168.216.2   00:50:56:e2:11:a1      1      60  VMware, Inc.
 192.168.216.160 00:0c:29:2c:d5:fb      1      60  VMware, Inc.
 192.168.216.254 00:50:56:ec:12:b0      1      60  VMware, Inc.

-- Active scan completed, 4 Hosts found.
```

>Exportamos la IP a una variable de entorno con `export IP=192.168.216.160`.
>Iniciamos un escaneo de `nmap`.

```bash
# Nmap 7.94 scan initiated Sat Mar 16 16:56:27 2024 as: nmap -sS --open -p- -T5 -vvv -Pn -n -oN scan.txt 192.168.216.160
Nmap scan report for 192.168.216.160
Host is up, received arp-response (0.037s latency).
Scanned at 2024-03-16 16:56:27 -03 for 77s
Not shown: 65532 closed tcp ports (reset), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 63
MAC Address: 00:0C:29:2C:D5:FB (VMware)

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sat Mar 16 16:57:44 2024 -- 1 IP address (1 host up) scanned in 77.14 seconds
```

>Aplicamos un escaneo aún más exhaustivo, probando scripts de reconocimiento incorporados en la herramienta.

```bash
# Nmap 7.94 scan initiated Sat Mar 16 16:58:58 2024 as: nmap -sCV -p22,80 -oN versions.txt 192.168.216.160
Nmap scan report for 192.168.216.160
Host is up (0.00079s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fc:c6:49:ce:9b:54:7f:57:6d:56:b3:0a:30:47:83:b4 (RSA)
|   256 73:86:8d:97:2e:60:08:8a:76:24:3c:94:72:8f:70:f7 (ECDSA)
|_  256 26:48:91:66:85:a2:39:99:f5:9b:62:da:f9:87:4a:e6 (ED25519)
80/tcp open  http    nginx 1.17.4
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.17.4
|_http-title: Login
MAC Address: 00:0C:29:2C:D5:FB (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar 16 16:59:05 2024 -- 1 IP address (1 host up) scanned in 6.87 seconds
```

>Buscamos páginas y directorios con el script `http-enum`.

```bash
# Nmap 7.94 scan initiated Sat Mar 16 17:00:34 2024 as: nmap --script http-enum -p80 -oN http-enum.txt 192.168.216.160
Nmap scan report for 192.168.216.160
Host is up (0.00050s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /login.php: Possible admin folder
|   /phpinfo.php: Possible information file
|_  /changelog.txt: Version 1:
MAC Address: 00:0C:29:2C:D5:FB (VMware)

# Nmap done at Sat Mar 16 17:00:48 2024 -- 1 IP address (1 host up) scanned in 14.72 seconds
```

>Interesante. Tenemos una filtración de información importante, ya que podemos visualizar el phpinfo.
>Veamos la web.

![1.png]({%link assets/img/safeharbor/1.png%})

>Hacemos una petición, la interceptamos con BurpSuite y cambiamos los valores para aplicar una inyección SQL sencilla.

![2.png]({%link assets/img/safeharbor/2.png%})

>Nos responde correctamente. Se efectuó una SQL Injection.

![3.png]({%link assets/img/safeharbor/3.png%})

>Volvamos y veamos posibles vectores de ataque con el archivo de phpinfo.

![4.png]({%link assets/img/safeharbor/4.png%})

>Podemos hostear un servidor web e incluir nuestra propia URL en caso de que se acontezca un RFI (Remote File Inclusion).

>También se pueden subir archivos al servidor. Esto es una posible superficie de ataque.

![5.png]({%link assets/img/safeharbor/5.png%})

>Volvemos al sistema de banking principal. Vemos lo siguiente:

![6.png]({%link assets/img/safeharbor/6.png%})

>Hay varias páginas, y para cada una de ellas carga un parámetro distinto en la URL. Podemos intentar un LFI. Lo logramos aplicando PHP wrappers, y únicamente incluimos los mismos archivos dado que se está empleando una whitelist por detrás con los nombres de cada sección.

![7.png]({%link assets/img/safeharbor/7.png%})

>Con esto podemos ver el código en base64 de la sección `welcome`. Si lo decodeamos en la terminal:

![8.png]({%link assets/img/safeharbor/8.png%})

>Ahora intentemos incluir un archivo remoto cargado desde nuestra máquina, esta vez que se llame como alguna de las secciones definidas. En este caso, lo llamaré `transfer.php`, y ejecutará `ifconfig`. 

![11.png]({%link assets/img/safeharbor/11.png%})

>Vemos que es un contenedor por la IP que tiene. Ahora subiré un archivo que ejecute una reverse shell, más específicamente utilizaré uno de los scripts de [PentestMonkey](https://github.com/pentestmonkey/php-reverse-shell).

![9.png]({%link assets/img/safeharbor/9.png%})

![10.png]({%link assets/img/safeharbor/10.png%})

>Estamos dentro! Buscamos más contenedores con las tablas ARP.

![12.png]({%link assets/img/safeharbor/12.png%})

>Nos conectamos con `chisel` para generar un túnel TCP y poder pivotear tranquilamente por los distintos contenedores.

![13.png]({%link assets/img/safeharbor/13.png%})

>Ahora intentamos hacer un descubrimiento de hosts con proxychains. Lo haremos filtrando por aquellos que tengan el puerto 80 abierto.

![14.png]({%link assets/img/safeharbor/14.png%})

>Dado que hicimos un descubrimiento por la capa de transporte del modelo TCP/IP, sabemos que además se estuvieron tramitando paquetes ARP por debajo en la capa de enlace de datos. Teniendo esto en cuenta, si hacemos un `arp -a`, nos encontraremos con más contenedores. En este caso, uno que nos llama la atención es el `172.20.0.124` que está corriendo un servicio vulnerable llamado ElasticSearch.

>Si filtramos con `searchsploit` por ElasticSearch, nos encontraremos el script `36337.py` que nos servirá para la explotación de este servicio.

![15.png]({%link assets/img/safeharbor/15.png%})

>Si vemos el `.bash_history` de root:

![16.png]({%link assets/img/safeharbor/16.png%})

>Vemos que está tramitando peticiones al puerto 2375 de la máquina que queremos vulnerar, que además curiosamente es el puerto donde corre la API de Docker.

>Antes de hacer algo, vamos a intentar pasar esta conexión por el túnel TCP que habíamos generado con `chisel` en el primer contenedor. Lo haremos con los siguientes comandos (en el primer contenedor, también):

![17.png]({%link assets/img/safeharbor/17.png%})

>Debemos pasar el `socat` al primer contenedor para poder usar este túnel. Lo hacemos desde nuestra máquina con un servidor web, levantándolo con el comando `sudo python3 -m http.server 80`.

>En la máquina donde ganamos acceso con ElasticSearch, ejecutamos lo siguiente.

![18.png]({%link assets/img/safeharbor/18.png%})

>Esto generará un túnel desde el segundo contenedor hasta nuestra máquina, abriendo nuestro puerto 8888 para comunicarnos hasta el segundo endpoint. Ahora añadimos al archivo `proxychains.conf` el nuevo puerto. 

>Hacemos una petición al servicio web de Docker con `curl` para ver si está activo, guiándonos con el [artículo de HackTricks sobre Docker](https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker).

![19.png]({%link assets/img/safeharbor/19.png%})

>Nos response exitosamente. Ahora solo falta agarrar alguna imagen y crear nuestro propio contenedor con esta API. Esto se describe muy bien nuevamente en HackTricks.

![20.png]({%link assets/img/safeharbor/20.png%})

>Creamos un contenedor utilizando la imagen de Alpine que corría en uno de los contenedores que nos devolvió la primer respuesta, y nos devolvió el ID. 

![21.png]({%link assets/img/safeharbor/21.png%})

>Pegamos nuestra clave SSH pública en el directorio `authorized_keys` de root en el contenedor, que tiene montura del sistema entero y por ende se comunica con el `docker.sock` para cambiar tanto archivos de la máquina host que queremos vulnerar como el contenedor. Decidí subir la clave SSH ya que tiene el puerto 22 abierto.

![22.png]({%link assets/img/safeharbor/22.png%})

>Ahora lo hacemos correr:

![23.png]({%link assets/img/safeharbor/23.png%})

>Listo! Subimos nuestra clave pública al directorio de SSH de root. Podemos conectarnos sin brindar contraseña.

![24.png]({%link assets/img/safeharbor/24.png%})

![25.png]({%link assets/img/safeharbor/25.png%})


