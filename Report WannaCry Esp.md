# Introducción


Este informe es la conclusión del curso **PMAT (Practical Malware Analysis & Triage)**, en el que se pide analizar una muestra de malware real. Para ello he elegido uno de los ransomware más famosos: WannaCry, que causó estragos allá por 2017.

De entre la gran variedad de ransomware que hay, las dos categorías principales diría que son: 
- Ransomware de cifrado: ataca cifrando archivos valiosos para que no se pueda acceder a ellos.
- Ransomware de bloqueo: bloquea el acceso al ordenador, impidiendo su uso.

**WannaCry** es un ransomware de cifrado con capacidades de gusano identificado por primera vez en mayo de 2017. Se propaga de forma automática en sistemas Windows mediante el protocolo SMB aprovechando la vulnerabilidad conocida como EternalBlue (CVE-2017-0144). También emplea el backdoor DoublePulsar. Una vez ejecutado con éxito en un equipo vulnerable, cifra los archivos de la víctima y muestra una nota de rescate con la idea de extorsionar a los usuarios y que paguen dinero en Bitcoin con la promesa de que se les devuelva el acceso a sus archivos.



# Análisis Estático Básico


## 1 - Hashes de la muestra

- *MD5*: `db349b97c37d22f5ea1d1841e3c89eb4`
    
- *SHA1*: `e889544aff85ffaf8b0d0da705105dee7c97fe26`
    
- *SHA256*: `24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c`
 
Al buscar estos hashes en VirusTotal se observa que la muestra es identificada como WannaCry. Además, la plataforma proporciona información adicional, como los nombres de detección, el análisis de la comunidad, etc:

<img width="639" height="476" alt="imagen" src="https://github.com/user-attachments/assets/f098861f-f83a-4472-a841-03efce541449" />

  

## 2 - Strings

Pueden encontrarse muchos strings relacionados con la criptografía:

```
CryptAcquireContextA
CryptGenRandom
Microsoft Base Cryptographic Provider v1.0
CryptReleaseContext
Microsoft Enhanced RSA and AES Cryptographic Provider
CryptGenKey
CryptDecrypt
CryptEncrypt
CryptDestroyKey
CryptImportKey
CryptAcquireContextA
WanaCrypt0r
```

Estos strings indican que la muestra usa la API criptográfica de Windows y que va a realizar operaciones relacionadas, como la generación de claves, el cifrado, el descifrado y la gestión de claves. Esto encaja con las funcionalidades de cifrado de WannaCry, aunque sin proporcionar información sobre su uso exacto.

También se puede encontrar una URL sospechosa:  

```
hxxp[://]www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com
```

Es conocido que esta URL está asociada con el kill switch de WannaCry. WannaCry intenta conectarse a este dominio durante su ejecución. Si la conexión se establece correctamente, el malware finaliza su ejecución.

Aparece también una lista de las extensiones de archivo que el malware intentará cifrar:

<details>
<summary>Lista de extensiones objetivo</summary>

```text
.der
.pfx
.key
.crt
.csr
.p12
.pem
.odt
.ott
.sxw
.stw
.uot
.3ds
.max
.3dm
.ods
.ots
.sxc
.stc
.dif
.slk
.wb2
.odp
.otp
.sxd
.std
.uop
.odg
.otg
.sxm
.mml
.lay
.lay6
.asc
.sqlite3
.sqlitedb
.sql
.accdb
.mdb
.dbf
.odb
.frm
.myd
.myi
.ibd
.mdf
.ldf
.sln
.suo
.cpp
.pas
.asm
.cmd
.bat
.ps1
.vbs
.dip
.dch
.sch
.brd
.jsp
.php
.asp
.java
.jar
.class
.mp3
.wav
.swf
.fla
.wmv
.mpg
.vob
.mpeg
.asf
.avi
.mov
.mp4
.3gp
.mkv
.3g2
.flv
.wma
.mid
.m3u
.m4u
.djvu
.svg
.psd
.nef
.tiff
.tif
.cgm
.raw
.gif
.png
.bmp
.jpg
.jpeg
.vcd
.iso
.backup
.zip
.rar
.tgz
.tar
.bak
.tbk
.bz2
.PAQ
.ARC
.aes
.gpg
.vmx
.vmdk
.vdi
.sldm
.sldx
.sti
.sxi
.602
.hwp
.snt
.onetoc2
.dwg
.pdf
.wk1
.wks
.123
.rtf
.csv
.txt
.vsdx
.vsd
.edb
.eml
.msg
.ost
.pst
.potm
.potx
.ppam
.ppsx
.ppsm
.pps
.pot
.pptm
.pptx
.ppt
.xltm
.xltx
.xlc
.xlm
.xlt
.xlw
.xlsb
.xlsm
.xlsx
.xls
.dotx
.dotm
.dot
.docm
.docb
.docx
.doc
```
</details>

Aparecen strings relacionados con el protocolo SMB, y, presumiblemente, con la explotación de EternalBlue:

```
\%s\IPC$
\172.16.99.5\IPC$
\192.168.56.20\IPC$
```

Además, se pueden encontrar largas cadenas alfanuméricas. Aparentemente podría tratarse de cadenas codificadas en Base64, aunque no es seguro que así sea:

<img width="724" height="473" alt="imagen" src="https://github.com/user-attachments/assets/23a9ba11-3414-482c-8ab6-08e8dd3972e7" />

Se podría intentar decodificar las cadenas, pero sólo una de ellas tiene los caracteres `==` al final, por lo que las diferentes cadenas podrían formar parte de una cadena mucho más grande. Debido a ello, no es posible decodificarlas sin saber el orden, y de momento no tengo forma de poder inferirlo. Si durante la ejecución se observa actividad relacionada con estas cadenas, podría ser posible determinar cómo la muestra accede a ellas, las combina o las procesa. Esto revelaría cómo serían concatenadas y podría hacer posible decodificar y analizar su contenido.


## 3 - PEStudio


### Imports


Al analizar la muestra en PEStudio se puede ver en primer lugar que fue compilado con Microsoft Visual C++ v6.0 y que se trata de un ejecutable PE de 32 bits:

<img width="371" height="151" alt="imagen" src="https://github.com/user-attachments/assets/8459f981-2a64-4db6-be7e-085aa35bbc7f" />

Figuran 91 imports, de los cuales 30 están marcados como potencialmente peligrosos o sospechosos:

<img width="356" height="249" alt="imagen" src="https://github.com/user-attachments/assets/f9c415be-38c2-4753-8556-5eed538d7aa9" />

De entre ellos hay varios que presentan una importación ordinal, la cual es una técnica mediante la cual un PE importa funciones de una DLL usando el número ordinal de la función en lugar de su nombre. Esto también es sospechoso porque puede ser una forma de ofuscación ligera al llamar a ciertas APIs.

De todas maneras, este tipo de técnica no es necesariamente maliciosa y también puede darse en software legítimo ya que hace que los binarios puedan ser más pequeños y que la velocidad de carga mejore. Aunque no es común en software moderno.

<img width="817" height="234" alt="imagen" src="https://github.com/user-attachments/assets/024f9c65-4261-4ed8-beb8-f1342d731917" />

Puede verse que por el nombre hacen referencia al uso de un socket, pero lo más revelador es que la DLL a la que llaman es WS2_32.dll, la Windows Socket Library, por lo que estos imports puede que sirvan al comportamiento de gusano que tiene el WannaCry.

MalAPI es una página web muy útil que cuenta con una clasificación de determinadas apis a menudo usadas por malware, y señala qué uso se les suele dar. Estas son las presentes en la muestra y señaladas como sospechosas: 

<details>
<summary>Clasificación en MalAPI de imports marcados</summary>
	
<img width="2848" height="4683" alt="imagen" src="https://github.com/user-attachments/assets/964e2e2f-e8d4-471d-a302-68708bf6634a" />

</details>

Por una parte, tenemos las relacionadas con la comunicación de red:
- **GetAdaptersInfo**: comúnmente usada para obtener información acerca de los adaptadores de red presentes en el sistema.
- **InternetOpenA, InternetOpenUrlA, InternetCloseHandle**: pueden utilizarse para inicializar el acceso a Internet, abrir una URL o recurso y liberar los handles asociados.

Por otra parte, relacionadas con la encriptación:
- **CryptAcquireContextA, CryptGenRandom**: funciones de carácter criptográfico.

Finalmente, relacionadas con la persistencia:
- **CreateServiceA**
- **StartServiceA**
- **StartServiceCtrlDispatcherA**
- **OpenSCManagerA**


### Segunda fase del malware


Se aprecia que hay un ejecutable de 32 bits dentro de la muestra:

<img width="724" height="75" alt="imagen" src="https://github.com/user-attachments/assets/8f1fd095-87d7-4215-8bec-725822e4913c" />

Esto podría indicar que la primera fase de WannaCry actuaría como un dropper, es decir, que contiene un ejecutable en su interior, el cual constituiría su segunda fase o segunda etapa. Se analizará esta segunda fase del malware más adelante, en un apartado propio.



# Análisis Dinámico Básico


## 1 - Indicadores basados en red


A modo de kill switch, intenta conectar al principio de la ejecución con la URL:

`hxxp[://]www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com` 

<img width="805" height="154" alt="imagen" src="https://github.com/user-attachments/assets/8f0e555c-e989-4cf3-aea4-b9bee0550773" />

Si la conexión es exitosa, el programa deja de actuar y no realiza ningún proceso más. Esto es lo que permitió parar el ataque, ya que el investigador Marcus Hutchins registró este dominio, ayudando a detener la propagación global del ransomware en mayo de 2017.

Luego, si se empieza a ejecutar el payload, se observa que empieza a haber mucha actividad de red, debido a la funcionalidad de worm que tiene WannaCry, expandiéndose por la red. Aquí puede verse, tanto en wireshark como a nivel de procesos del sistema, cómo intenta conectarse con el resto de posibles sistemas en la red, haciendo un barrido por las diferentes IPs de la red. Por otra parte, tenemos que el puerto al que apunta siempre es el **445**. Esto se debe a que el protocolo SMB opera en ese puerto, el **445**, y por lo tanto es al que se debe apuntar para la explotación de **EternalBlue**.

<img width="428" height="272" alt="imagen" src="https://github.com/user-attachments/assets/dc0fc126-9876-4481-a4ad-a79ecd31ad00" />

<img width="910" height="197" alt="imagen" src="https://github.com/user-attachments/assets/576e3455-c496-49dd-8feb-f06be9755146" />

Se inicia otra conexión con un proceso nuevo llamado `taskhsvc.exe` y otra con `@WanaDecryptor@.exe`, dirigidas al localhost.

<img width="892" height="78" alt="imagen" src="https://github.com/user-attachments/assets/3d851202-2e68-42f0-bd98-ec2e7e33e159" />

Puede verse además que este proceso deja el puerto 9050 a la escucha para todas las interfaces:

<img width="894" height="66" alt="imagen" src="https://github.com/user-attachments/assets/92bb02bb-2f66-4516-9b83-75ef27875302" />

He intentado conectarme a dicho puerto usando netcat, sin éxito.

Tras investigar un poco, descubro que el puerto 9050 es usado por defecto por el proxy SOCKS de Tor. Como hipótesis personal, creo que esto podría ser un backdoor de algún tipo, que permitiese al atacante conectarse al sistema mediante el uso de la red Tor.

Para intentar captar el comportamiento de gusano de WannaCry, puse en la red virtual una máquina Windows 7 vulnerable a EternalBlue:

<img width="646" height="245" alt="imagen" src="https://github.com/user-attachments/assets/b5b64c0c-98f8-4b48-876b-11a321da8350" />

Sin embargo, tras varios intentos, no se consiguió captar la propagación por la red del malware. Esto probablemente sea debido a que la vulnerabilidad EternalBlue no tiene una tasa de éxito demasiado elevada. Como curiosidad, detecté que uno de los intentos de explotación no usa como path la IP de la VM vulnerable, sino 192.168.56.20, lo cual aparece como una ruta IPC$ en los strings identificados en el análisis estático:

<img width="563" height="217" alt="imagen" src="https://github.com/user-attachments/assets/636fa03d-b363-40c5-9cec-2f96f92019c0" />

Esto podría indicarnos que el malware fue desarrollado en virtualbox, usando su modo host-only, ya que es el rango de IPs que usa por defecto: 192.168.56.0/24. Aunque esto es sólo una hipótesis personal.


## 2 - Indicadores basados en host


Nuestra mejor herramienta en esta sección es procmon. Para empezar, se ejecuta la muestra como administrador y se establece como filtro el nombre de proceso que tendrá el ejecutable. Como se ha visto, la primera fase de este malware actúa un dropper, por lo que se establece como filtro *Operation is CreateFile* en procmon y se podrá ver el nombre que se le da a la segunda fase del malware y dónde se creará. Al establecer este filtro se ven muchos archivos como objetivo de WannaCry, pero eso es sólo porque la API *CreateFile* sirve tanto como para crear archivos nuevos como para acceder a archivos en general:

<img width="438" height="184" alt="imagen" src="https://github.com/user-attachments/assets/6c70220e-fb2f-482b-8407-b381448b7288" />

Teniendo en cuenta las capacidades de la API *CreateFile*, es de suponer que el malware verifica primero la existencia de un archivo llamado *tasksche.exe*, el cual presumiblemente es la segunda fase, en la ruta *C:\Windows*, y si no lo encuentra, lo crea, como puede inferirse de las dos operaciones sucesivas remarcadas y su resultado.

<img width="305" height="222" alt="imagen" src="https://github.com/user-attachments/assets/63503066-ff92-4120-a062-20afb4e90c46" />

Sabiendo ahora cómo se llama la segunda fase, se establece como filtro para seguir investigando. Puede verse que hay una operación con un string alfanumérico extraño:

<img width="426" height="106" alt="imagen" src="https://github.com/user-attachments/assets/f74375df-037c-4bcd-a868-3ba3157467b4" />

El cual es una carpeta que creada por el payload:

<img width="401" height="178" alt="imagen" src="https://github.com/user-attachments/assets/1080e705-17a5-4a4d-a25c-fd9fb55a17b5" />

En dicha carpeta puede verse multitud de archivos, así como el archivo que conforma la segunda fase (`tasksche.exe`):

<img width="325" height="476" alt="imagen" src="https://github.com/user-attachments/assets/bbdbc383-59f3-4457-81c9-c134a4d7e3c6" />

También aparecen 3 archivos de nombre 00000000. Al analizar el de extensión .pky, puede verse lo siguiente:

<img width="638" height="232" alt="imagen" src="https://github.com/user-attachments/assets/a52815c9-b827-4657-a006-0c2a4a3acbb0" />

La mención al sistema criptográfico RSA y la similitud de los nombres, hace pensar que estos tres archivos están involucrados en el proceso de cifrado de los datos.

Al poner como filtro en procmon el nombre de la carpeta, se obtienen un resultado interesante:

<img width="486" height="52" alt="imagen" src="https://github.com/user-attachments/assets/795b135c-d004-4b9e-ac8b-4f07928460bf" />

La creación de un nuevo registro con el nombre de la carpeta creada y su posterior inicio. Yendo al registro:

<img width="602" height="206" alt="imagen" src="https://github.com/user-attachments/assets/e810bdf1-9433-40db-886e-8848b14e811d" />

El cual sirve a un servicio con el mismo nombre y que se encarga de ejecutar el payload. Esto es un mecanismo de persistencia que se encargará de ejecutarlo cada vez que se inicie el equipo, cifrando todo nuevo archivo que el usuario haya creado tras la infección inicial, intentando esparcir de nuevo el malware, etcétera.

En efecto, en servicios puede verse el servicio de persistencia creado, el cual se encuentra detenido al principio y cuenta con inicio automático:

<img width="383" height="371" alt="imagen" src="https://github.com/user-attachments/assets/67fdd899-c8d8-4b47-bc9c-c2797c6a5bf6" />

Por último, los indicadores de host más claros y evidentes: casi todos los archivos quedan cifrados y no se puede acceder a ellos. La extensión de los archivos pasa a ser `.WNCRY`:

<img width="231" height="237" alt="60" src="https://github.com/user-attachments/assets/274ff6ab-67a1-4b46-bf9a-e3a0bf83c2c6" />

Además, el fondo de pantalla cambia a uno con instrucciones para pagar y aparece esta ventana con instrucciones más detalladas para el pago:

<img width="1541" height="669" alt="imagen" src="https://github.com/user-attachments/assets/7e546c70-4d88-4908-b2bb-442329d195cd" />

Mientras comprobaba eventos en procmon para la realización de este análisis, me di cuenta de que por mucho de que cerrara la ventana con instrucciones, de nombre *Wana Decrypt0r 2.0*, siempre volvía a aparecer, resultando muy molesta al usuario. Comprobé que *tasksche.exe* vuelve a abrir siempre el proceso, apareciendo la ventana cada vez. Sin embargo, si se termina *tasksche.exe* no volverá a aparecer la ventana, y tampoco si se elimina el archivo *@WanaDecryptor@.exe* de la carpeta creada por el malware.

Investigando en procmon sobre este ejecutable, encontré que al iniciarse, ejecuta el siguiente comando:

<img width="838" height="368" alt="imagen" src="https://github.com/user-attachments/assets/092eeee3-3b90-411a-8cc2-e1df7b3a6eb5" />

```
cmd.exe /c  
vssadmin delete shadows /all /quiet  
& wmic shadowcopy delete  
& bcdedit /set {default} bootstatuspolicy ignoreallfailures  
& bcdedit /set {default} recoveryenabled no  
& wbadmin delete catalog -quiet
```

Examinando el comando paso a paso:

- **vssadmin delete shadows /all /quiet**: elimina todas las Volume Shadow Copies (puntos de restauración del sistema) sin confirmación
- **wmic shadowcopy delete**: elimina las shadow copies mediante WMI. Esto proporciona otro mecanismo para eliminar las Volume Shadow Copies.
- **bcdedit /set {default} bootstatuspolicy ignoreallfailures**: modifica el Boot Configuration Data para que Windows ignore errores de arranque y no muestre opciones de recuperación automática
- **bcdedit /set {default} recoveryenabled no**: deshabilita el entorno de recuperación de Windows (WinRE), lo cual impide la reparación automática y la restauración desde el entorno de recuperación
- **wbadmin delete catalog -quiet**: borra el catálogo de backups de Windows Backup

Es evidente que este ejecutable se encarga de, entre otras cosas, la fase antirecuperación del malware mediante la ejecución de este comando. El malware no sólo cifra los datos, sino que además dificulta su recuperación.


# Análisis Estático Avanzado


Mediante el análisis avanzado se pueden ver ciertos aspectos de la muestra a nivel interno. Por ejemplo, el killswitch comentado en la sección de indicadores basados en red:

<img width="637" height="632" alt="imagen" src="https://github.com/user-attachments/assets/1de95c47-3ee0-43b7-967e-c5582f30de49" />

Puede verse en *1* que se pasa el string que contiene la url al registro ESI para que pueda ser usada luego como argumento. En *2* se ven las llamadas a las funciones que realizarán la comunicación web a dicha url. Luego, si no hay respuesta por parte de la web, irá por *3* y continuará ejecutándose de forma normal. Si hay respuesta, irá por *4* y el programa saldrá sin haber cifrado ninguno de los archivos.

Por otra parte, puede verse también cuando guarda en disco el ejecutable que lleva en su interior, debido a diferentes llamadas a APIs que realiza para este fin. Primero, se ve cómo carga en registro los strings de las llamadas que va a hacer a las APIs para crear un archivo y escribir en él:

<img width="612" height="368" alt="imagen" src="https://github.com/user-attachments/assets/e7c8c192-1186-4167-abd6-a87aeb974a52" />

Luego, hace uso de estas APIs para buscar el recurso, cargarlo, obtener su puntero y su tamaño:

<img width="482" height="632" alt="imagen" src="https://github.com/user-attachments/assets/a5154c42-ff2b-42ed-9744-99b5163743a2" />

Para finalizar, se ve el nombre que se le va a poner al archivo, además de, por ejemplo, la ruta en que se va a guardar, etc:

<img width="305" height="419" alt="imagen" src="https://github.com/user-attachments/assets/8d894136-c1cf-41a0-bd71-19d379e4f1b7" />


# Análisis Dinámico Avanzado


He intentado manipular el comportamiento de worm de WannaCry para intentar capturar el momento en que se intenta llevar a cabo la explotación de EternalBlue y la propagación de WannaCry. Sin embargo, en mis pruebas previas el exploit siempre falla y no consigue infectar a la VM vulnerable. Por ello, decidí investigar dinámicamente en qué punto fallaba el flujo de ejecución y determinar si una modificación de dicho flujo permitiría alcanzar la etapa posterior de envío del payload, el cual intentaré capturar usando wireshark.

Como punto de partida para empezar a investigar, tengo los intentos de explotación de EternalBlue que he podido ver en la sección de análisis dinámico básico:

<img width="563" height="217" alt="imagen" src="https://github.com/user-attachments/assets/49900272-73df-4360-8867-35137943f419" />

Strings que contienen la cadena `IPC` ya han aparecido en la sección de análisis estático básico, por lo que las busco mediante Cutter para saber la dirección de memoria en que se cargan esos strings:

<img width="369" height="73" alt="imagen" src="https://github.com/user-attachments/assets/7f9b2023-9bb4-4024-a7f9-037379cba7c5" />

Usando las referencias cruzadas (X-Refs), se puede saber en qué instrucción se carga ese string en memoria:

<img width="767" height="409" alt="imagen" src="https://github.com/user-attachments/assets/770f5020-d8c5-4f82-a70e-6b5e1799f1c1" />

Una buena característica de Cutter es que durante el análisis permite cambiar el nombre a las funciones a voluntad, por lo que subo en la jerarquía y renombro a la función como `EternalBlue`. 

Por otra parte, algo que había descubierto en el análisis estático eran largas cadenas alfanuméricas. Hasta este momento, no se ha observado que estos strings fuesen usados durante el flujo de ejecución:

<img width="724" height="473" alt="imagen" src="https://github.com/user-attachments/assets/23a9ba11-3414-482c-8ab6-08e8dd3972e7" />

Bajo la sospecha de que estos strings podían estar relacionados con la propagación del malware, realicé los mismos pasos en Cutter que para determinar cuál era la función que tomaría este papel. Renombré dicha función como `Payload`. Luego, subiendo en la jerarquía de llamadas, veo que están muy cerca una de otra:

<img width="559" height="447" alt="imagen" src="https://github.com/user-attachments/assets/43f66340-bf1d-47f7-9acb-774116a8d7fb" />

La función a la que llamé `EternalBlue` (*1*) se halla muy cerca y antes de la función a la que denominé `Payload` (*2*), lo cual tendría sentido, porque primero se comprueba que funciona el exploit y luego se manda el payload. Por lo tanto, los saltos condicionales en (*3*) y (*4*) son los que hay manipular. Establezco un breakpoint en `0x00407582` para controlar paso a paso la ejecución del programa.

Sin embargo, el breakpoint nunca se activa. Al correr el programa aparece en el debugger que la ejecución ha terminado, pero el resto de procesos ya descubiertos en este análisis sí que se llevan a cabo. Con esto en mente y mirando más cuidadosamente, me he dado cuenta de que tras la comprobación del killswitch (*1*), el PID del proceso cambia (*2*):

<img width="651" height="196" alt="imagen" src="https://github.com/user-attachments/assets/287dcae5-821b-48d4-a61a-66ead44b553d" />

<img width="427" height="172" alt="imagen" src="https://github.com/user-attachments/assets/230c7a88-1581-4555-9932-d4a5259e3bd9" />

En los detalles del evento puede verse que se ejecuta de nuevo la primera fase del malware con el flag `-m security`. Se puede ver también que el PID del nuevo proceso coincide con el mostrado en la imagen anterior. El problema que me surge es que pierdo el control de la ejecución en el debugger tras la comprobación del killswitch. Esto explica por qué se perdía el control de la sesión de debugging después de la comprobación del kill switch: la ejecución relevante para la siguiente etapa tenía lugar en un proceso diferente.

La solución que usé fue poner un breakpoint en la función que crea nuevos hilos para que se pare la ejecución en ese punto, comprobar procmon cada vez y vincular rápidamente el debugger x32dbg al nuevo proceso, pausándolo una vez vinculado. El problema de esto es que no tengo control sobre las primeros momentos de la ejecución de este nuevo proceso. No obstante, fui lo suficientemente rápido como para poder continuar la investigación. Al poco de iniciarse el nuevo proceso, se termina el anterior:

<img width="260" height="134" alt="imagen" src="https://github.com/user-attachments/assets/8e0c8188-17e8-4294-a84a-a20f6ce13582" />

Ahora sí, tras asociar el debugger al nuevo proceso, se para la ejecución en el breakpoint fijado en la función `EternalBlue`. Al hacer Step Over sobre esa función se ve el tráfico de red del intento de explotación, con el mismo resultado que en la sección de análisis dinámico básico:

<img width="825" height="215" alt="imagen" src="https://github.com/user-attachments/assets/61e30ccb-7651-41a7-a550-c3345de4285d" />

Al continuar con la ejecución de forma normal, veo que intenta tomar el salto siguiente (*3*). Modifico el valor de la Zero Flag (ZF) de 1 a 0 para impedir que ejecutase el salto: 

<img width="559" height="447" alt="imagen" src="https://github.com/user-attachments/assets/2a982f09-9259-4caa-a1f0-7ebcdfa54c22" /><br/>

<img width="199" height="82" alt="imagen" src="https://github.com/user-attachments/assets/9a869c4e-81c1-4dc9-90e3-fac68c2b99ec" />

El siguiente salto (*4*) no intenta tomarlo. Tras llegar a la función `Payload` y hacer Step Over sobre ella, puede verse tráfico SMB que no había detectado antes hacia mi máquina vulnerable:

<img width="718" height="228" alt="imagen" src="https://github.com/user-attachments/assets/93b34aa2-eeef-4e82-9edf-62e86659661b" />

Se mandan las diferentes cadenas alfanuméricas en varios paquetes SMB. En cada paquete la cantidad de datos enviados es muy superior a la esperada, de 4096 bytes. Como puede verse en la siguiente imagen, que muestra el último paquete enviado, al final del string están los símbolos `==`:

<img width="488" height="440" alt="imagen" src="https://github.com/user-attachments/assets/bcb618d3-3add-42ba-b737-2eb8937f19be" />

La presencia de los símbolos `==` hace pensar que se trate de información codificada en base64. Sin embargo, he intentado poner todas las cadenas una tras otra, siguiendo el orden en que son enviadas en un intento para desencriptar el payload enviado, sin éxito. 

Por otro lado, tras el envío de estas cadenas, el malware vuelve a transmitir datos:

<img width="444" height="349" alt="imagen" src="https://github.com/user-attachments/assets/d35124a2-4abb-4ee5-b7fb-fbac922825d2" />

Estos datos no contienen ninguna cadena que pueda tener sentido, más bien parece que sólo manda información en hexadecimal. Como hipótesis personal, podría ser un shellcode:

<img width="541" height="33" alt="imagen" src="https://github.com/user-attachments/assets/dbab7b05-e5f8-4dfd-ba3a-6dd0629d22c2" />

<img width="490" height="305" alt="imagen" src="https://github.com/user-attachments/assets/62a533bc-26f1-434b-b459-a9bbd800ed1a" />

Investigando, descubrí que este tipo de actividad de red está asociada con el uso de DoublePulsar, un backdoor, capaz de inyectar shellcode o ejecutar DLLs en memoria.

DoublePulsar usa una ofuscación XOR no demasiado compleja. Conociendo la fórmula que se usa para ello, la cual es pública, debería ser sencillo obtener el payload enviado. Consigo desencriptarlo usando para ello un archivo PCAP con el tráfico capturado y el siguiente script:

```
https://github.com/WithSecureLabs/doublepulsar-c2-traffic-decryptor/blob/master/decrypt_doublepulsar_traffic.py
```

Adapté sin problema el script de python 2 a python 3 usando ChatGPT.

El archivo generado por el script es un ejecutable PE al que llamé `payload`:

<img width="460" height="234" alt="imagen" src="https://github.com/user-attachments/assets/2a5ebd5e-899c-45dc-9074-23f93414818a" />

Dentro de este ejecutable se halla el recurso W. Debido a su alta entropía, es muy posible que sea otro ejecutable:

<img width="933" height="307" alt="imagen" src="https://github.com/user-attachments/assets/7ee68248-68b4-4642-8655-9777fd819607" />

Dentro del recurso W encuentro a su vez al recurso R, y al recurso XIA dentro de éste último. Por lo cual, el recurso W debería ser la primera fase del malware.

<img width="507" height="466" alt="imagen" src="https://github.com/user-attachments/assets/f137c840-8464-4729-b9d4-bab4b637f0b2" />

La sospecha de que el recurso W fuese la primera fase del malware parecía razonable, pero comparando tanto del hash del archivo `payload` como el del recurso W con el hash de la muestra inicial, se observa que no coinciden:

<img width="748" height="193" alt="61" src="https://github.com/user-attachments/assets/733cf13b-fd12-4dd4-bfff-4110f3682c3f" />

Sin embargo, el hash del recurso R contenido dentro del recurso W sí que coincide con el del archivo tasksche.exe, extraído de la muestra inicial:

<img width="658" height="130" alt="62" src="https://github.com/user-attachments/assets/27a3b6f7-26a8-4c06-bfd2-ed75a53baca6" />

Entonces, el malware consigue propagarse por la red, pero al parecer no transmite su primera fase de forma idéntica, ya que el hash cambia. Lo que sí se puede decir de este nuevo ejecutable obtenido tras la propagación es que sí tiene el mecanismo de kill switch y la capacidad para propagarse por la red. Como puede verse en la siguiente imagen, obtengo los strings del archivo `payload` y figuran tanto el dominio del kill switch como los strings referentes a la comunicación SMB:

<img width="480" height="368" alt="63" src="https://github.com/user-attachments/assets/d9e240eb-d5f3-4eba-86c7-2e34d3668a4a" />

Dichos strings no aparecen en la segunda fase del malware, como puede verse en esta imagen:

<img width="418" height="324" alt="64" src="https://github.com/user-attachments/assets/3004b2fb-54c8-4fd1-9b06-b5b9a3d87fd7" />

Y debido a ello, parece razonable afirmar que este comportamiento del malware pertenece sólo a la primera fase y no a la segunda; y que a pesar de no coincidir los hashes de la muestra inicial y del payload reconstruido a partir del tráfico, las funcionalidades del malware se conservan.

Extrañamente, después de este proceso comprobé la VM vulnerable y observé que había sido infectada:

<img width="865" height="639" alt="59" src="https://github.com/user-attachments/assets/32672a26-eae1-4b0f-a2cc-869633c95955" />

Puede verse la carpeta que crea y que contiene todos los archivos vistos en los indicadores basados en host de la sección de análisis dinámico básico. Sin embargo, el nombre alfanumérico de la carpeta es diferente del observado en la muestra original:

<img width="823" height="624" alt="65" src="https://github.com/user-attachments/assets/a7ff6b1a-9f22-40a8-b281-fb8322dbbbff" />

También puede verse que el hash SHA256 del archivo `tasksche.exe` presente en la máquina infectada es el mismo que el reconstruido a partir del tráfico de red y el mismo también que el obtenido a partir de la muestra inicial:

<img width="646" height="66" alt="66" src="https://github.com/user-attachments/assets/21b09bde-5f00-4e92-9965-b6f41ccccd21" />

Sin embargo, no he podido concretar las condiciones que esta vez han hecho posible la propagación, más allá de la alteración del flujo de ejecución.

Combinando análisis estático y dinámico pude identificar las funciones que llevaban a cabo tanto la explotación de EternalBlue como el envío del malware a la nueva máquina infectada, así como captar todo este tráfico en wireshark y reconstruir el payload enviado.


# Segunda fase del malware


Analizando la muestra con PEStudio puede verse que el recurso R es un ejecutable, el cual es la segunda fase y que tendrá por nombre *tasksche.exe*.

<img width="724" height="75" alt="imagen" src="https://github.com/user-attachments/assets/1e1bd88c-6b93-434b-b34d-949451e3b9ab" />

Usando PEStudio se guardar este ejecutable para su análisis. Inspeccionándolo se puede ver que hay un archivo comprimido PKZIP llamado XIA dentro de él:

<img width="666" height="102" alt="imagen" src="https://github.com/user-attachments/assets/a92b9ebc-cf09-4978-8e06-d147342c4601" />

Extraigo el archivo XIA y le cambio la extensión a .7z para descomprimirlo y comprobar su contenido. Sin embargo, está protegido con contraseña. Teniendo en cuenta que este archivo comprimido estaba dentro de *tasksche.exe*, es altamente probable que la contraseña para descomprimirlo esté dentro de él. Inspeccionando con Cutter figura la contraseña:

<img width="487" height="155" alt="imagen" src="https://github.com/user-attachments/assets/87b6ba0f-02e3-4a62-b29a-cf02cf2a87c2" />

La contraseña es: **WNcry@2ol7**

Algo interesante puede verse también en la imagen:

<img width="477" height="112" alt="imagen" src="https://github.com/user-attachments/assets/5c724bc1-6ace-4f20-856c-bbf834807ea6" />

Estos comandos son acciones posteriores que el malware ejecuta en el sistema una vez ya ha extraído el contenido. Ambos son comandos legítimos de Windows, usados aquí con fines maliciosos:

 1. `attrib +h .`

	- `attrib` es un comando de Windows que sirve para cambiar atributos de archivos o carpetas
	- `+h` significa “añadir el atributo oculto” (hidden)
	- `.` hace referencia al directorio actual

Este comando oculta la carpeta actual donde se ha descomprimido el contenido del malware, para evitar que el usuario pueda ver los archivos o que los componentes del malware sean fácilmente detectables.

 2. `icacls . /grant Everyone:F /T /C /Q`

	- `icacls` gestiona permisos en Windows
	- `.`  hace referencia al directorio actual
	- `/grant Everyone:F`  concede permisos de control total (“Full”) al grupo “Everyone” (todos los usuarios)
	- `/T`  aplica recursivamente a todos los archivos y subcarpetas
	- `/C`  continúa aunque haya errores
	- `/Q`  modo silencioso

Cambia los permisos de toda la carpeta y su contenido para que cualquier usuario (y proceso) tenga control total y pueda actuar sin restricciones.

Dentro del archivo comprimido pueden encontrarse los siguientes archivos:

<img width="631" height="246" alt="imagen" src="https://github.com/user-attachments/assets/f37d241c-74fc-46ef-8b56-e9012ea6c9df" />

Se puede ver qué es cada archivo usando la herramienta detect-it-easy y luego cambiando la extensión cuando sea necesario:
- **Carpeta msg**: contiene archivos .rtf con la extensión .wnry, los cuales tienen, en diferentes idiomas, una nota explicativa de la situación y de los pasos a seguir para realizar el pago. Estas notas serán usadas por el programa *Wana Decrypt0r 2.0*:

<img width="337" height="236" alt="imagen" src="https://github.com/user-attachments/assets/40cf334a-502e-4299-9d7d-ff31d880e26e" />

<img width="569" height="243" alt="imagen" src="https://github.com/user-attachments/assets/d58f3a54-8f35-46e8-904e-40bcb90ce42c" />

Puede verse el mensaje en ruso, por ejemplo.

- **b.wnry**: fondo de pantalla que queda tras la ejecución con instrucciones para el usuario.

<img width="779" height="534" alt="imagen" src="https://github.com/user-attachments/assets/a50111fc-7ce5-44e6-a1af-25a75545bc35" />

- **c.wnry**: lista de direcciones .onion, puede que para realizar el pago o bien para funciones de command and control, aunque no he verificado su posible uso. También hay un link para descargar el navegador Tor, probablemente en caso de que no estuviera presente en el sistema:

<img width="555" height="404" alt="imagen" src="https://github.com/user-attachments/assets/ba22a8df-985b-43c6-b506-67a9c720d1b2" />

<img width="671" height="172" alt="imagen" src="https://github.com/user-attachments/assets/ddd29c74-4401-4f5c-bee2-6e8f04c563e9" />

- **r.wnry**: archivo de texto con mensaje para el usuario explicándole que ha sido víctima de un ransomware y debe pagar.
- **s.wnry**: carpeta comprimida en la que figuran varios archivos .dll relacionados con Tor.

<img width="201" height="272" alt="imagen" src="https://github.com/user-attachments/assets/331b181e-5cb1-4b7f-b490-aedc3bc29649" />

- **t.wnry**: se hace complicado saber para qué se usa este archivo, ya que el magic number de este archivo no es de los comunes, sino `WANACRY!`:

<img width="645" height="265" alt="imagen" src="https://github.com/user-attachments/assets/fedf4293-011e-4843-83eb-ec360204a9e1" />

Reemplazando el magic number por `MZ`, no se observa nueva información. No tengo claro para qué sirve este archivo, haría falta investigar más.

- **taskdl.exe**: este ejecutable cuenta con las siguientes imports sospechosas:
	- **FindFirstFileW**
	- **FindNextFileW**
	- **DeleteFileW**

Las dos primeras se usan para buscar en directorio y la tercera para el borrado de archivos, por lo cual es lícito pensar que el uso de este ejecutable es el de borrar archivos, posiblemente los archivos del usuario tras su encriptación.

- **taskse.exe**: analizando este ejecutable en PEstudio o bien mirando sus strings, no se aprecia nada sospechoso. Mediante el análisis dinámico sí he podido figurarme cómo encaja en el gran esquema de las cosas, y pudiendo tener más funciones, se ve que está relacionado con el programa `@WanaDecryptor@.exe`. Este programa muestra una ventana al término de la ejecución del malware. Si se cierra esta ventana, el proceso activo `tasksche.exe` ejecuta  `taskse.exe` y este a su vez vuelve a ejecutar `@WanaDecryptor@.exe`. Esto ocurre aproximadamente cada 30 segundos, convirtiéndose en algo bastante molesto, a menos que se cierre el proceso principal `@WanaDecryptor@.exe` y el proceso  `tasksche.exe`, que es quien llama a `taskse.exe` cada vez. 

<img width="244" height="79" alt="imagen" src="https://github.com/user-attachments/assets/9bcba2c4-7fb3-46eb-b9bf-3367d0ac6ba9" /><br/>

<img width="245" height="97" alt="imagen" src="https://github.com/user-attachments/assets/d14c8157-bf6e-425b-91c0-a08149118f88" />

Teniendo en cuenta que `taskse.exe` se abre sólo cuando hace falta invocar a `@WanaDecryptor@.exe` de nuevo y luego se cierra, diría que `tasksche.exe` monitoriza la lista de procesos activos, y si no figura `@WanaDecryptor@.exe`, es cuando ejecuta `taskse.exe`. Pero esto es sólo una suposición por mi parte.

- **u.wnry**: ejecutable de **@WanaDecryptor@.exe**:

<img width="811" height="614" alt="imagen" src="https://github.com/user-attachments/assets/cd9a7c09-e309-4ab1-8881-1d62411cacf4" />


# Regla YARA


Basándome en la mayoría de indicadores recopilados durante el análisis, se puede escribir una regla YARA para este malware. Sin embargo, esta regla la he creado sólo con la primera fase del malware en mente, y por ello no todos los indicadores valen, ya que algunos de ellos se encuentran en el archivo comprimido. Por ejemplo, las url .onion nunca van a saltar con esta muestra y por lo tanto no las incluyo. 

```
rule YaraCry {
    
    meta: 
        last_updated = "2026"
        author = "Me"
        description = "Rule YARA WannaCry First Stage"

    strings:
        // Fill out identifying strings and other criteria
        $string1 = ".wnry"                  ascii
        $string2 = "tasksche.exe"           ascii
        $string3 = "WNcry@2ol7"             ascii
        $string4 = "taskdl.exe"             ascii
        $string5 = "taskse.exe"             ascii

        $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii

        $magic_number = "MZ"                ascii


    condition:
        // Fill out the conditions that must be met to identify the binary
        $magic_number at 0 and ($killswitch or 1 of ($string*))
```



# Splunk


Ya que esto no es un análisis formal sino la conclusión de un curso, puedo permitirme explorar otros caminos relacionados. Splunk es una de las principales herramientas SIEM del mercado, y ya que permite recopilar, analizar y correlacionar datos de red y sistemas en tiempo real, resulta interesante ver qué resultados nos ofrece al ejecutar la muestra en el laboratorio. He analizado la telemetría del equipo mediante la app "Sysmon app for Splunk" y los logs generados por Sysmon. 

Desafortunadamente, no se recopilan datos de todos los eventos conocidos, como la creación de los archivos encriptados u otros. Esto puede deberse al cifrado de los datos, lo cual impide que sean enviados, o a la falta de recursos asignados a la VM del servidor Splunk, lo que puede provocar problemas de ingesta de datos, al menos en mi experiencia. Sin embargo, sigue siendo una forma útil de listar eventos automáticamente de forma preliminar.


## Sysmon app para Splunk


Para usarla, hay que instalar sysmon en la VM objetivo (he usado el archivo de configuración de **SwiftOnSecurity**) y mandar el log que genera con los eventos de interés a Splunk mediante un agente ligero llamado forwarder. Una vez enviados los datos, se podrán visualizar en diferentes dashboards. 

<img width="1630" height="578" alt="imagen" src="https://github.com/user-attachments/assets/8453fa2a-83c5-4809-bef1-aa0eef98e518" />

Estos dashboards también permiten inspeccionar eventos concretos. Por ejemplo, se puede observar directamente la petición DNS asociada al kill switch de WannaCry:

<img width="493" height="331" alt="imagen" src="https://github.com/user-attachments/assets/87e23f1e-6a74-44ed-bae3-0d86b1d836e4" />

O incluso se pueden ver otros comportamientos no percibidos hasta ahora en el análisis, como la alteración de la fecha de creación de los archivos  `taskse.exe`, `tasksdl.exe` y  `tor.exe` por parte de la segunda fase del malware,  `tasksche.exe`. En la foto, la modificación de `taskse.exe`:

<img width="494" height="466" alt="imagen" src="https://github.com/user-attachments/assets/964d4242-56ac-4e54-90fb-fce1deba6d6e" />

Otra sección que puede verse es la de operaciones a nivel de registro de Windows. Aquí encuentro el registro creado para ejecutar *tasksche.exe* al inicio, que ya comentado en la parte de indicadores basados en host. Además, puede observarse otro servicio nuevo:

<img width="489" height="140" alt="imagen" src="https://github.com/user-attachments/assets/cb2f7b9e-a253-4307-9457-2e5ec27ed920" />

El servicio mssecsvc2.0, que no había identificado previamente, también es creado por WannaCry. Está configurado para ejecutar la primera fase del malware al inicio del sistema:

<img width="550" height="215" alt="imagen" src="https://github.com/user-attachments/assets/d2a6fa60-94f9-407a-95d5-bc71a9655949" />

Start indica el tipo de arranque del servicio, mientras que el valor 2 indica que el servicio se iniciará automáticamente al arrancar Windows.

<img width="583" height="305" alt="imagen" src="https://github.com/user-attachments/assets/0933b160-849f-4bd8-b357-1099a0f25250" />

Como se ve, ejecuta al inicio el archivo original del malware, por lo que este servicio es otro mecanismo más de persistencia.

Este hallazgo resulta especialmente interesante porque no había sido identificado durante las fases anteriores del análisis y demuestra el valor de correlacionar la telemetría obtenida mediante diferentes herramientas.

En conjunto, el uso de Splunk y Sysmon proporcionó una perspectiva adicional sobre el comportamiento del malware. Aunque la telemetría recopilada no fue completa, permitió confirmar indicadores identificados anteriormente, como la petición DNS del kill switch y los mecanismos de persistencia, además de revelar actividad adicional que no había sido detectada durante los análisis estático y dinámico iniciales.
