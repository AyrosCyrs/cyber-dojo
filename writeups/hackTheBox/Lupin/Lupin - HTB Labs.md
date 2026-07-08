---
tags:
  - HTB
  - MalwareAnalysis
  - ReverseEngineering
  - BlueTeam
Fecha: 2026-03-19
Author: "@AyrosCyrs"
---
# HTB Labs - Lupin: Análisis Forense de un Clipper Phorpiex

## Introducción
Lupin es una máquina de categoría **Blue Team** que nos permite analizar el comportamiento de un binario malicioso en Windows. A través de este laboratorio, exploraremos técnicas de persistencia, evasión por región y la lógica detrás de un *cryptocurrency clipper*.

## Paso 1. Triage y Análisis Estático Inicial
Al recibir la muestra, procedemos con un reconocimiento básico para identificar la arquitectura y posibles capas de protección (empaquetado).

![Comandos iniciales de reconocimiento en terminal Kali Linux](images/0.png)
*Evidencia 1: Comandos iniciales de reconocimiento en terminal Kali Linux.*

```shell
┌──(ayroscyrs㉿ayroscyrs)-[~/CTFs/Lupin/Lupin]
└─$ file optimize.exe
optimize.exe: PE32 executable for MS Windows 5.00 (GUI), Intel i386, 3 sections

┌──(ayroscyrs㉿ayroscyrs)-[~/CTFs/Lupin/Lupin]
└─$ upx -t optimize.exe
upx: optimize.exe: NotPackedException: not packed by UPX

┌──(ayroscyrs㉿ayroscyrs)-[~/CTFs/Lupin/Lupin]
└─$ md5sum optimize.exe
f30fdbf3448f67cbc3566f31729cb7a6  optimize.exe
```

> **Nota técnica**
> El comando `file` nos confirma que es un **PE32 (Portable Executable)** para Windows de 32 bits. Esto es vital porque define nuestro entorno de análisis: en Ghidra debemos utilizar el lenguaje `x86:LE:32`. Además, la verificación con `upx -t` nos asegura que el código es legible directamente sin necesidad de realizar un unpacking previo.

### Enriquecimiento con OSINT (VirusTotal)
Utilizamos el hash MD5 `f30fdbf3448f67cbc3566f31729cb7a6` para consultar antecedentes en VirusTotal.

![Resultado de la muestra en VirusTotal](images/1.png)
_Evidencia 2: Resultado de la muestra en VirusTotal._

El reporte identifica el binario como un **clipper** sofisticado con capacidades de gusano (worm). Destaca los siguientes indicadores de compromiso (IoC):
- **Persistencia:** Replicación en `%windir%` con un nombre de archivo que imita procesos legítimos del sistema.
- **Capacidad:** Monitoreo del portapapeles para el robo de billeteras (BTC, ETH, etc.).
- **Propagación:** Infección de unidades extraíbles mediante accesos directos maliciosos (`.lnk`).

## Paso 2. Resolución de Tasks

### Task 1. Entropía del ejecutable
La entropía de Shannon nos permite medir el grado de aleatoriedad en los datos del binario. En seguridad, valores altos suelen indicar cifrado o compresión.

Para obtener este valor, utilizamos la herramienta `ent`:

![Usamos la herramienta ent para calcular la entropía](images/2.png)
_Evidencia 3: Usamos la herramienta ent para calcular la entropia_

```shell
┌──(ayroscyrs㉿ayroscyrs)-[~/CTFs/Lupin/Lupin]
└─$ ent optimize.exe 
Entropy = 6.414480 bits per byte.
```

> **Análisis de resultados**
> La entropía obtenida indica que el binario contiene secciones de datos densas (como las listas de carteras atacantes o el módulo de propagación), pero no está cifrado en su totalidad.

### Task 2. Nombre de archivo usado al replicarse
A partir del análisis dinámico y el reporte de VirusTotal, identificamos que el malware busca asegurar su supervivencia en el sistema víctima replicándose en directorios críticos con un nombre de archivo que simula un proceso legítimo de Windows.

![Leyendo el reporte de VirusTotal](images/3.png)
_Evidencia 4: Leyendo el reporte_

### Task 3. API usada para restricción de ejecución por región
Para resolver esta tarea, iniciamos utilizando **Ghidra**. El objetivo es identificar funciones que permitan al malware obtener información sobre la ubicación geográfica o el idioma del sistema infectado.

#### Metodología de búsqueda en Ghidra:
1. **Navegación por Símbolos:** En el panel **Symbol Tree** (ubicado a la izquierda), expandimos la sección de **Imports**. Aquí es donde el binario declara qué funciones externas necesita del Sistema Operativo para funcionar.
2. **Filtrado en KERNEL32.DLL:** La mayoría de las funciones de gestión de sistema y lenguaje residen en esta librería.
3. **Uso de Palabras Clave:**
	- Iniciamos buscando la cadena `Lang` (buscando funciones como `GetSystemDefaultLangID`), técnica común en malwares rusos para evitar sistemas locales.
	- Al no encontrar coincidencias directas, ampliamos la búsqueda a `Locale`. Esto nos permite localizar funciones que extraen información más detallada del entorno regional.

![Localización de la API de locale en la tabla de importaciones de KERNEL32.DLL](images/4.png)
_Evidencia 5: Localización de la API de locale en la tabla de importaciones de KERNEL32.DLL._

> **Análisis Técnico de la API**
> La API identificada es utilizada por el malware para recuperar información sobre un locale (localidad) específico, como el nombre del país o el código de lenguaje.
>
> En este binario, observamos que tras llamar a esta API, el malware realiza una comparación lógica. Si el resultado coincide con regiones de la **CEI (Comunidad de Estados Independientes)**, el malware detiene su ejecución inmediatamente. Esta es una técnica de **evasión regional** diseñada para evitar el escrutinio de las autoridades en los países de origen de los atacantes.

### Task 4. API usada para limpiar la caché del navegador
#### Metodología de análisis:
1. **Salto a Dirección Específica:** En Ghidra, utilizamos el atajo de teclado `G` (Go to) para dirigirnos directamente a la dirección relativa donde ocurre la lógica de red.
2. **Análisis del Decompiler:** Al observar el flujo del programa en esta dirección, identificamos un bucle `do-while` (persistente) que orquesta las peticiones de red.
3. **Identificación de la API:** Justo antes de la lógica de descarga, localizamos la llamada a una API de la librería `WININET.dll`.

![Identificación de la función dentro del bucle de comunicación](images/5.png)
_Evidencia 6: Identificación de la función dentro del bucle de comunicación._

> **Análisis de Evasión de Caché**
> El malware pasa como argumento la URL del C2 construida dinámicamente mediante `wsprintfA`.
>
> Esta técnica asegura que cada petición al servidor sea reciente. Al eliminar la entrada de caché antes de cada intento, el atacante garantiza que el malware reciba los comandos o carteras de criptomonedas más actualizados, evadiendo cualquier optimización de red del sistema operativo que pudiera servir una copia obsoleta.

### Task 5. Función responsable del comportamiento anómalo al pegar
El comportamiento inusual descrito (donde el contenido del portapapeles cambia al momento de pegar) es la característica principal de un **Clipper**. Para identificar la función responsable, debemos rastrear qué parte del código interactúa con las APIs del portapapeles de Windows.

#### Metodología de análisis:
1. **Rastreo de APIs de Usuario:** En el panel **Symbol Tree**, navegamos a `USER32.dll` e identificamos funciones clave como `OpenClipboard`, `GetClipboardData` y `SetClipboardData`.
2. **Análisis de Referencias Cruzadas (XREFs):** Realizamos un "Show References to" sobre estas APIs para localizar qué funciones de usuario las invocan.
3. **Localización de la Función Orquestadora:** El rastreo nos dirige a una dirección donde el binario no solo abre el portapapeles, sino que implementa lógica de comparación.

![Identificación de la función principal del Clipper](images/6.png)
_Evidencia 7: Identificación de la función principal del Clipper mediante el rastreo de `OpenClipboard`._

> **Análisis de la Lógica del Clipper**
> Al analizar la función identificada, observamos que el malware utiliza `OpenClipboard` de manera recurrente dentro de una estructura condicional.
>
> Esta función es la "unidad de inteligencia" del malware: se encarga de extraer el texto que la víctima copia, verificar mediante patrones si se trata de una dirección de criptomonedas y, en caso positivo, disparar la rutina de reemplazo.

### Task 6. Mensaje de Windows que dispara el monitoreo del portapapeles
Para que el malware actúe de forma eficiente, no puede estar revisando el portapapeles al azar; debe ser "notificado" por el sistema operativo cuando ocurra un cambio. En la arquitectura de Windows, esto se logra mediante el manejo de **Mensajes de Ventana**.

#### Metodología de análisis:
1. **Identificación de Constantes:** Al analizar la función de monitoreo, observamos en el Decompiler una comparación crítica contra un valor hexadecimal.
2. **Búsqueda de Escalares:** Para entender el contexto de este valor, utilizamos la herramienta **Search -> Scalar** en Ghidra.
3. **Interpretación de la API de Windows:** Consultando la documentación oficial de Microsoft (MSDN) y los encabezados de desarrollo (`WinUser.h`), identificamos a qué constante predefinida corresponde ese valor.

![Localización del valor hexadecimal en la lógica de decisión del malware](images/7.png)
_Evidencia 8: Localización del valor hexadecimal en la lógica de decisión del malware._

> **¿De dónde proviene este valor?**
> En la programación de Windows (WinAPI), los mensajes del sistema no se envían como texto, sino como **constantes numéricas** definidas en los archivos de encabezado del SDK de Windows (como `WinUser.h`). Por esta razón, en herramientas de ingeniería inversa como Ghidra, siempre buscaremos el valor numérico bruto para identificar eventos del sistema.

> **Mecanismo de Disparo (Trigger)**
> El malware se registra previamente como un "Clipboard Viewer" mediante la API `SetClipboardViewer`. A partir de ese momento, Windows envía un mensaje a la ventana del malware cada vez que el contenido del portapapeles cambia, lo que permite al atacante actuar en tiempo real justo cuando la víctima realiza una operación de copiado.

### Task 7. Función que modifica el contenido del portapapeles
Una vez que el malware ha sido "despertado" por el mensaje del sistema y ha confirmado que el contenido del portapapeles es una billetera de criptomonedas, debe ejecutar la acción final: el reemplazo de los datos. Para encontrar esta función, rastreamos la API encargada de escribir información en el portapapeles.

#### Metodología de análisis:
1. **Localización de la API de Escritura:** En el panel **Symbol Tree**, dentro de `USER32.dll` seleccionamos la función **`SetClipboardData`**. Esta es la función legítima de Windows que se usa para colocar datos en el portapapeles.
2. **Rastreo de Invocación (XREFs):** Realizamos un "Show References to", buscamos qué parte del código del binario la está llamando para realizar cambios no autorizados.
3. **Identificación del Punto de Inyección:** El rastreo nos lleva directamente a una función específica que gestiona el flujo: Abrir portapapeles -> Vaciar contenido -> **Inyectar wallet del atacante** -> Cerrar portapapeles.

![Referencias cruzadas de SetClipboardData apuntando a la función de reemplazo](images/8.png)
_Evidencia 9: Referencias cruzadas (XREFs) de `SetClipboardData` apuntando a la función de reemplazo._

> **Análisis del Reemplazo (Clipper Action)**
> La función identificada es el componente ejecutor del Clipper: tiene el control directo sobre `SetClipboardData`.
>
> A diferencia de la función de monitoreo, esta sección del código es la responsable de la modificación física de los datos. Aquí es donde el malware toma una dirección de billetera "hardcoded" (grabada en su código) y la sustituye por la que la víctima pretendía usar, consumando así el robo de los fondos en la siguiente operación de pegado.

### Task 8. Rastreo de la billetera del atacante en la blockchain
#### Metodología de investigación OSINT:
1. **Resolución de Dominio ENS:** Utilizamos **Etherscan.io** para buscar el dominio ENS vinculado al caso. Los dominios ENS funcionan como "apodos" legibles para direcciones hexadecimales complejas de Ethereum.
2. **Identificación de la Dirección de la Billetera:** Al buscar el dominio, localizamos la dirección resuelta correspondiente.
3. **Auditoría de Transacciones:** Analizamos el historial de la billetera para identificar la actividad operativa más reciente del usuario.

![Resolución del dominio ENS y obtención de la dirección de la billetera vinculada](images/9.png)
_Evidencia 10.1: Resolución del dominio ENS y obtención de la dirección de la billetera vinculada._

#### Análisis de la Blockchain:
Al explorar la pestaña de transacciones, observamos diversas interacciones. Para los propósitos de este laboratorio, la "última operación" se refiere a la transacción de transferencia más reciente documentada en la captura de actividad.

![Historial de transacciones salientes desde la cuenta vinculada](images/10.png)
_Evidencia 10.2: Historial de transacciones salientes (OUT) desde la cuenta vinculada._

> **Nota sobre On-chain Analysis**
> El Hash de Transacción (TxHash) es el identificador único de una operación en la blockchain. Identificar el hash correcto nos permite ver a qué otras billeteras se está enviando el dinero robado por el Clipper, lo que facilita el rastreo de la infraestructura de lavado de criptoactivos del atacante.

### Task 9. Dirección multicast usada por las sondas SSDP
El binario de Lupin no solo se limita al robo de criptoactivos; también posee capacidades de **movimiento lateral**. Para lograr esto, utiliza el protocolo **SSDP** (Simple Service Discovery Protocol), el cual permite descubrir dispositivos en la red local de manera automática.

#### Metodología de análisis en Ghidra:
1. **Exploración de Cadenas Definidas:** En el menú superior de Ghidra, navegamos a `Window -> Defined Strings`. Esta ventana es fundamental para identificar indicadores de compromiso (IoCs) de red que el desarrollador haya dejado "hardcoded" en el binario.
2. **Filtrado por Protocolo:** Utilizamos el filtro inferior para buscar términos asociados a servicios de red. Al filtrar por `M-SEARCH` (el comando de búsqueda estándar de SSDP), localizamos las estructuras de datos que el malware enviará a través de la red.
3. **Identificación de la Dirección Multicast:** Entre los resultados, destaca la presencia de una dirección IP específica que no pertenece a un servidor C2 convencional, sino a un rango de difusión.

![Localización de la IP Multicast y el encabezado M-SEARCH](images/11.png)
_Evidencia 11: Localización de la IP Multicast y el encabezado M-SEARCH mediante la ventana Defined Strings._

> **Análisis Técnico: ¿Qué es esta IP?**
> En el ámbito de redes, existe una dirección de **Multicast administrativa local** reservada mundialmente para SSDP.
>
> Cuando el malware envía un paquete a esta IP, no está contactando a un solo equipo, sino que está contactando a todos los dispositivos de la red local (como routers, cámaras inteligentes o impresoras) para que estos respondan revelando su ubicación y servicios disponibles. Esta es la fase de reconocimiento de la botnet para intentar propagarse.

### Task 10. Puerto UDP usado para las solicitudes M-SEARCH
Tras identificar la dirección Multicast, el siguiente paso es determinar el puerto de comunicación que el malware utiliza para realizar sus peticiones de descubrimiento. En el análisis de tráfico de red, el puerto define el servicio específico al que se intenta contactar.

#### Metodología de análisis en Ghidra:
1. **Inspección Detallada de Cadenas:** En la ventana de **Listing**, nos posicionamos sobre la cadena de datos asociada al comando `M-SEARCH` y la IP Multicast previamente identificada.
2. **Visualización del Payload:** Al pasar el cursor sobre el identificador de la cadena, Ghidra despliega una vista previa del contenido completo del mensaje que será enviado a través del _socket_ de red.
3. **Identificación del Puerto:** Dentro de la cabecera `HOST`, observamos la estructura clásica de `IP:PUERTO`.

![Visualización del payload M-SEARCH revelando el puerto de destino](images/12.jpg)
_Evidencia 12: Visualización del payload M-SEARCH revelando el puerto de destino._

> **Análisis del Protocolo UPnP**
> El puerto identificado en el paquete de red es el estándar para el protocolo **UPnP** (Universal Plug and Play).
>
> El malware Lupin (Phorpiex) utiliza este puerto para intentar realizar un "relevo de puertos" (Port Mapping) en el router de la víctima. Esto le permite abrir brechas en el firewall local para permitir conexiones entrantes desde el servidor C2 o para convertir la máquina infectada en un nodo de propagación hacia el exterior, facilitando así el control remoto de la botnet.

### Task 11. Familia de malware asociada
Tras un análisis exhaustivo que abarcó desde la entropía del binario hasta el desensamblado de sus módulos de red y monitoreo, procedemos a realizar la clasificación final de la amenaza. La combinación de capacidades de **Clipper** (robo de billeteras) y **Worm** (propagación por SSDP/LNK) es característica de una botnet de larga trayectoria.

#### Metodología de Clasificación:
1. **Correlación de Hallazgos:**
	* El uso de la API de locale para evasión regional.
    - El monitoreo del portapapeles mediante el mensaje de Windows correspondiente.
    - El descubrimiento de red vía SSDP en el puerto UPnP.
2. **Validación con Inteligencia de Amenazas (OSINT):** Consultamos nuevamente los motores de detección para verificar las etiquetas de familia asignadas por la comunidad de ciberseguridad.

![Clasificación de la muestra en VirusTotal](images/13.png)
_Evidencia 13: Clasificación de la muestra en VirusTotal._

> **Conclusión del Análisis: La Botnet Phorpiex**
> Los indicadores técnicos (IoCs) y el comportamiento observado coinciden plenamente con la familia de malware **Phorpiex** (también conocida como Trik).
>
> Esta botnet es conocida por su arquitectura modular: funciona como un **Clipper** para generar ganancias directas, un **Worm** para infectar dispositivos USB y redes locales, y un **Downloader** capaz de desplegar otras amenazas como Ransomware. La presencia de etiquetas de esta familia en el reporte de VirusTotal confirma nuestra hipótesis inicial, cerrando así el ciclo de análisis forense del laboratorio.