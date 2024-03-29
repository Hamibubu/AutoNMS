# AutoNMS

Este proyecto de automatización de redes está diseñado para administrar y realizar tareas comunes en dispositivos de red. Utiliza las siguientes bibliotecas de Python:

- `netmiko` para la automatización de dispositivos de red.
- Otras bibliotecas estándar de Python como `re`, `csv`, `os`, `json`, `threading`, `logging`, `socket` y `docx`.

## Funcionalidades

El proyecto incluye las siguientes funcionalidades:

1. **Gestión de dispositivos**: Permite cargar y administrar la lista de dispositivos de red.

2. **IP Address Management (IPAM)**: Puede mostrar y guardar información sobre las interfaces IP de los dispositivos.

3. **Configuración Manager**: Permite enviar configuraciones a dispositivos específicos o a todos los dispositivos.

4. **Syslog**: Escucha y registra mensajes syslog de dispositivos de red.

5. **Compliance Security**: Realiza comprobaciones de seguridad en los dispositivos.

6. **Generación de Informes**: Genera informes en formato Word con información de los dispositivos.

## Uso

1. Asegúrate de tener todas las bibliotecas necesarias instaladas. Puedes instalarlas ejecutando `pip install -r requirements.txt`.

2. Ejecuta el programa principal `AutoNMS.py`.

3. Selecciona la opción que desees del menú principal para acceder a las diferentes funcionalidades.

## Contribuir

Si deseas contribuir a este proyecto, ¡no dudes en hacerlo! Puedes realizar mejoras, corregir errores o agregar nuevas funcionalidades. Abre un problema o envía una solicitud de extracción.

## Instalación

Siga estos pasos para configurar y ejecutar el proyecto en su entorno local:

1. **Clonar el Repositorio**:

    Clone este repositorio en su máquina local utilizando el siguiente comando de git:

    ```
    git clone https://github.com/Hamibubu/AutoNMS.git
    ```

2. **Instalar Dependencias**:

    Asegúrese de que esté en el directorio raíz del proyecto y ejecute el siguiente comando para instalar las dependencias desde el archivo `requirements.txt`:

    ```
    pip install -r requirements.txt
    ```

3. **Ejecutar el Proyecto**:

    Una vez que todas las dependencias estén instaladas, puede ejecutar el proyecto principal utilizando el siguiente comando:

    ```
    python AutoNMS.py
    ```

4. **Utilizar el Proyecto**:

    El proyecto mostrará un menú principal con varias opciones. Seleccione la opción que desee para utilizar las diferentes funcionalidades del proyecto.
