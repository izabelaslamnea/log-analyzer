# Security Log Analyzer

## Descripción

Security Log Analyzer es una herramienta desarrollada en Python para analizar registros de acceso e identificar patrones de actividad potencialmente sospechosos.

El programa procesa eventos de inicio de sesión, analiza las direcciones IP y detecta posibles ataques de fuerza bruta y accesos precedidos por múltiples intentos fallidos.

## Funcionalidades

- Análisis automático de registros de acceso.
- Identificación de inicios de sesión exitosos y fallidos.
- Agrupación de eventos por dirección IP.
- Detección de posibles ataques de fuerza bruta.
- Detección de accesos exitosos después de múltiples fallos.
- Clasificación de alertas según el nivel de riesgo.
- Validación de registros y detección de líneas inválidas.
- Exportación de alertas a informes CSV.
- Registro de fecha y hora de las alertas.

## Tecnologías utilizadas

- Python 3
- `collections`
- `datetime`
- `csv`

## Requisitos

- Python 3 instalado.
- No requiere bibliotecas externas.

## Estructura del proyecto

```text
03_Analizador_Logs/
│
├── log_analyzer.py
├── access.log
├── security_report.csv
└── README.md
```

## Ejecución

Ejecutar desde la terminal:

```bash
python log_analyzer.py
```

El archivo `access.log` debe encontrarse en la misma carpeta que el programa.

Al finalizar, se genera automáticamente `security_report.csv`.

## Detección de actividad sospechosa

### Riesgo alto: posible fuerza bruta

Se genera una alerta cuando una dirección IP registra cinco o más intentos fallidos dentro de un intervalo de dos minutos.

### Riesgo medio: fallos seguidos de acceso correcto

Se genera una alerta cuando una dirección IP acumula tres o más intentos fallidos durante los diez minutos anteriores a un inicio de sesión exitoso.

## Ejemplo de resultados

```text
[ALTO] 192.168.1.20
Tipo: Posible fuerza bruta
Detalle: 5 intentos fallidos en 2 minutos

[MEDIO] 192.168.1.30
Tipo: Fallos seguidos de acceso correcto
Detalle: 3 fallos antes del acceso correcto
```

## Objetivo del proyecto

Desarrollar habilidades prácticas en Python y aprender fundamentos de análisis de registros, monitorización de eventos y detección de patrones potencialmente sospechosos.

## Consideraciones de seguridad

Este proyecto tiene fines educativos y utiliza registros ficticios. Las alertas representan indicadores que deben investigarse y no demuestran por sí solas la existencia de un ataque.

## Autoría

Proyecto personal de aprendizaje de ciberseguridad desarrollado en Python.
