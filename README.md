# NtdllHookScanner

Herramienta para detectar hooks en funciones sensibles de `ntdll.dll` dentro de procesos en ejecución en sistemas Windows.

## Funciones monitoreadas

- `NtOpenProcess`
- `NtReadVirtualMemory`
- `NtWriteVirtualMemory`
- `NtCreateThreadEx`
- `NtQuerySystemInformation`
- `NtAllocateVirtualMemory`

## Características

- Escaneo de uno o varios procesos específicos o todos los procesos en ejecución.
- Comparación de stubs con versiones limpias de `ntdll.dll`.
- Múltiples niveles de verbosidad para la salida:
  - **summary** (por defecto): Solo indica si una función está hookeada o limpia.
  - **stub32**: Muestra las instrucciones desensambladas de los primeros 32 bytes.
  - **stub64**: Muestra 64 bytes del stub con desensamblado completo.
- Exportación de resultados en formato JSON.

## Uso

```bash
NtHookScanner.exe [process.exe | all] [--verbosity summary|stub32|stub64] [--jsonfile output.json]
```

## Ejemplos
- Escanear todos los procesos:
```bash
NtHookScanner.exe all
```

- Escanear notepad.exe y calc.exe, con salida JSON:
```bash
NtHookScanner.exe notepad.exe calc.exe --jsonfile hooks.json
```

- Escanear explorer.exe con nivel de verbosidad 32:
```bash
NtHookScanner.exe explorer.exe --verbosity stub32
```

## Compilación
Este proyecto se puede compilar con Visual Studio (x64). Requisitos:
- Windows SDK
- Biblioteca Capstone (https://www.capstone-engine.org/)

Agrega Capstone como dependencia estática o vincúlalo dinámicamente según tus preferencias.

## Requisitos
- Windows 10/11 (x64)
- Privilegios de administrador para escanear procesos protegidos

## Créditos
Desarrollado con fines de análisis forense y detección de técnicas de hooking por inyección de código en entornos Windows.
