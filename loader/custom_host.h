/**
  Definiciones del Custom CLR Host para el entorno de Donut
*/

#ifndef CUSTOM_HOST_H
#define CUSTOM_HOST_H

#include "loader.h" 

#define CUSTOM_ASSEMBLY_ID      50000
#define DUMMY_MEMORY_LOAD       30
#define DUMMY_AVAILABLE_BYTES   (100 * 1024 * 1024) // 100 MB

MyHostControl* SetupPICCustomHost(PDONUT_INSTANCE inst, TargetAssembly* targetAssm);

#endif