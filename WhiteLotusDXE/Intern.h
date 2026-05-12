#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/DevicePathLib.h>

UINT32
EFIAPI
InternalSyncCompareExchange32 (
  IN      volatile UINT32  *Value,
  IN      UINT32           CompareValue,
  IN      UINT32           ExchangeValue
  );

UINT32
EFIAPI
InterlockedCompareExchange32 (
  IN OUT  volatile UINT32  *Value,
  IN      UINT32           CompareValue,
  IN      UINT32           ExchangeValue
  );

UINT64
EFIAPI
InternalSyncCompareExchange64 (
  IN      volatile UINT64  *Value,
  IN      UINT64           CompareValue,
  IN      UINT64           ExchangeValue
  );

UINT64
EFIAPI
InterlockedCompareExchange64 (
  IN OUT  volatile UINT64  *Value,
  IN      UINT64           CompareValue,
  IN      UINT64           ExchangeValue
  );

VOID *
EFIAPI
InterlockedCompareExchangePointer (
  IN OUT  VOID                      *volatile  *Value,
  IN      VOID                                 *CompareValue,
  IN      VOID                                 *ExchangeValue
  );
