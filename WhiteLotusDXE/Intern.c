#include "WhiteLotus.h"

UINT32
EFIAPI
InternalSyncCompareExchange32 (
  IN      volatile UINT32  *Value,
  IN      UINT32           CompareValue,
  IN      UINT32           ExchangeValue
  )
{
  return *Value != CompareValue ? *Value :
         ((*Value = ExchangeValue), CompareValue);
}

UINT32
EFIAPI
InterlockedCompareExchange32 (
  IN OUT  volatile UINT32  *Value,
  IN      UINT32           CompareValue,
  IN      UINT32           ExchangeValue
  )
{
  ASSERT (Value != NULL);
  return InternalSyncCompareExchange32 (Value, CompareValue, ExchangeValue);
}

UINT64
EFIAPI
InternalSyncCompareExchange64 (
  IN      volatile UINT64  *Value,
  IN      UINT64           CompareValue,
  IN      UINT64           ExchangeValue
  )
{
  return *Value != CompareValue ? *Value :
         ((*Value = ExchangeValue), CompareValue);
}

UINT64
EFIAPI
InterlockedCompareExchange64 (
  IN OUT  volatile UINT64  *Value,
  IN      UINT64           CompareValue,
  IN      UINT64           ExchangeValue
  )
{
  ASSERT (Value != NULL);
  return InternalSyncCompareExchange64 (Value, CompareValue, ExchangeValue);
}

VOID *
EFIAPI
InterlockedCompareExchangePointer (
  IN OUT  VOID                      *volatile  *Value,
  IN      VOID                                 *CompareValue,
  IN      VOID                                 *ExchangeValue
  )
{
  UINT8  SizeOfValue;

  SizeOfValue = sizeof (*Value);

  switch (SizeOfValue) {
    case sizeof (UINT32):
      return (VOID *)(UINTN)InterlockedCompareExchange32 (
                              (volatile UINT32 *)Value,
                              (UINT32)(UINTN)CompareValue,
                              (UINT32)(UINTN)ExchangeValue
                              );
    case sizeof (UINT64):
      return (VOID *)(UINTN)InterlockedCompareExchange64 (
                              (volatile UINT64 *)Value,
                              (UINT64)(UINTN)CompareValue,
                              (UINT64)(UINTN)ExchangeValue
                              );
    default:
      ASSERT (FALSE);
      return NULL;
  }
}
