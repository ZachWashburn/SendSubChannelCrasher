//========= Copyright © 1996-2005, Valve Corporation, All rights reserved. ============//
//
// Purpose: 
//
// $NoKeywords: $
//
//=============================================================================//

#include "bitbuf.h"
#include "bitbuf.h"




#if _WIN32
#define FAST_BIT_SCAN 1
#if defined( _X360 )
#define CountLeadingZeros(x) _CountLeadingZeros(x)
inline unsigned int CountTrailingZeros(unsigned int elem)
{
	// this implements CountTrailingZeros() / BitScanForward()
	unsigned int mask = elem - 1;
	unsigned int comp = ~elem;
	elem = mask & comp;
	return (32 - _CountLeadingZeros(elem));
}
#else
#include <intrin.h>
#pragma intrinsic(_BitScanReverse)
#pragma intrinsic(_BitScanForward)

inline unsigned int CountLeadingZeros(unsigned int x)
{
	unsigned long firstBit;
	if (_BitScanReverse(&firstBit, x))
		return 31 - firstBit;
	return 32;
}
inline unsigned int CountTrailingZeros(unsigned int elem)
{
	unsigned long out;
	if (_BitScanForward(&out, elem))
		return out;
	return 32;
}

#endif
#else
#define FAST_BIT_SCAN 0
#endif


//static BitBufErrorHandler g_BitBufErrorHandler = 0;


void InternalBitBufErrorHandler(BitBufErrorType errorType, const char* pDebugName)
{
	if (g_BitBufErrorHandler)
		g_BitBufErrorHandler(errorType, pDebugName);
}


void SetBitBufErrorHandler(BitBufErrorHandler fn)
{
	g_BitBufErrorHandler = fn;
}


// #define BB_PROFILING




#undef Assert
#undef ASSERT
#define Assert(COND) _ASSERT(COND)
#define ASSERT(COND) _ASSERT(COND)
#undef AssertFatalMsg
#define AssertFatalMsg(COND) _ASSERT(COND)


#define DEBUG_LINK_CHECK ;
// ---------------------------------------------------------------------------------------- //
// bf_write
// ---------------------------------------------------------------------------------------- //

bf_write::bf_write()
{
	DEBUG_LINK_CHECK;
	m_pData = NULL;
	m_nDataBytes = 0;
	m_nDataBits = -1; // set to -1 so we generate overflow on any operation
	m_iCurBit = 0;
	m_bOverflow = false;
	m_bAssertOnOverflow = true;
	m_pDebugName = NULL;

}

bf_write::bf_write(const char* pDebugName, void* pData, int nBytes, int nBits)
{
	DEBUG_LINK_CHECK;
	m_bAssertOnOverflow = true;
	m_pDebugName = pDebugName;
	StartWriting(pData, nBytes, 0, nBits);
}

bf_write::bf_write(void* pData, int nBytes, int nBits)
{
	m_bAssertOnOverflow = true;
	m_pDebugName = NULL;
	StartWriting(pData, nBytes, 0, nBits);
}

void bf_write::StartWriting(void* pData, int nBytes, int iStartBit, int nBits)
{
	// Make sure it's dword aligned and padded.
	DEBUG_LINK_CHECK;


	// The writing code will overrun the end of the buffer if it isn't dword aligned, so truncate to force alignment
	nBytes &= ~3;

	m_pData = (unsigned char*)pData;
	m_nDataBytes = nBytes;

	if (nBits == -1)
	{
		m_nDataBits = nBytes << 3;
	}
	else
	{

		m_nDataBits = nBits;
	}

	m_iCurBit = iStartBit;
	m_bOverflow = false;
}

void bf_write::Reset()
{
	m_iCurBit = 0;
	m_bOverflow = false;
}


void bf_write::SetAssertOnOverflow(bool bAssert)
{
	m_bAssertOnOverflow = bAssert;
}


const char* bf_write::GetDebugName()
{
	return m_pDebugName;
}


void bf_write::SetDebugName(const char* pDebugName)
{
	m_pDebugName = pDebugName;
}


void bf_write::SeekToBit(int bitPos)
{
	m_iCurBit = bitPos;
}


// Sign bit comes first
void bf_write::WriteSBitLong(int data, int numbits)
{
#if 1
	if (data < 0)
	{
		WriteUBitLong((unsigned int)(0x80000000 + data), numbits - 1, false);
		WriteOneBit(1);
	}
	else
	{
		WriteUBitLong((unsigned int)data, numbits - 1);
		WriteOneBit(0);
	}
#else
	// Force the sign-extension bit to be correct even in the case of overflow.
	int nValue = data;
	int nPreserveBits = (0x7FFFFFFF >> (32 - numbits));
	int nSignExtension = (nValue >> 31) & ~nPreserveBits;
	nValue &= nPreserveBits;
	nValue |= nSignExtension;

	//AssertMsg2(nValue == data, "WriteSBitLong: 0x%08x does not fit in %d bits", data, numbits);

	WriteUBitLong(nValue, numbits, false);
#endif
}

#if _WIN32
inline unsigned int BitCountNeededToEncode(unsigned int data)
{
#if defined(_X360)
	return (32 - CountLeadingZeros(data + 1)) - 1;
#else
	unsigned long firstBit;
	_BitScanReverse(&firstBit, data + 1);
	return firstBit;
#endif
}
#endif	// _WIN32

// writes an unsigned integer with variable bit length
void bf_write::WriteUBitVar(unsigned int n)
{
	if (n < 16)
		WriteUBitLong(n, 6);
	else
		if (n < 256)
			WriteUBitLong((n & 15) | 16 | ((n & (128 | 64 | 32 | 16)) << 2), 10);
		else
			if (n < 4096)
				WriteUBitLong((n & 15) | 32 | ((n & (2048 | 1024 | 512 | 256 | 128 | 64 | 32 | 16)) << 2), 14);
			else
			{
				WriteUBitLong((n & 15) | 48, 6);
				WriteUBitLong((n >> 4), 32 - 4);
			}
}

void bf_write::WriteVarInt32(uint32 data)
{
	// Check if align and we have room, slow path if not
	if ((m_iCurBit & 7) == 0 && (m_iCurBit + bitbuf::kMaxVarint32Bytes * 8) <= m_nDataBits)
	{
		uint8* target = ((uint8*)m_pData) + (m_iCurBit >> 3);

		target[0] = static_cast<uint8>(data | 0x80);
		if (data >= (1 << 7))
		{
			target[1] = static_cast<uint8>((data >> 7) | 0x80);
			if (data >= (1 << 14))
			{
				target[2] = static_cast<uint8>((data >> 14) | 0x80);
				if (data >= (1 << 21))
				{
					target[3] = static_cast<uint8>((data >> 21) | 0x80);
					if (data >= (1 << 28))
					{
						target[4] = static_cast<uint8>(data >> 28);
						m_iCurBit += 5 * 8;
						return;
					}
					else
					{
						target[3] &= 0x7F;
						m_iCurBit += 4 * 8;
						return;
					}
				}
				else
				{
					target[2] &= 0x7F;
					m_iCurBit += 3 * 8;
					return;
				}
			}
			else
			{
				target[1] &= 0x7F;
				m_iCurBit += 2 * 8;
				return;
			}
		}
		else
		{
			target[0] &= 0x7F;
			m_iCurBit += 1 * 8;
			return;
		}
	}
	else // Slow path
	{
		while (data > 0x7F)
		{
			WriteUBitLong((data & 0x7F) | 0x80, 8);
			data >>= 7;
		}
		WriteUBitLong(data & 0x7F, 8);
	}
}

void bf_write::WriteVarInt64(uint64 data)
{
	// Check if align and we have room, slow path if not
	if ((m_iCurBit & 7) == 0 && (m_iCurBit + bitbuf::kMaxVarintBytes * 8) <= m_nDataBits)
	{
		uint8* target = ((uint8*)m_pData) + (m_iCurBit >> 3);

		// Splitting into 32-bit pieces gives better performance on 32-bit
		// processors.
		uint32 part0 = static_cast<uint32>(data);
		uint32 part1 = static_cast<uint32>(data >> 28);
		uint32 part2 = static_cast<uint32>(data >> 56);

		int size;

		// Here we can't really optimize for small numbers, since the data is
		// split into three parts.  Cheking for numbers < 128, for instance,
		// would require three comparisons, since you'd have to make sure part1
		// and part2 are zero.  However, if the caller is using 64-bit integers,
		// it is likely that they expect the numbers to often be very large, so
		// we probably don't want to optimize for small numbers anyway.  Thus,
		// we end up with a hardcoded binary search tree...
		if (part2 == 0)
		{
			if (part1 == 0)
			{
				if (part0 < (1 << 14))
				{
					if (part0 < (1 << 7))
					{
						size = 1; goto size1;
					}
					else
					{
						size = 2; goto size2;
					}
				}
				else
				{
					if (part0 < (1 << 21))
					{
						size = 3; goto size3;
					}
					else
					{
						size = 4; goto size4;
					}
				}
			}
			else
			{
				if (part1 < (1 << 14))
				{
					if (part1 < (1 << 7))
					{
						size = 5; goto size5;
					}
					else
					{
						size = 6; goto size6;
					}
				}
				else
				{
					if (part1 < (1 << 21))
					{
						size = 7; goto size7;
					}
					else
					{
						size = 8; goto size8;
					}
				}
			}
		}
		else
		{
			if (part2 < (1 << 7))
			{
				size = 9; goto size9;
			}
			else
			{
				size = 10; goto size10;
			}
		}



	size10: target[9] = static_cast<uint8>((part2 >> 7) | 0x80);
	size9: target[8] = static_cast<uint8>((part2) | 0x80);
	size8: target[7] = static_cast<uint8>((part1 >> 21) | 0x80);
	size7: target[6] = static_cast<uint8>((part1 >> 14) | 0x80);
	size6: target[5] = static_cast<uint8>((part1 >> 7) | 0x80);
	size5: target[4] = static_cast<uint8>((part1) | 0x80);
	size4: target[3] = static_cast<uint8>((part0 >> 21) | 0x80);
	size3: target[2] = static_cast<uint8>((part0 >> 14) | 0x80);
	size2: target[1] = static_cast<uint8>((part0 >> 7) | 0x80);
	size1: target[0] = static_cast<uint8>((part0) | 0x80);

		target[size - 1] &= 0x7F;
		m_iCurBit += size * 8;
	}
	else // slow path
	{
		while (data > 0x7F)
		{
			WriteUBitLong((data & 0x7F) | 0x80, 8);
			data >>= 7;
		}
		WriteUBitLong(data & 0x7F, 8);
	}
}

void bf_write::WriteSignedVarInt32(int32 data)
{
	WriteVarInt32(bitbuf::ZigZagEncode32(data));
}

void bf_write::WriteSignedVarInt64(int64 data)
{
	WriteVarInt64(bitbuf::ZigZagEncode64(data));
}

int	bf_write::ByteSizeVarInt32(uint32 data)
{
	int size = 1;
	while (data > 0x7F) {
		size++;
		data >>= 7;
	}
	return size;
}

int	bf_write::ByteSizeVarInt64(uint64 data)
{
	int size = 1;
	while (data > 0x7F) {
		size++;
		data >>= 7;
	}
	return size;
}

int bf_write::ByteSizeSignedVarInt32(int32 data)
{
	return ByteSizeVarInt32(bitbuf::ZigZagEncode32(data));
}

int bf_write::ByteSizeSignedVarInt64(int64 data)
{
	return ByteSizeVarInt64(bitbuf::ZigZagEncode64(data));
}

void bf_write::WriteBitLong(unsigned int data, int numbits, bool bSigned)
{
	if (bSigned)
		WriteSBitLong((int)data, numbits);
	else
		WriteUBitLong(data, numbits);
}

bool bf_write::WriteBits(const void* pInData, int nBits)
{
#if defined( BB_PROFILING )
	VPROF("bf_write::WriteBits");
#endif

	unsigned char* pIn = (unsigned char*)pInData;
	int nBitsLeft = nBits;

	// Bounds checking..
	if ((m_iCurBit + nBits) > m_nDataBits)
	{
		SetOverflowFlag();
		CallErrorHandler(BITBUFERROR_BUFFER_OVERRUN, GetDebugName());
		return false;
	}

	// Align input to dword boundary
	while (((uintp)pIn & 3) != 0 && nBitsLeft >= 8)
	{
		WriteUBitLong(*pIn, 8, false);
		++pIn;
		nBitsLeft -= 8;
	}

	if (nBitsLeft >= 32)
	{
		if ((m_iCurBit & 7) == 0)
		{
			// current bit is byte aligned, do block copy
			int numbytes = nBitsLeft >> 3;
			int numbits = numbytes << 3;

			memcpy(m_pData + (m_iCurBit >> 3), pIn, numbytes);
			pIn += numbytes;
			nBitsLeft -= numbits;
			m_iCurBit += numbits;
		}
		else
		{
			const uint32 iBitsRight = (m_iCurBit & 31);

			const uint32 iBitsLeft = 32 - iBitsRight;
			const int iBitsChanging = 32 + iBitsLeft; // how many bits are changed during one step (not necessary written meaningful)
			unsigned int iDWord = m_iCurBit >> 5;

			uint32 outWord = LoadLittleDWord((uint32*)m_pData, iDWord);
			outWord &= g_BitWriteMasks[iBitsRight][32]; // clear rest of beginning DWORD 

			// copy in DWORD blocks
			while (nBitsLeft >= iBitsChanging)
			{
				uint32 curData = LittleDWord(*(uint32*)pIn);
				pIn += sizeof(uint32);

				outWord |= curData << iBitsRight;
				StoreLittleDWord((uint32*)m_pData, iDWord, outWord);

				++iDWord;
				outWord = curData >> iBitsLeft;

				nBitsLeft -= 32;
				m_iCurBit += 32;
			}

			// store last word
			StoreLittleDWord((uint32*)m_pData, iDWord, outWord);

			// write remaining DWORD 
			if (nBitsLeft >= 32)
			{
				WriteUBitLong(LittleDWord(*((uint32*)pIn)), 32, false);
				pIn += sizeof(uint32);
				nBitsLeft -= 32;
			}
		}
	}

	// write remaining bytes
	while (nBitsLeft >= 8)
	{
		WriteUBitLong(*pIn, 8, false);
		++pIn;
		nBitsLeft -= 8;
	}

	// write remaining bits
	if (nBitsLeft)
	{
		WriteUBitLong(*pIn, nBitsLeft, false);
	}

	return !IsOverflowed();
}

bool bf_write::WriteBitsFromBuffer(bf_read* pIn, int nBits)
{

	return !IsOverflowed();
}


void bf_write::WriteBitAngle(float fAngle, int numbits)
{
	int d;
	unsigned int mask;
	unsigned int shift;

	shift = BitForBitnum(numbits);
	mask = shift - 1;

	d = (int)((fAngle / 360.0) * shift);
	d &= mask;

	WriteUBitLong((unsigned int)d, numbits);
}

void bf_write::WriteBitCoordMP(const float f, EBitCoordType coordType)
{
}

void bf_write::WriteBitCellCoord(const float f, int bits, EBitCoordType coordType)
{

}


void bf_write::WriteBitCoord(const float f)
{

}

void bf_write::WriteBitFloat(float val)
{

}

void bf_write::WriteBitVec3Coord(const Vector& fa)
{

}

void bf_write::WriteBitNormal(float f)
{

}

void bf_write::WriteBitVec3Normal(const Vector& fa)
{

}

void bf_write::WriteBitAngles(const QAngle& fa)
{

}

void bf_write::WriteChar(int val)
{
	WriteSBitLong(val, sizeof(char) << 3);
}

void bf_write::WriteByte(unsigned int val)
{
	WriteUBitLong(val, sizeof(unsigned char) << 3);
}

void bf_write::WriteShort(int val)
{
	WriteSBitLong(val, sizeof(short) << 3);
}

void bf_write::WriteWord(unsigned int val)
{
	WriteUBitLong(val, sizeof(unsigned short) << 3);
}

void bf_write::WriteLong(int32 val)
{
	WriteSBitLong(val, sizeof(int32) << 3);
}

void bf_write::WriteLongLong(int64 val)
{
	__debugbreak();
}
#define LittleFloat( pOut, pIn )	( *pOut = *pIn )
void bf_write::WriteFloat(float val)
{
	// Pre-swap the float, since WriteBits writes raw data
	LittleFloat(&val, &val);

	WriteBits(&val, sizeof(val) << 3);
}

bool bf_write::WriteBytes(const void* pBuf, int nBytes)
{
	return WriteBits(pBuf, nBytes << 3);
}

bool bf_write::WriteString(const char* pStr)
{
	if (pStr)
	{
		do
		{
			WriteChar(*pStr);
			++pStr;
		} while (*(pStr - 1) != 0);
	}
	else
	{
		WriteChar(0);
	}

	return !IsOverflowed();
}

bool bf_write::WriteString(const wchar_t* pStr)
{
	if (pStr)
	{
		do
		{
			WriteShort(*pStr);
			++pStr;
		} while (*(pStr - 1) != 0);
	}
	else
	{
		WriteShort(0);
	}

	return !IsOverflowed();
}