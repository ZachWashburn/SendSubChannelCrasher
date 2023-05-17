#pragma once

#include <intrin.h>


#include <cstdlib>
#include <ctype.h>
#include <corecrt_memcpy_s.h>
typedef unsigned char uint8;
typedef signed char int8;



typedef __int32 intp;
typedef unsigned __int32 uintp;

typedef __int16 int16;
typedef unsigned __int16 uint16;
typedef __int32 int32;
typedef unsigned __int32 uint32;
typedef __int64 int64;
typedef unsigned __int64 uint64;
#define LittleDWord( val )			( val )
inline uint32 LoadLittleDWord(uint32* base, unsigned int dwordIndex)
{
	return LittleDWord(base[dwordIndex]);
}

inline void StoreLittleDWord(uint32* base, unsigned int dwordIndex, uint32 dword)
{
	base[dwordIndex] = LittleDWord(dword);
}

#undef Assert
#undef ASSERT
#define Assert(COND) _ASSERT(COND)
#define ASSERT(COND) _ASSERT(COND)

#define CallErrorHandler(COND, SHIT) ;
//-----------------------------------------------------------------------------
// Forward declarations.
//-----------------------------------------------------------------------------

class Vector;
class QAngle;

//-----------------------------------------------------------------------------
// You can define a handler function that will be called in case of 
// out-of-range values and overruns here.
//
// NOTE: the handler is only called in debug mode.
//
// Call SetBitBufErrorHandler to install a handler.
//-----------------------------------------------------------------------------

typedef enum
{
	BITBUFERROR_VALUE_OUT_OF_RANGE = 0,		// Tried to write a value with too few bits.
	BITBUFERROR_BUFFER_OVERRUN,				// Was about to overrun a buffer.

	BITBUFERROR_NUM_ERRORS
} BitBufErrorType;


typedef void (*BitBufErrorHandler)(BitBufErrorType errorType, const char* pDebugName);


#if defined( _DEBUG )
extern void InternalBitBufErrorHandler(BitBufErrorType errorType, const char* pDebugName);
//#define CallErrorHandler( errorType, pDebugName ) InternalBitBufErrorHandler( errorType, pDebugName );
#else
#define CallErrorHandler( errorType, pDebugName )
#endif
#define BITS_PER_INT		32
static BitBufErrorHandler g_BitBufErrorHandler = 0;
inline unsigned GetEndMask(int numBits)
{
	static unsigned bitStringEndMasks[] =
	{
		0xffffffff,
		0x00000001,
		0x00000003,
		0x00000007,
		0x0000000f,
		0x0000001f,
		0x0000003f,
		0x0000007f,
		0x000000ff,
		0x000001ff,
		0x000003ff,
		0x000007ff,
		0x00000fff,
		0x00001fff,
		0x00003fff,
		0x00007fff,
		0x0000ffff,
		0x0001ffff,
		0x0003ffff,
		0x0007ffff,
		0x000fffff,
		0x001fffff,
		0x003fffff,
		0x007fffff,
		0x00ffffff,
		0x01ffffff,
		0x03ffffff,
		0x07ffffff,
		0x0fffffff,
		0x1fffffff,
		0x3fffffff,
		0x7fffffff,
	};

	return bitStringEndMasks[numBits % BITS_PER_INT];
}


inline int GetBitForBitnum(int bitNum)
{
	static int bitsForBitnum[] =
	{
		(1 << 0),
		(1 << 1),
		(1 << 2),
		(1 << 3),
		(1 << 4),
		(1 << 5),
		(1 << 6),
		(1 << 7),
		(1 << 8),
		(1 << 9),
		(1 << 10),
		(1 << 11),
		(1 << 12),
		(1 << 13),
		(1 << 14),
		(1 << 15),
		(1 << 16),
		(1 << 17),
		(1 << 18),
		(1 << 19),
		(1 << 20),
		(1 << 21),
		(1 << 22),
		(1 << 23),
		(1 << 24),
		(1 << 25),
		(1 << 26),
		(1 << 27),
		(1 << 28),
		(1 << 29),
		(1 << 30),
		(1 << 31),
	};

	return bitsForBitnum[(bitNum) & (BITS_PER_INT - 1)];
}

inline int GetBitForBitnumByte(int bitNum)
{
	static int bitsForBitnum[] =
	{
		(1 << 0),
		(1 << 1),
		(1 << 2),
		(1 << 3),
		(1 << 4),
		(1 << 5),
		(1 << 6),
		(1 << 7),
	};

	return bitsForBitnum[bitNum & 7];
}


inline int BitForBitnum(int bitnum)
{
	return GetBitForBitnum(bitnum);
}


inline uint32 g_LittleBits[32];

// Precalculated bit masks for WriteUBitLong. Using these tables instead of 
// doing the calculations gives a 33% speedup in WriteUBitLong.
inline uint32 g_BitWriteMasks[32][33];

// (1 << i) - 1
inline uint32 g_ExtraMasks[33];
class CBitWriteMasksInit
{
public:
	CBitWriteMasksInit()
	{
		for (unsigned int startbit = 0; startbit < 32; startbit++)
		{
			for (unsigned int nBitsLeft = 0; nBitsLeft < 33; nBitsLeft++)
			{
				unsigned int endbit = startbit + nBitsLeft;
				g_BitWriteMasks[startbit][nBitsLeft] = BitForBitnum(startbit) - 1;
				if (endbit < 32)
					g_BitWriteMasks[startbit][nBitsLeft] |= ~(BitForBitnum(endbit) - 1);
			}
		}

		for (unsigned int maskBit = 0; maskBit < 32; maskBit++)
			g_ExtraMasks[maskBit] = BitForBitnum(maskBit) - 1;

		//g_ExtraMasks[32] = ~0ul;

		for (unsigned int littleBit = 0; littleBit < 32; littleBit++) {
			StoreLittleDWord((uint32*)&g_LittleBits[littleBit], 0, 1u << littleBit);
		}
	}
};
inline CBitWriteMasksInit g_BitWriteMasksInit;






// Use this to install the error handler. Call with NULL to uninstall your error handler.
void SetBitBufErrorHandler(BitBufErrorHandler fn);


//-----------------------------------------------------------------------------
// Helpers.
//-----------------------------------------------------------------------------

inline int BitByte(int bits)
{
	// return PAD_NUMBER( bits, 8 ) >> 3;
	return (bits + 7) >> 3;
}

//-----------------------------------------------------------------------------
enum EBitCoordType
{
	kCW_None,
	kCW_LowPrecision,
	kCW_Integral
};

//-----------------------------------------------------------------------------
// namespaced helpers
//-----------------------------------------------------------------------------
namespace bitbuf
{
	// ZigZag Transform:  Encodes signed integers so that they can be
	// effectively used with varint encoding.
	//
	// varint operates on unsigned integers, encoding smaller numbers into
	// fewer bytes.  If you try to use it on a signed integer, it will treat
	// this number as a very large unsigned integer, which means that even
	// small signed numbers like -1 will take the maximum number of bytes
	// (10) to encode.  ZigZagEncode() maps signed integers to unsigned
	// in such a way that those with a small absolute value will have smaller
	// encoded values, making them appropriate for encoding using varint.
	//
	//       int32 ->     uint32
	// -------------------------
	//           0 ->          0
	//          -1 ->          1
	//           1 ->          2
	//          -2 ->          3
	//         ... ->        ...
	//  2147483647 -> 4294967294
	// -2147483648 -> 4294967295
	//
	//        >> encode >>
	//        << decode <<

	inline uint32 ZigZagEncode32(int32 n)
	{
		// Note:  the right-shift must be arithmetic
		return(n << 1) ^ (n >> 31);
	}

	inline int32 ZigZagDecode32(uint32 n)
	{
		return(n >> 1) ^ -static_cast<int32>(n & 1);
	}

	inline uint64 ZigZagEncode64(int64 n)
	{
		// Note:  the right-shift must be arithmetic
		return(n << 1) ^ (n >> 63);
	}

	inline int64 ZigZagDecode64(uint64 n)
	{
		return(n >> 1) ^ -static_cast<int64>(n & 1);
	}

	const int kMaxVarintBytes = 10;
	const int kMaxVarint32Bytes = 5;
}

//-----------------------------------------------------------------------------
// Used for serialization
//-----------------------------------------------------------------------------
#pragma pack(push, 4)
class bf_write
{
public:
	bf_write();

	// nMaxBits can be used as the number of bits in the buffer. 
	// It must be <= nBytes*8. If you leave it at -1, then it's set to nBytes * 8.
	bf_write(void* pData, int nBytes, int nMaxBits = -1);
	bf_write(const char* pDebugName, void* pData, int nBytes, int nMaxBits = -1);

	// Start writing to the specified buffer.
	// nMaxBits can be used as the number of bits in the buffer. 
	// It must be <= nBytes*8. If you leave it at -1, then it's set to nBytes * 8.
	void			StartWriting(void* pData, int nBytes, int iStartBit = 0, int nMaxBits = -1);

	// Restart buffer writing.
	void			Reset();

	// Get the base pointer.
	unsigned char* GetBasePointer() { return (unsigned char*)m_pData; }

	// Enable or disable assertion on overflow. 99% of the time, it's a bug that we need to catch,
	// but there may be the occasional buffer that is allowed to overflow gracefully.
	void			SetAssertOnOverflow(bool bAssert);

	// This can be set to assign a name that gets output if the buffer overflows.
	const char* GetDebugName();
	void			SetDebugName(const char* pDebugName);


	// Seek to a specific position.
public:

	void			SeekToBit(int bitPos);


	// Bit functions.
public:

	void			WriteOneBit(int nValue);
	void			WriteOneBitNoCheck(int nValue);
	void			WriteOneBitAt(int iBit, int nValue);

	// Write signed or unsigned. Range is only checked in debug.
	void			WriteUBitLong(unsigned int data, int numbits, bool bCheckRange = true);
	void			WriteSBitLong(int data, int numbits);

	// Tell it whether or not the data is unsigned. If it's signed,
	// cast to unsigned before passing in (it will cast back inside).
	void			WriteBitLong(unsigned int data, int numbits, bool bSigned);

	// Write a list of bits in.
	bool			WriteBits(const void* pIn, int nBits);

	// writes an unsigned integer with variable bit length
	void			WriteUBitVar(unsigned int data);

	// writes a varint encoded integer
	void			WriteVarInt32(uint32 data);
	void			WriteVarInt64(uint64 data);
	void			WriteSignedVarInt32(int32 data);
	void			WriteSignedVarInt64(int64 data);
	int				ByteSizeVarInt32(uint32 data);
	int				ByteSizeVarInt64(uint64 data);
	int				ByteSizeSignedVarInt32(int32 data);
	int				ByteSizeSignedVarInt64(int64 data);

	// Copy the bits straight out of pIn. This seeks pIn forward by nBits.
	// Returns an error if this buffer or the read buffer overflows.
	bool			WriteBitsFromBuffer(class bf_read* pIn, int nBits);

	void			WriteBitAngle(float fAngle, int numbits);
	void			WriteBitCoord(const float f);
	void			WriteBitCoordMP(const float f, EBitCoordType coordType);
	void 			WriteBitCellCoord(const float f, int bits, EBitCoordType coordType);
	void			WriteBitFloat(float val);
	void			WriteBitVec3Coord(const Vector& fa);
	void			WriteBitNormal(float f);
	void			WriteBitVec3Normal(const Vector& fa);
	void			WriteBitAngles(const QAngle& fa);


	// Byte functions.
public:

	void			WriteChar(int val);
	void			WriteByte(unsigned int val);
	void			WriteShort(int val);
	void			WriteWord(unsigned int val);
	void			WriteLong(int32 val);
	void			WriteLongLong(int64 val);
	void			WriteFloat(float val);
	bool			WriteBytes(const void* pBuf, int nBytes);

	// Returns false if it overflows the buffer.
	bool			WriteString(const char* pStr);
	bool			WriteString(const wchar_t* pStr);


	// Status.
public:

	// How many bytes are filled in?
	int				GetNumBytesWritten() const;
	int				GetNumBitsWritten() const;
	int				GetMaxNumBits() const;
	int				GetNumBitsLeft() const;
	int				GetNumBytesLeft() const;
	unsigned char* GetData();
	const unsigned char* GetData() const;

	// Has the buffer overflowed?
	bool			CheckForOverflow(int nBits);
	inline bool		IsOverflowed() const { return m_bOverflow; }

	inline void		SetOverflowFlag();

public:
	// The current buffer.
	unsigned  char* m_pData;
	uint32				m_nDataBytes;
	uint32				m_nDataBits;
	uint32				m_iCurBit;
	bool			m_bOverflow;
	bool			m_bAssertOnOverflow;

	const char* m_pDebugName;


};
#pragma pack(pop)

//-----------------------------------------------------------------------------
// Inlined methods
//-----------------------------------------------------------------------------

// How many bytes are filled in?
inline int bf_write::GetNumBytesWritten() const
{
	return BitByte(m_iCurBit);
}

inline int bf_write::GetNumBitsWritten() const
{
	return m_iCurBit;
}

inline int bf_write::GetMaxNumBits() const
{
	return m_nDataBits;
}

inline int bf_write::GetNumBitsLeft() const
{
	return m_nDataBits - m_iCurBit;
}

inline int bf_write::GetNumBytesLeft() const
{
	return GetNumBitsLeft() >> 3;
}

inline unsigned char* bf_write::GetData()
{
	return (unsigned char*)m_pData;
}

inline const unsigned char* bf_write::GetData() const
{
	return (unsigned char*)m_pData;
}

inline bool bf_write::CheckForOverflow(int nBits)
{
	if (m_iCurBit + nBits > m_nDataBits)
	{
		SetOverflowFlag();
		CallErrorHandler(BITBUFERROR_BUFFER_OVERRUN, GetDebugName());
	}

	return m_bOverflow;
}

inline void bf_write::SetOverflowFlag()
{
	if (m_bAssertOnOverflow)
	{
		//Assert( false );

	}

	m_bOverflow = true;
}

inline void bf_write::WriteOneBitNoCheck(int nValue)
{
	if (nValue)
		m_pData[m_iCurBit >> 3] |= (1 << (m_iCurBit & 7));
	else
		m_pData[m_iCurBit >> 3] &= ~(1 << (m_iCurBit & 7));

	++m_iCurBit;
}

inline void bf_write::WriteOneBit(int nValue)
{
	if (!CheckForOverflow(1))
		WriteOneBitNoCheck(nValue);
}


inline void	bf_write::WriteOneBitAt(int iBit, int nValue)
{
	if (iBit + 1 > m_nDataBits)
	{
		SetOverflowFlag();
		CallErrorHandler(BITBUFERROR_BUFFER_OVERRUN, GetDebugName());
		return;
	}

	if (nValue)
		m_pData[iBit >> 3] |= (1 << (iBit & 7));
	else
		m_pData[iBit >> 3] &= ~(1 << (iBit & 7));
}


inline __declspec(noinline) void bf_write::WriteUBitLong(unsigned int curData, int numbits, bool bCheckRange)
{
#ifdef _DEBUG
	// Make sure it doesn't overflow.
	if (bCheckRange && numbits < 32)
	{
		if (curData >= (uint32)(1 << numbits))
		{
			//CallErrorHandler(BITBUFERROR_VALUE_OUT_OF_RANGE, GetDebugName());
		}
	}
	//Assert(numbits >= 0 && numbits <= 32);
#endif

	extern uint32 g_BitWriteMasks[32][33];

	// Bounds checking..
	if ((m_iCurBit + numbits) > m_nDataBits)
	{
		m_iCurBit = m_nDataBits;
		SetOverflowFlag();
		CallErrorHandler(BITBUFERROR_BUFFER_OVERRUN, GetDebugName());
		return;
	}

	int nBitsLeft = numbits;
	int iCurBit = m_iCurBit;

	// Mask in a dword.
	unsigned int iDWord = iCurBit >> 5;


	uint32 iCurBitMasked = iCurBit & 31;

	uint32 dword = LoadLittleDWord((uint32*)m_pData, iDWord);

	dword &= g_BitWriteMasks[iCurBitMasked][nBitsLeft];
	dword |= curData << iCurBitMasked;

	// write to stream (lsb to msb ) properly
	StoreLittleDWord((uint32*)m_pData, iDWord, dword);

	// Did it span a dword?
	int nBitsWritten = 32 - iCurBitMasked;
	if (nBitsWritten < nBitsLeft)
	{
		nBitsLeft -= nBitsWritten;
		curData >>= nBitsWritten;

		// read from stream (lsb to msb) properly 
		dword = LoadLittleDWord((uint32*)m_pData, iDWord + 1);

		dword &= g_BitWriteMasks[0][nBitsLeft];
		dword |= curData;

		// write to stream (lsb to msb) properly 
		StoreLittleDWord((uint32*)m_pData, iDWord + 1, dword);
	}

	m_iCurBit += numbits;
}


//-----------------------------------------------------------------------------
// This is useful if you just want a buffer to write into on the stack.
//-----------------------------------------------------------------------------

template<int SIZE>
class old_bf_write_static : public bf_write
{
public:
	inline old_bf_write_static() : bf_write(m_StaticData, SIZE) {}

	char	m_StaticData[SIZE];
};
