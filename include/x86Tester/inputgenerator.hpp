#pragma once

#include <array>
#include <cassert>
#include <cstdint>
#include <random>
#include <sfl/small_vector.hpp>
#include <span>

namespace x86Tester::Generator
{
    namespace Detail
    {
        static constexpr auto kMagicNumbers8b = []() {
            // 8 bit.
            std::array<std::int64_t, 256> arr{};
            for (std::int64_t i = 0; i < 256; i++)
                arr[i] = static_cast<std::int64_t>(static_cast<std::int8_t>(i));
            return arr;
        }();

        static constexpr std::int64_t kMagicNumbers16b[] = {
            // 16 bit.
            0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x0010, 0x0020, 0x0040, 0x0080,
            0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x4800, 0x8000, 0xFFFF, 0x7FFF, 0x8001, 0xFFFE, 0x00FF,
            0xFF00, 0x0FFF, 0xF000, 0x3FFF, 0xC000, 0x0008, 0xFFF8, 0xFFEF, 0x001F, 0xFFE0, 0xAAAA, 0x5555, 0x6996, 0x9669,
            0x5AA5, 0xA55A, 0x6CC6, 0xC663, 0x3333, 0xCCCC, 0x7FFE, 0x8002, 0x7E00, 0x81FF, 0x1234, 0x4321, 0x3C3C, 0x000F,
            0xC3C3, 0xF0F0, 0x0F0F, 0xFFFF, 0x0001, 0xFFFE, 0x7FFD, 0x8003, 0xFFFF, 0x0040, 0xFFC0, 0x4000, 0xBFFF, 0xDAAD,
            0x2552, 0x0111, 0xFEEE, 0xFFFD, 0,      1,      2,      3,      4,      5,      6,      7,      8,      9,
            -1,     -2,     -3,     -4,     -5,     -6,     -7,     1600,   50,     1650,   -8,     -9,     -15,    -127,
            -255,   -32767, 0x7F,   0x7FFF, 0xF,    0xFF,   16384,  8192,   4096,   2048,   1024,   512,    256,    128,
            64,     32,     16,     8,      4,      2,      1,      -32768, 48,     32
        };

        static constexpr std::int64_t kMagicNumbers32b[] = {
            // 32 bit.
            0x00000000, 0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006,  0x00000007,  0x00000008,
            0x00000009, 0x00000010, 0x00000020, 0x00000040, 0x00000080, 0x00000100, 0x00000200,  0x00000400,  0x00000800,
            0x00001000, 0x00002000, 0x00004000, 0x00008000, 0x00010000, 0x00020000, 0x00040000,  0x00080000,  0x00100000,
            0x00200000, 0x00400000, 0x00800000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,  0x10000000,  0x20000000,
            0x40000000, 0x48000000, 0x80000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0x80000001,  0xFFFFFFFE,  0x0000FFFF,
            0xFFFF0000, 0x00FFFFFF, 0xFF000000, 0x0FFFFFFF, 0xF0000000, 0x3FFFFFFF, 0x0000000F,  0xAAAAAAAA,  0x55555555,
            0xC0000000, 0x00000008, 0xFFFFFFF8, 0x00000010, 0xFFFFFFEF, 0x0000001F, 0xFFFFFFE0,  0xAAAAAAAA,  0x55555555,
            0x12345678, 0x87654321, 0x69966996, 0x96699669, 0x5AA55AA5, 0xA55AA55A, 0x6CC66CC6,  0xC663C663,  0x33333333,
            0xCCCCCCCC, 0x7FFFFFFE, 0x80000002, 0x3C3C3C3C, 0xC3C3C3C3, 0x1E1E1E1E, 0xE1E1E1E1,  0x000003E8,  0xFFFFFC18,
            0x12481248, 0x84218421, 0x7FFD0000, 0x80020001, 0x40000000, 0xBFFFFFFF, 0xF0000001,  0x0FFFF000,  0xFFFEFFFF,
            0x00010000, 0xFFFFFFFD, 0x0000000A, 0x0000000B, 0x0000000C, 0x0000000D, 0x0000000E,  0x0000000F,  0x00000010,
            0x00000011, 0x00000012, 0x00000013, 0x00000014, 0x00000015, 0x00000016, 0x00000017,  0x00000018,  0x00000019,
            0x0000001A, 0x0000001B, 0x0000001C, 0x0000001D, 0x0000001E, 0x0000001F, 0x00000020,  0x00000021,  0x00000022,
            0x00000023, 0x00000024, 0x00000025, 0x00000026, 0x00000027, 0x00000028, 0x00000029,  0x0000002A,  0x0000002B,
            0x0000002C, 0x0000002D, 0x0000002E, 0x0000002F, 0x00000030, 0x00000031, 0x00000032,  0x00000033,  0x00000034,
            0x00000035, 0x00000036, 0x00000037, 0x00000038, 0x00000039, 0x0000003A, 0x0000003B,  0x0000003C,  0x0000003D,
            0x0000003E, 0x0000003F, 0x00000040, 0x00000041, 0x00000042, 0x00000043, 0x00000044,  0x00000045,  0x00000046,
            0x00000047, 0x00000048, 0x00000049, 0x0000004A, 0x0000004B, 0x0000004C, 0x0000004D,  0x0000004E,  0x0000004F,
            0x00000050, 0x00000051, 0x00000052, 0x00000053, 0x00000054, 0x00000055, 0x00000056,  0x00000057,  0x00000058,
            0x00000059, 0x0000005A, 0x0000005B, 0x0000005C, 0x0000005D, 0x0000005E, 0x0000005F,  0x00000060,  0x00000061,
            0x00000062, 0x00000063, 0x00000064, 0x00000065, 0x00000066, 0x00000067, 0x00000068,  0x00000069,  0x0000006A,
            0x0000006B, 0x0000006C, 0x0000006D, 0x0000006E, 0x0000006F, 0x00000070, 0x00000071,  0x00000072,  0x00000073,
            0x00000074, 0x00000075, 0x00000076, 0x00000077, 0x00000078, 0x00000079, 0x0000007A,  0x0000007B,  0x0000007C,
            0x0000007D, 0x0000007E, 0x0000007F, 0x00000080, 0x00000081, 0x00000082, 0x00000083,  0x00000084,  0x00000085,
            0x00000086, 0x00000087, 0x00000088, 0x00000089, 0x0000008A, 0x0000008B, 0x0000008C,  0x0000008D,  0x0000008E,
            0x0000008F, 0x00000090, 0x00000091, 0x00000092, 0x00000093, 0x00000094, 0x00000095,  0x00000096,  0x00000097,
            0x00000098, 0x00000099, 0x0000009A, 0x0000009B, 0x0000009C, 0x0000009D, 0x0000009E,  0x0000009F,  0x000000A0,
            0x000000A1, 0x000000A2, 0x000000A3, 0x000000A4, 0x000000A5, 0x000000A6, 0x000000A7,  0x000000A8,  0x000000A9,
            0x000000AA, 0x000000AB, 0x000000AC, 0x000000AD, 0x000000AE, 0x000000AF, 0x000000B0,  0x000000B1,  0x000000B2,
            0x00010000, 0xFFFFFFFD, 0,          1,          2,          3,          4,           5,           6,
            7,          8,          9,          -1,         -2,         -3,         -4,          -5,          -6,
            -7,         -8,         -9,         -15,        -127,       -255,       -32767,      -2147483647, 0x7F,
            1073741824, 536870912,  268435456,  134217728,  67108864,   33554432,   16777216,    8388608,     4194304,
            2097152,    1048576,    524288,     262144,     131072,     65536,      -2147483648, 0x7FFF,      0x7FFFFFFF,
            0xF,        0xFF,       48,         32,
        };

        static constexpr std::int64_t kMagicNumbers64b[] = {
            // 64 bit.
            0x0000000000000000,
            0x0000000000000001,
            0x0000000000000002,
            0x0000000000000003,
            0x0000000000000004,
            0x0000000000000005,
            0x0000000000000006,
            0x0000000000000007,
            0x0000000000000008,
            0x0000000000000010,
            0x0000000000000020,
            0x0000000000000040,
            0x0000000000000080,
            0x0000000000000100,
            0x0000000000000200,
            0x0000000000000300,
            0x0000000000000400,
            0x0000000000000800,
            0x0000000000001000,
            0x0000000000002000,
            0x0000000000004000,
            0x0000000000005000,
            0x0000000000008000,
            0x0000000000010000,
            0x0000000000020000,
            0x0000000000040000,
            0x0000000000080000,
            0x0000000000100000,
            0x0000000000200000,
            0x0000000000400000,
            0x0000000000800000,
            0x0000000001000000,
            0x0000000002000000,
            0x0000000004000000,
            0x0000000004700000,
            0x0000000004800000,
            0x0000000008000000,
            0x0000000010000000,
            0x0000000020000000,
            0x0000000040000000,
            0x0000000047000000,
            0x0000000048000000,
            0x0000000080000000,
            0x0000000100000000,
            0x0000000200000000,
            0x0000000300000000,
            0x0000000400000000,
            0x0000000700000000,
            0x0000000800000000,
            0x0000001000000000,
            0x0000002000000000,
            0x0000004000000000,
            0x0000008000000000,
            0x0000010000000000,
            0x0000020000000000,
            0x0000040000000000,
            0x0000080000000000,
            0x0000100000000000,
            0x0000200000000000,
            0x0000400000000000,
            0x0000800000000000,
            0x0001000000000000,
            0x0002000000000000,
            0x0004000000000000,
            0x0008000000000000,
            0x0010000000000000,
            0x0020000000000000,
            0x0040000000000000,
            0x0080000000000000,
            0x0100000000000000,
            0x0200000000000000,
            0x0400000000000000,
            0x0800000000000000,
            0x1000000000000000,
            0x2000000000000000,
            0x4000000000000000,
            0x8000000000000000,
            0xCBF29CE484222325,
            0x00000100000001B3,
            0x7FFFFFFFFFFFFFFF,
            0x8000000000000000,
            0x8000000000000001,
            0xFFFFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFFFFF,
            0x00000000FFFFFFFF,
            0xFFFFFFFF00000000,
            0x0000FFFFFFFFFFFF,
            0xFFFF000000000000,
            0x000000FFFFFFFFFF,
            0xFF00000000000000,
            0x0FFFFFFFFFFFFFFF,
            0xF000000000000000,
            0x3FFFFFFFFFFFFFFF,
            0xC000000000000000,
            0x0000000000000008,
            0xFFFFFFFFFFFFFFF8,
            0x0000000000000010,
            0xFFFFFFFFFFFFFFEF,
            0x000000000000001F,
            0xFFFFFFFFFFFFFFE0,
            0xAAAAAAAAAAAAAAAA,
            0x5555555555555555,
            0x123456789ABCDEF0,
            0x0FEDCBA987654321,
            0x6996699669966996,
            0x9669966996699669,
            0x5AA55AA55AA55AA5,
            0xA55AA55AA55AA55A,
            0x6CC66CC66CC66CC6,
            0xC663C663C663C663,
            0x3333333333333333,
            0xCCCCCCCCCCCCCCCC,
            0x7FFFFFFFFFFFFFFE,
            0x8000000000000002,
            0x3C3C3C3C3C3C3C3C,
            0xC3C3C3C3C3C3C3C3,
            0x1E1E1E1E1E1E1E1E,
            0xE1E1E1E1E1E1E1E1,
            0x00000000000003E8,
            0xFFFFFFFFFFFFFC18,
            0x1248124812481248,
            0x8421842184218421,
            0x000000007FFD0000,
            0x8002000000000001,
            0x4000000000000000,
            0xBFFFFFFFFFFFFFFF,
            0xFFFFFFFF0001FFFF,
            0xFFF0FFFFFFFFFFFF,
            0xF000000000000001,
            0x0FFFFFFFFFFFF000,
            0xFFFFFFFFFFFFFFFD,
            0x00000000,
            0x00000001,
            0x00000002,
            0x00000003,
            0x00000004,
            0x00000005,
            0x00000006,
            0x00000007,
            0x00000008,
            0x00000009,
            0x00000010,
            0x00000020,
            0x00000040,
            0x00000080,
            0x00000100,
            0x00000200,
            0x00000400,
            0x00000800,
            0x00001000,
            0x00002000,
            0x00004000,
            0x00008000,
            0x00010000,
            0x00020000,
            0x00040000,
            0x00080000,
            0x00100000,
            0x00200000,
            0x00400000,
            0x00800000,
            0x01000000,
            0x02000000,
            0x04000000,
            0x08000000,
            0x10000000,
            0x20000000,
            0x40000000,
            0x48000000,
            0x80000000,
            0xFFFFFFFF,
            0x7FFFFFFF,
            0x80000000,
            0x80000001,
            0xFFFFFFFE,
            0x0000FFFF,
            0xFFFF0000,
            0x00FFFFFF,
            0xFF000000,
            0x0FFFFFFF,
            0xF0000000,
            0x3FFFFFFF,
            0x0000000F,
            0xAAAAAAAA,
            0x55555555,
            0xC0000000,
            0x00000008,
            0xFFFFFFF8,
            0x00000010,
            0xFFFFFFEF,
            0x0000001F,
            0xFFFFFFE0,
            0xAAAAAAAA,
            0x55555555,
            0x12345678,
            0x87654321,
            0x69966996,
            0x96699669,
            0x5AA55AA5,
            0xA55AA55A,
            0x6CC66CC6,
            0xC663C663,
            0x33333333,
            0xCCCCCCCC,
            0x7FFFFFFE,
            0x80000002,
            0x3C3C3C3C,
            0xC3C3C3C3,
            0x1E1E1E1E,
            0xE1E1E1E1,
            0x000003E8,
            0xFFFFFC18,
            0x12481248,
            0x84218421,
            0x7FFD0000,
            0x80020001,
            0x40000000,
            0xBFFFFFFF,
            0xF0000001,
            0x0FFFF000,
            0xFFFEFFFF,
            0x00010000,
            0xFFFFFFFD,
            0x0000000A,
            0x0000000B,
            0x0000000C,
            0x0000000D,
            0x0000000E,
            0x0000000F,
            0x00000010,
            0x00000011,
            0x00000012,
            0x00000013,
            0x00000014,
            0x00000015,
            0x00000016,
            0x00000017,
            0x00000018,
            0x00000019,
            0x0000001A,
            0x0000001B,
            0x0000001C,
            0x0000001D,
            0x0000001E,
            0x0000001F,
            0x00000020,
            0x00000021,
            0x00000022,
            0x00000023,
            0x00000024,
            0x00000025,
            0x00000026,
            0x00000027,
            0x00000028,
            0x00000029,
            0x0000002A,
            0x0000002B,
            0x0000002C,
            0x0000002D,
            0x0000002E,
            0x0000002F,
            0x00000030,
            0x00000031,
            0x00000032,
            0x00000033,
            0x00000034,
            0x00000035,
            0x00000036,
            0x00000037,
            0x00000038,
            0x00000039,
            0x0000003A,
            0x0000003B,
            0x0000003C,
            0x0000003D,
            0x0000003E,
            0x0000003F,
            0x00000040,
            0x00000041,
            0x00000042,
            0x00000043,
            0x00000044,
            0x00000045,
            0x00000046,
            0x00000047,
            0x00000048,
            0x00000049,
            0x0000004A,
            0x0000004B,
            0x0000004C,
            0x0000004D,
            0x0000004E,
            0x0000004F,
            0x00000050,
            0x00000051,
            0x00000052,
            0x00000053,
            0x00000054,
            0x00000055,
            0x00000056,
            0x00000057,
            0x00000058,
            0x00000059,
            0x0000005A,
            0x0000005B,
            0x0000005C,
            0x0000005D,
            0x0000005E,
            0x0000005F,
            0x00000060,
            0x00000061,
            0x00000062,
            0x00000063,
            0x00000064,
            0x00000065,
            0x00000066,
            0x00000067,
            0x00000068,
            0x00000069,
            0x0000006A,
            0x0000006B,
            0x0000006C,
            0x0000006D,
            0x0000006E,
            0x0000006F,
            0x00000070,
            0x00000071,
            0x00000072,
            0x00000073,
            0x00000074,
            0x00000075,
            0x00000076,
            0x00000077,
            0x00000078,
            0x00000079,
            0x0000007A,
            0x0000007B,
            0x0000007C,
            0x0000007D,
            0x0000007E,
            0x0000007F,
            0x00000080,
            0x00000081,
            0x00000082,
            0x00000083,
            0x00000084,
            0x00000085,
            0x00000086,
            0x00000087,
            0x00000088,
            0x00000089,
            0x0000008A,
            0x0000008B,
            0x0000008C,
            0x0000008D,
            0x0000008E,
            0x0000008F,
            0x00000090,
            0x00000091,
            0x00000092,
            0x00000093,
            0x00000094,
            0x00000095,
            0x00000096,
            0x00000097,
            0x00000098,
            0x00000099,
            0x0000009A,
            0x0000009B,
            0x0000009C,
            0x0000009D,
            0x0000009E,
            0x0000009F,
            0x000000A0,
            0x000000A1,
            0x000000A2,
            0x000000A3,
            0x000000A4,
            0x000000A5,
            0x000000A6,
            0x000000A7,
            0x000000A8,
            0x000000A9,
            0x000000AA,
            0x000000AB,
            0x000000AC,
            0x000000AD,
            0x000000AE,
            0x000000AF,
            0x000000B0,
            0x000000B1,
            0x000000B2,
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            32,
            48,
            50,
            1650,
            -1,
            -2,
            -3,
            -4,
            -5,
            -6,
            -7,
            -8,
            -9,
            -15,
            -127,
            -255,
            -32767,
            -2147483647,
            -9223372036854775807,
            4611686018427387904,
            2305843009213693952,
            1152921504606846976,
            576460752303423488,
            288230376151711744,
            144115188075855872,
            72057594037927936,
            36028797018963968,
            18014398509481984,
            9007199254740992,
            4503599627370496,
            2251799813685248,
            1125899906842624,
            562949953421312,
            281474976710656,
            -9223372036854775808,
            0x200,
            0x7F,
            0x7FFF,
            0x7FFFFFFF,
            0x7FFFFFFFFFFFFFFF,
            0xF,
            0xFF,
        };
    } // namespace Detail

    class InputGenerator
    {
        sfl::small_vector<uint8_t, 8> _data{};
        std::mt19937_64& _prng;

        enum class Strategy
        {
            reset,
            flipRandomBit,
            magicNumbers,
            /*
            bitWalk,
            allOnes,
            incremental,
            */
            end,
        };

        Strategy _strategy{};
        size_t _bitIndex{};
        size_t _maxBits{};
        size_t _counter{};

    public:
        InputGenerator(size_t maxBits, std::mt19937_64& prng)
            : _prng(prng)
            , _maxBits(maxBits)
        {
            _data.resize((maxBits + 7) / 8);
        }

        void reset()
        {
            _strategy = Strategy::reset;
            _bitIndex = 0;
            _counter = 0;
            std::fill(_data.begin(), _data.end(), 0);
        }

        std::span<const uint8_t> current() const
        {
            return _data;
        }

        bool advance()
        {
            switch (_strategy)
            {
                case Strategy::reset:
                    reset();
                    advanceStrategy();
                    return true;
                case Strategy::magicNumbers:
                    return advanceMagicNumbers();
                case Strategy::flipRandomBit:
                    return advanceRandomFlip();
                /*
                case Strategy::bitWalk:
                    return advanceBitWalk();
                case Strategy::allOnes:
                    return advanceAllOnes();
                case Strategy::incremental:
                    return advanceIncremental();
                */
                default:
                    return false;
            }
        }

    private:
        void setStrategy(Strategy strategy)
        {
            _strategy = strategy;
            _bitIndex = 0;
            _counter = 0;
        }

        bool advanceStrategy()
        {
            auto nextStrat = static_cast<Strategy>(static_cast<int>(_strategy) + 1);
            if (nextStrat == Strategy::end)
            {
                setStrategy(Strategy::reset);
                return false;
            }

            setStrategy(nextStrat);
            return true;
        }

        bool advanceBitWalk()
        {
            if (_bitIndex > 0)
                _data[(_bitIndex - 1) / 8] = 0;

            _data[_bitIndex / 8] = 1 << (_bitIndex % 8);
            _bitIndex++;

            if (_bitIndex >= _maxBits)
            {
                return advanceStrategy();
            }

            return true;
        }

        bool advanceRandomFlip()
        {
            std::uniform_int_distribution<size_t> dist(0, _maxBits - 1);

            const auto bitIndex = dist(_prng);
            const auto byteIndex = bitIndex / 8;
            const auto bitMask = 1 << (bitIndex % 8);

            _data[byteIndex] ^= bitMask;

            if (++_counter >= _maxBits)
            {
                return advanceStrategy();
            }

            return true;
        }

        bool advanceAllOnes()
        {
            std::fill(_data.begin(), _data.end(), 0xFF);

            return advanceStrategy();
        }

        bool advanceMagicNumbers()
        {
            bool nextStrat = false;

            if (_maxBits == 8)
            {
                const auto value = Detail::kMagicNumbers8b[_counter % std::size(Detail::kMagicNumbers8b)];
                if (++_counter >= std::size(Detail::kMagicNumbers8b))
                    nextStrat = true;
                std::memcpy(_data.data(), &value, sizeof(value));
            }
            else if (_maxBits == 16)
            {
                const auto value = Detail::kMagicNumbers16b[_counter % std::size(Detail::kMagicNumbers16b)];
                if (++_counter >= std::size(Detail::kMagicNumbers16b))
                    nextStrat = true;
                std::memcpy(_data.data(), &value, sizeof(value));
            }
            else if (_maxBits == 32)
            {
                const auto value = Detail::kMagicNumbers32b[_counter % std::size(Detail::kMagicNumbers32b)];
                if (++_counter >= std::size(Detail::kMagicNumbers32b))
                    nextStrat = true;
                std::memcpy(_data.data(), &value, sizeof(value));
            }
            else if (_maxBits == 64)
            {
                const auto value = Detail::kMagicNumbers64b[_counter % std::size(Detail::kMagicNumbers64b)];
                if (++_counter >= std::size(Detail::kMagicNumbers64b))
                    nextStrat = true;
                std::memcpy(_data.data(), &value, sizeof(value));
            }
            else
            {
                assert(false);
            }

            if (nextStrat)
            {
                return advanceStrategy();
            }

            return true;
        }

        bool advanceIncremental()
        {
            for (size_t i = 0; i < _data.size(); ++i)
            {
                if (++_data[i] != 0)
                    return true; // No overflow in this byte, continue incrementing

                // Overflow to the next byte
            }

            // Reached max value, reset and switch strategy
            return advanceStrategy();
        }
    };

} // namespace x86Tester::Generator