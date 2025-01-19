#pragma once

#include <array>
#include <cassert>
#include <cstdint>
#include <random>
#include <sfl/small_vector.hpp>
#include <span>
#include <xmmintrin.h>

namespace x86Tester::Generator
{
    namespace Detail
    {
        template<typename T> static std::vector<std::vector<std::uint8_t>> generateIntegers()
        {
            std::vector<T> numbers;

            // Add first 64 numbers, important for shifts and rotates.
            for (T i = 1; i < 64; i++)
            {
                numbers.push_back(i);
            }

            numbers.push_back(0);

            // Add all bits set.
            {
                T value{};
                for (std::size_t i = 0; i < sizeof(T) * 8; i++)
                {
                    value |= T{ 1 } << i;
                }
                numbers.push_back(value);
            }

            // Add with single bit set.
            {
                for (std::size_t i = 0; i < sizeof(T) * 8; i++)
                {
                    T value{};
                    value |= T{ 1 } << i;
                    numbers.push_back(value);
                }
            }

            // Add with every 3. bit set.
            {
                T value{};
                for (std::size_t i = 0; i < sizeof(T) * 8; i += 3)
                {
                    value |= T{ 1 } << i;
                }
                numbers.push_back(value);
            }

            // Add with every 4. bit set.
            {
                T value{};
                for (std::size_t i = 0; i < sizeof(T) * 8; i += 3)
                {
                    value |= T{ 1 } << i;
                }
                numbers.push_back(value);
            }

            // Add numbers with 2 bits set with 1 bit spacing.
            {
                T value{};
                for (std::size_t i = 0; i < sizeof(T) * 8; i += 3)
                {
                    value |= T{ 1 } << i;
                    value |= T{ 1 } << (i + 1);
                }
                numbers.push_back(value);
            }

            // Add numbers with 2 bits set with 2 bits spacing.
            {
                T value{};
                for (std::size_t i = 0; i < sizeof(T) * 8; i += 4)
                {
                    value |= T{ 1 } << i;
                    value |= T{ 1 } << (i + 1);
                }
                numbers.push_back(value);
            }

            // Add numbers with 3 bits set.
            {
                T value{};
                for (std::size_t i = 0; i < sizeof(T) * 8; i += 4)
                {
                    value |= T{ 1 } << i;
                    value |= T{ 1 } << (i + 1);
                    value |= T{ 1 } << (i + 2);
                }
                numbers.push_back(value);
            }

            // Add numbers with 2 bits set and 1 bit unset.
            {
                T value{};
                for (std::size_t i = 0; i < sizeof(T) * 8; i += 4)
                {
                    value |= T{ 1 } << i;
                    value |= T{ 1 } << (i + 2);
                }
                numbers.push_back(value);
            }

            if constexpr (sizeof(T) >= 2)
            {
                // Add numbers with single byte fully set.
                {
                    for (std::size_t i = 0; i < sizeof(T); i++)
                    {
                        T num{ 0xFF };
                        num <<= i * 8;
                        numbers.push_back(num);
                    }
                }

                // Add numbers with all bits set except for specific byte.
                {
                    for (std::size_t i = 0; i < sizeof(T); i++)
                    {
                        T num = ~T{ 0 };
                        // Clear the byte.
                        num &= ~(T{ 0xFF } << (i * 8));
                        numbers.push_back(num);
                    }
                }
            }

            if constexpr (sizeof(T) >= 8)
            {
                std::mt19937_64 prng{ 1 };

                // Generate random floating point numbers.
                {
                    std::uniform_real_distribution<double> dist(0.0f, 1.0f);
                    for (size_t i = 0; i < 64; i++)
                    {
                        double value = dist(prng);
                        numbers.push_back(std::bit_cast<std::int64_t>(value));
                    }
                }
            }

            for (T i = 1; i < 16; i++)
            {
                numbers.push_back(i);
                numbers.push_back(-i);
            }

            for (size_t i = 0, maxNum = numbers.size(); i < maxNum; i++)
            {
                auto num = numbers[i];
                if (num == 0)
                    continue;
                if (num == -1)
                    continue;

                for (size_t rot = 1; rot < 4; rot++)
                {
                    num = (num << 8) | (num >> (sizeof(T) * 8 - 8));
                    numbers.push_back(num);
                }
            }

            // Make unique.
            std::sort(numbers.begin(), numbers.end());
            numbers.erase(std::unique(numbers.begin(), numbers.end()), numbers.end());

            // Convert.
            auto res = std::vector<std::vector<std::uint8_t>>{};
            res.reserve(numbers.size());

            for (auto num : numbers)
            {
                std::vector<std::uint8_t> bytes(sizeof(T));
                std::memcpy(bytes.data(), &num, sizeof(T));
                res.push_back(std::move(bytes));
            }

            return res;
        }

        static std::vector<std::vector<std::uint8_t>> generateXmmNumbers()
        {
            std::vector<std::vector<std::uint8_t>> res;

            // All bits set.
            {
                std::vector<std::uint8_t> bytes(16, 0xFF);
                res.push_back(std::move(bytes));
            }

            // 0-31 set.
            {
                std::vector<std::uint8_t> bytes(16, 0);
                for (std::size_t i = 0; i < 32; i++)
                {
                    bytes[i / 8] |= 1 << (i % 8);
                }
                res.push_back(std::move(bytes));
            }

            // 32-63 set.
            {
                std::vector<std::uint8_t> bytes(16, 0);
                for (std::size_t i = 32; i < 64; i++)
                {
                    bytes[i / 8] |= 1 << (i % 8);
                }
                res.push_back(std::move(bytes));
            }

            // 64-95 set.
            {
                std::vector<std::uint8_t> bytes(16, 0);
                for (std::size_t i = 64; i < 96; i++)
                {
                    bytes[i / 8] |= 1 << (i % 8);
                }
                res.push_back(std::move(bytes));
            }

            // 96-127 set.
            {
                std::vector<std::uint8_t> bytes(16, 0);
                for (std::size_t i = 96; i < 128; i++)
                {
                    bytes[i / 8] |= 1 << (i % 8);
                }
                res.push_back(std::move(bytes));
            }

            // Every second bit set.
            {
                std::vector<std::uint8_t> bytes(16, 0);
                for (std::size_t i = 0; i < 128; i += 2)
                {
                    bytes[i / 8] |= 1 << (i % 8);
                }
                res.push_back(std::move(bytes));
            }

            // Special values.
            {
                std::vector<std::uint8_t> bytes(16, 0);

                __m128 val{};
                val.m128_u64[0] = 0xFFFFFFFFFF8000FF;

                std::memcpy(bytes.data(), &val, sizeof(val));

                res.push_back(bytes);
            }

            // Random floats.
            {
                std::mt19937_64 prng{ 1 };
                std::uniform_real_distribution<float> dist(-99999.0f, 99999.0f);
                for (size_t i = 0; i < 64; i++)
                {
                    std::vector<std::uint8_t> bytes(16);

                    __m128 val{};
                    val.m128_f32[0] = dist(prng);
                    val.m128_f32[1] = dist(prng);
                    val.m128_f32[2] = dist(prng);
                    val.m128_f32[3] = dist(prng);

                    std::memcpy(bytes.data(), &val, sizeof(val));

                    res.push_back(std::move(bytes));
                }
            }

            for (std::uint32_t a0 = 0; a0 < 4; a0++)
            {
                for (std::uint32_t b0 = 0; b0 < 4; b0++)
                {
                    for (std::uint32_t c0 = 0; c0 < 4; c0++)
                    {
                        for (std::uint32_t d0 = 0; d0 < 4; d0++)
                        {
                            std::vector<std::uint8_t> bytes(16);

                            __m128 val{};
                            val.m128_u32[0] = a0 * 9;
                            val.m128_u32[1] = b0 * 2147483647;
                            val.m128_u32[2] = c0 * 3;
                            val.m128_u32[3] = d0 * 9;

                            std::memcpy(bytes.data(), &val, sizeof(val));

                            res.push_back(std::move(bytes));
                        }
                    }
                }
            }

            // Remove duplicates.
            std::sort(res.begin(), res.end());
            res.erase(std::unique(res.begin(), res.end()), res.end());

            return res;
        }

        template<std::size_t TBitSize> std::vector<std::vector<std::uint8_t>> generateNumbers()
        {
            if constexpr (TBitSize == 8)
            {
                return generateIntegers<std::int8_t>();
            }
            else if constexpr (TBitSize == 16)
            {
                return generateIntegers<std::int16_t>();
            }
            else if constexpr (TBitSize == 32)
            {
                return generateIntegers<std::int32_t>();
            }
            else if constexpr (TBitSize == 64)
            {
                return generateIntegers<std::int64_t>();
            }
            else if constexpr (TBitSize == 128)
            {
                return generateXmmNumbers();
            }
            else
            {
                static_assert(TBitSize == 0, "Unsupported bit size");
            }
        }

        static const auto kMagicNumbers8b = generateIntegers<std::int8_t>();

        static const auto kMagicNumbers16b = generateIntegers<std::int16_t>();

        static const auto kMagicNumbers32b = generateIntegers<std::int32_t>();

        static const auto kMagicNumbers64b = generateIntegers<std::int64_t>();

        static const auto kMagicNumbers128b = generateXmmNumbers();

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
            // Make sure we have an initial value.
            advanceStrategy();
            advance();
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

            if (_maxBits == 1)
            {
                const auto value = _counter & 1;
                if (++_counter >= 2)
                    nextStrat = true;

                _data[0] = value;
            }
            else if (_maxBits == 8)
            {
                const auto valueBytes = Detail::kMagicNumbers8b[_counter % std::size(Detail::kMagicNumbers8b)];
                if (++_counter >= std::size(Detail::kMagicNumbers8b))
                    nextStrat = true;

                std::copy(valueBytes.begin(), valueBytes.end(), _data.begin());
            }
            else if (_maxBits == 16)
            {
                const auto valueBytes = Detail::kMagicNumbers16b[_counter % std::size(Detail::kMagicNumbers16b)];
                if (++_counter >= std::size(Detail::kMagicNumbers16b))
                    nextStrat = true;

                std::copy(valueBytes.begin(), valueBytes.end(), _data.begin());
            }
            else if (_maxBits == 32)
            {
                const auto valueBytes = Detail::kMagicNumbers32b[_counter % std::size(Detail::kMagicNumbers32b)];
                if (++_counter >= std::size(Detail::kMagicNumbers32b))
                    nextStrat = true;

                std::copy(valueBytes.begin(), valueBytes.end(), _data.begin());
            }
            else if (_maxBits == 64)
            {
                const auto valueBytes = Detail::kMagicNumbers64b[_counter % std::size(Detail::kMagicNumbers64b)];
                if (++_counter >= std::size(Detail::kMagicNumbers64b))
                    nextStrat = true;

                std::copy(valueBytes.begin(), valueBytes.end(), _data.begin());
            }
            else if (_maxBits == 128)
            {
                const auto valueBytes = Detail::kMagicNumbers128b[_counter % std::size(Detail::kMagicNumbers128b)];
                if (++_counter >= std::size(Detail::kMagicNumbers128b))
                    nextStrat = true;

                std::copy(valueBytes.begin(), valueBytes.end(), _data.begin());
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