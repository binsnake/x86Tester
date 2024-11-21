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
        template<typename T> static std::vector<std::int64_t> generateNumbers()
        {
            std::vector<T> numbers;

            // Add first 64 numbers, important for shifts and rotates.
            for (T i = 0; i < 64; i++)
            {
                numbers.push_back(i);
            }

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
            auto res = std::vector<std::int64_t>();
            for (auto num : numbers)
            {
                res.push_back(static_cast<std::int64_t>(num));
            }

            return res;
        }

        static const auto kMagicNumbers8b = generateNumbers<std::int8_t>();

        static const auto kMagicNumbers16b = generateNumbers<std::int16_t>();

        static const auto kMagicNumbers32b = generateNumbers<std::int32_t>();

        static const auto kMagicNumbers64b = generateNumbers<std::int64_t>();

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
            else if (_maxBits == 128)
            {
                const auto value1 = Detail::kMagicNumbers64b[_counter % std::size(Detail::kMagicNumbers64b)];
                if (++_counter >= std::size(Detail::kMagicNumbers64b))
                    nextStrat = true;

                const auto value2 = Detail::kMagicNumbers64b[_counter % std::size(Detail::kMagicNumbers64b)];
                if (++_counter >= std::size(Detail::kMagicNumbers64b))
                    nextStrat = true;

                std::memcpy(_data.data(), &value1, sizeof(value1));
                std::memcpy(_data.data() + sizeof(value1), &value2, sizeof(value2));
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