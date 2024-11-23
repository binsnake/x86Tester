#include "generator.hpp"

#include "basegenerator.hpp"

#include <Zydis/Encoder.h>
extern "C" {
#include <Zydis/Internal/EncoderData.h>
#include <Zydis/Internal/SharedData.h>
}

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <execution>
#include <format>
#include <memory>
#include <print>
#include <span>
#include <vector>

namespace x86Tester::Generator
{
    namespace Generators
    {
        namespace Detail
        {
            struct SegRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_ES, ZYDIS_REGISTER_CS, ZYDIS_REGISTER_SS,
                    ZYDIS_REGISTER_DS, ZYDIS_REGISTER_FS, ZYDIS_REGISTER_GS,
                };
            };

            struct Gp8Regs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_AL,   ZYDIS_REGISTER_CL,   ZYDIS_REGISTER_DL,   ZYDIS_REGISTER_BL,   ZYDIS_REGISTER_AH,
                    ZYDIS_REGISTER_CH,   ZYDIS_REGISTER_DH,   ZYDIS_REGISTER_BH,   ZYDIS_REGISTER_SPL,  ZYDIS_REGISTER_BPL,
                    ZYDIS_REGISTER_SIL,  ZYDIS_REGISTER_DIL,  ZYDIS_REGISTER_R8B,  ZYDIS_REGISTER_R9B,  ZYDIS_REGISTER_R10B,
                    ZYDIS_REGISTER_R11B, ZYDIS_REGISTER_R12B, ZYDIS_REGISTER_R13B, ZYDIS_REGISTER_R14B, ZYDIS_REGISTER_R15B,
                };
            };

            struct Gp16Regs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_AX,   ZYDIS_REGISTER_CX,   ZYDIS_REGISTER_DX,   ZYDIS_REGISTER_BX,
                    ZYDIS_REGISTER_SP,   ZYDIS_REGISTER_BP,   ZYDIS_REGISTER_SI,   ZYDIS_REGISTER_DI,
                    ZYDIS_REGISTER_R8W,  ZYDIS_REGISTER_R9W,  ZYDIS_REGISTER_R10W, ZYDIS_REGISTER_R11W,
                    ZYDIS_REGISTER_R12W, ZYDIS_REGISTER_R13W, ZYDIS_REGISTER_R14W, ZYDIS_REGISTER_R15W,
                };
            };

            struct Gp32Regs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_EAX,  ZYDIS_REGISTER_ECX,  ZYDIS_REGISTER_EDX,  ZYDIS_REGISTER_EBX,
                    ZYDIS_REGISTER_ESP,  ZYDIS_REGISTER_EBP,  ZYDIS_REGISTER_ESI,  ZYDIS_REGISTER_EDI,
                    ZYDIS_REGISTER_R8D,  ZYDIS_REGISTER_R9D,  ZYDIS_REGISTER_R10D, ZYDIS_REGISTER_R11D,
                    ZYDIS_REGISTER_R12D, ZYDIS_REGISTER_R13D, ZYDIS_REGISTER_R14D, ZYDIS_REGISTER_R15D,
                };
            };

            struct Gp64Regs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RBX,
                    ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI,
                    ZYDIS_REGISTER_R8,  ZYDIS_REGISTER_R9,  ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11,
                    ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15,
                };
            };

            struct Gp8MemRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_AL,  ZYDIS_REGISTER_CL,   ZYDIS_REGISTER_DL,
                    ZYDIS_REGISTER_BL,   ZYDIS_REGISTER_DIL, ZYDIS_REGISTER_R15B,
                };
            };

            struct Gp16MemRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_IP, ZYDIS_REGISTER_AX,
                    ZYDIS_REGISTER_CX,   ZYDIS_REGISTER_DX, ZYDIS_REGISTER_R15W,
                };
            };

            struct Gp32MemRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_EIP, ZYDIS_REGISTER_EAX,
                    ZYDIS_REGISTER_ECX,  ZYDIS_REGISTER_EDX, ZYDIS_REGISTER_R15D,
                };
            };

            struct Gp64MemRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_RIP, ZYDIS_REGISTER_RAX,
                    ZYDIS_REGISTER_RCX,  ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_R15,
                };
            };

            struct StRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_ST0, ZYDIS_REGISTER_ST1, ZYDIS_REGISTER_ST2, ZYDIS_REGISTER_ST3,
                    ZYDIS_REGISTER_ST4, ZYDIS_REGISTER_ST5, ZYDIS_REGISTER_ST6, ZYDIS_REGISTER_ST7,
                };
            };

            struct MmRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_MM0, ZYDIS_REGISTER_MM1, ZYDIS_REGISTER_MM2, ZYDIS_REGISTER_MM3,
                    ZYDIS_REGISTER_MM4, ZYDIS_REGISTER_MM5, ZYDIS_REGISTER_MM6, ZYDIS_REGISTER_MM7,
                };
            };

            struct XmmRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_XMM0,  ZYDIS_REGISTER_XMM1,  ZYDIS_REGISTER_XMM2,  ZYDIS_REGISTER_XMM3,
                    ZYDIS_REGISTER_XMM4,  ZYDIS_REGISTER_XMM5,  ZYDIS_REGISTER_XMM6,  ZYDIS_REGISTER_XMM7,
                    ZYDIS_REGISTER_XMM8,  ZYDIS_REGISTER_XMM9,  ZYDIS_REGISTER_XMM10, ZYDIS_REGISTER_XMM11,
                    ZYDIS_REGISTER_XMM12, ZYDIS_REGISTER_XMM13, ZYDIS_REGISTER_XMM14, ZYDIS_REGISTER_XMM15,
                    ZYDIS_REGISTER_XMM16, ZYDIS_REGISTER_XMM17, ZYDIS_REGISTER_XMM18, ZYDIS_REGISTER_XMM19,
                    ZYDIS_REGISTER_XMM20, ZYDIS_REGISTER_XMM21, ZYDIS_REGISTER_XMM22, ZYDIS_REGISTER_XMM23,
                    ZYDIS_REGISTER_XMM24, ZYDIS_REGISTER_XMM25, ZYDIS_REGISTER_XMM26, ZYDIS_REGISTER_XMM27,
                    ZYDIS_REGISTER_XMM28, ZYDIS_REGISTER_XMM29, ZYDIS_REGISTER_XMM30, ZYDIS_REGISTER_XMM31,
                };
            };

            struct YmmRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_YMM0,  ZYDIS_REGISTER_YMM1,  ZYDIS_REGISTER_YMM2,  ZYDIS_REGISTER_YMM3,
                    ZYDIS_REGISTER_YMM4,  ZYDIS_REGISTER_YMM5,  ZYDIS_REGISTER_YMM6,  ZYDIS_REGISTER_YMM7,
                    ZYDIS_REGISTER_YMM8,  ZYDIS_REGISTER_YMM9,  ZYDIS_REGISTER_YMM10, ZYDIS_REGISTER_YMM11,
                    ZYDIS_REGISTER_YMM12, ZYDIS_REGISTER_YMM13, ZYDIS_REGISTER_YMM14, ZYDIS_REGISTER_YMM15,
                    ZYDIS_REGISTER_YMM16, ZYDIS_REGISTER_YMM17, ZYDIS_REGISTER_YMM18, ZYDIS_REGISTER_YMM19,
                    ZYDIS_REGISTER_YMM20, ZYDIS_REGISTER_YMM21, ZYDIS_REGISTER_YMM22, ZYDIS_REGISTER_YMM23,
                    ZYDIS_REGISTER_YMM24, ZYDIS_REGISTER_YMM25, ZYDIS_REGISTER_YMM26, ZYDIS_REGISTER_YMM27,
                    ZYDIS_REGISTER_YMM28, ZYDIS_REGISTER_YMM29, ZYDIS_REGISTER_YMM30, ZYDIS_REGISTER_YMM31,
                };
            };

            struct ZmmRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_ZMM0,  ZYDIS_REGISTER_ZMM1,  ZYDIS_REGISTER_ZMM2,  ZYDIS_REGISTER_ZMM3,
                    ZYDIS_REGISTER_ZMM4,  ZYDIS_REGISTER_ZMM5,  ZYDIS_REGISTER_ZMM6,  ZYDIS_REGISTER_ZMM7,
                    ZYDIS_REGISTER_ZMM8,  ZYDIS_REGISTER_ZMM9,  ZYDIS_REGISTER_ZMM10, ZYDIS_REGISTER_ZMM11,
                    ZYDIS_REGISTER_ZMM12, ZYDIS_REGISTER_ZMM13, ZYDIS_REGISTER_ZMM14, ZYDIS_REGISTER_ZMM15,
                    ZYDIS_REGISTER_ZMM16, ZYDIS_REGISTER_ZMM17, ZYDIS_REGISTER_ZMM18, ZYDIS_REGISTER_ZMM19,
                    ZYDIS_REGISTER_ZMM20, ZYDIS_REGISTER_ZMM21, ZYDIS_REGISTER_ZMM22, ZYDIS_REGISTER_ZMM23,
                    ZYDIS_REGISTER_ZMM24, ZYDIS_REGISTER_ZMM25, ZYDIS_REGISTER_ZMM26, ZYDIS_REGISTER_ZMM27,
                    ZYDIS_REGISTER_ZMM28, ZYDIS_REGISTER_ZMM29, ZYDIS_REGISTER_ZMM30, ZYDIS_REGISTER_ZMM31,
                };
            };

            struct TmmRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_TMM0, ZYDIS_REGISTER_TMM1, ZYDIS_REGISTER_TMM2, ZYDIS_REGISTER_TMM3,
                    ZYDIS_REGISTER_TMM4, ZYDIS_REGISTER_TMM5, ZYDIS_REGISTER_TMM6, ZYDIS_REGISTER_TMM7,
                };
            };

        } // namespace Detail

        class OperandBase
        {
        public:
            virtual ZydisEncoderOperand current() = 0;

            virtual bool advance() = 0;
        };

        template<typename TClassTable> class RegT : public OperandBase
        {
            BaseGenerator<ZydisRegister> _gen{ TClassTable::kTable };

        public:
            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_REGISTER;
                op.reg.value = _gen.current();
                return op;
            }

            bool advance() override
            {
                return _gen.advance();
            }
        };

        using Gp8 = RegT<Detail::Gp8Regs>;
        using Gp16 = RegT<Detail::Gp16Regs>;
        using Gp32 = RegT<Detail::Gp32Regs>;
        using Gp64 = RegT<Detail::Gp64Regs>;
        using St = RegT<Detail::StRegs>;
        using Mmx = RegT<Detail::MmRegs>;
        using Xmm = RegT<Detail::XmmRegs>;
        using Ymm = RegT<Detail::YmmRegs>;
        using Zmm = RegT<Detail::ZmmRegs>;
        using Tmm = RegT<Detail::TmmRegs>;

        struct RegImplicit : public OperandBase
        {
            ZydisRegister reg;

            RegImplicit(ZydisRegister reg)
                : reg(reg)
            {
            }

            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_REGISTER;
                op.reg.value = reg;
                return op;
            }

            bool advance() override
            {
                return false;
            }
        };

        class Imm : public OperandBase
        {
            static constexpr int64_t kValues[] = {
                0, 1, 3, 4, 6, 8, -1, -2, -3, -4, -8, -9, 0x7F, 0x7FFF, 0x7FFFFFFF, 0x7FFFFFFFFFFFFFFF, 0xF, 0xFF,
            };

            BaseGenerator<int64_t> _gen{ std::span(kValues) };

        public:
            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                op.imm.s = _gen.current();
                return op;
            }

            bool advance() override
            {
                return _gen.advance();
            }
        };

        class Rel8 : public OperandBase
        {
            static constexpr int64_t kValues[] = {
                2, 8, 16, -2, -8, -16,
            };

            BaseGenerator<int64_t> _gen{ std::span(kValues) };

        public:
            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                op.imm.s = _gen.current();
                return op;
            }

            bool advance() override
            {
                return _gen.advance();
            }
        };

        class Rel32 : public OperandBase
        {
            static constexpr int64_t kValues[] = {
                1024, 0x7FFFFFFF, 0x7FFFFFFF, -1024, -0x7FFFFFFF, -0x7FFFFFFF,
            };

            BaseGenerator<int64_t> _gen{ std::span(kValues) };

        public:
            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                op.imm.s = _gen.current();
                return op;
            }

            bool advance() override
            {
                return _gen.advance();
            }
        };

        template<typename TRegClass, uint16_t TMemSize> class MemT : public OperandBase
        {
            static constexpr uint8_t kScaleValues[] = { 1, 4, 8 };
            static constexpr int64_t kImmValues[] = {
                0,
                0x89FFFFF,
                -0x89FFFFF,
            };

            BaseGenerator<ZydisRegister> _seg{ std::span(Detail::SegRegs::kTable) };
            BaseGenerator<ZydisRegister> _base{ std::span(TRegClass::kTable) };
            BaseGenerator<ZydisRegister> _index{ std::span(TRegClass::kTable) };
            BaseGenerator<int64_t> _disp{ std::span(kImmValues) };
            BaseGenerator<uint8_t> _scale{ std::span(kScaleValues) };

        public:
            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_MEMORY;
                op.mem.base = _base.current();
                op.mem.index = _index.current();
                op.mem.displacement = _disp.current();
                op.mem.scale = _scale.current();
                op.mem.size = TMemSize;
                return op;
            }

            bool advance() override
            {
                if (_base.advance())
                    return true;
                if (_index.advance())
                    return true;
                if (_disp.advance())
                    return true;
                if (_scale.advance())
                    return true;

                return false;
            }
        };

        using Mem8 = MemT<Detail::Gp8MemRegs, 1>;
        using Mem16 = MemT<Detail::Gp16MemRegs, 2>;
        using Mem32 = MemT<Detail::Gp32MemRegs, 4>;
        using Mem64 = MemT<Detail::Gp64MemRegs, 8>;

        class Operand
        {
            size_t _index{};
            std::vector<std::unique_ptr<OperandBase>> _gens;

        public:
            template<typename T, typename... Args> void add(Args&&... args)
            {
                _gens.push_back(std::make_unique<T>(std::forward<Args>(args)...));
            }

            ZydisEncoderOperand current()
            {
                assert(_index < _gens.size());

                return _gens[_index]->current();
            }

            bool advance()
            {
                if (_gens[_index]->advance())
                    return true;

                _index++;
                if (_index < _gens.size())
                    return true;

                _index = 0;
                return false;
            }

            bool empty() const
            {
                return _gens.empty();
            }
        };

        class Instr
        {
            ZydisMnemonic _mnemonic;
            std::vector<Operand> _opGens;

        public:
            Instr(ZydisMnemonic mnemonic)
                : _mnemonic(mnemonic)
            {
            }

            void addOpGen(Operand&& gen)
            {
                _opGens.push_back(std::move(gen));
            }

            ZydisEncoderRequest current()
            {
                ZydisEncoderRequest req{};
                req.mnemonic = _mnemonic;
                req.operand_count = _opGens.size();
                for (size_t i = 0; i < _opGens.size(); ++i)
                {
                    req.operands[i] = _opGens[i].current();
                }
                return req;
            }

            bool advance()
            {
                for (size_t i = 0; i < _opGens.size(); ++i)
                {
                    if (_opGens[i].advance())
                        return true;
                }
                return false;
            }
        };

    } // namespace Generators

    static Generators::Operand buildOpGenerators(ZydisMnemonic mnemonic, const ZydisOperandDefinition& opDef)
    {
        Generators::Operand gens;

        auto handleImplicitReg = [&]() {
            if (opDef.op.reg.type == ZYDIS_IMPLREG_TYPE_STATIC)
            {
                gens.add<Generators::RegImplicit>(static_cast<ZydisRegister>(opDef.op.reg.reg.reg));
            }
        };

        switch (opDef.type)
        {
            case ZYDIS_SEMANTIC_OPTYPE_IMPLICIT_REG:
                handleImplicitReg();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR8:
                gens.add<Generators::Gp8>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR16:
                gens.add<Generators::Gp16>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR32:
                gens.add<Generators::Gp32>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR64:
                gens.add<Generators::Gp64>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR16_32_64:
                gens.add<Generators::Gp16>();
                gens.add<Generators::Gp32>();
                gens.add<Generators::Gp64>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR32_32_64:
                gens.add<Generators::Gp32>();
                gens.add<Generators::Gp64>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR16_32_32:
                gens.add<Generators::Gp16>();
                gens.add<Generators::Gp32>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR_ASZ:
                gens.add<Generators::Gp16>();
                gens.add<Generators::Gp32>();
                gens.add<Generators::Gp64>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_IMM:
                gens.add<Generators::Imm>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_FPR:
                gens.add<Generators::St>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_MMX:
                gens.add<Generators::Mmx>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_XMM:
                gens.add<Generators::Xmm>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_YMM:
                gens.add<Generators::Ymm>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_ZMM:
                gens.add<Generators::Zmm>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_REL:
                gens.add<Generators::Rel8>();
                gens.add<Generators::Rel32>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_AGEN:
                gens.add<Generators::Mem8>();
                gens.add<Generators::Mem16>();
                gens.add<Generators::Mem32>();
                gens.add<Generators::Mem64>();
                break;
            default:
                break;
        }
        return gens;
    }

    static bool mnemonicPassesFilter(ZydisMnemonic mnemonic, const Filter& filter)
    {
        if (filter.mnemonics.none())
            return true;

        return filter.mnemonics.test(static_cast<size_t>(mnemonic));
    }

    static std::vector<Generators::Instr> createGenerators(const Filter& filter)
    {
        std::vector<Generators::Instr> instrs;

        for (auto mnemonic = ZYDIS_MNEMONIC_INVALID + 1; mnemonic < ZYDIS_MNEMONIC_MAX_VALUE + 1; mnemonic++)
        {
            if (!mnemonicPassesFilter((ZydisMnemonic)mnemonic, filter))
                continue;

            const ZydisEncodableInstruction* entries = nullptr;
            const auto countEntries = ZydisGetEncodableInstructions((ZydisMnemonic)mnemonic, &entries);

            for (ZyanU8 i = 0; i < countEntries; ++i)
            {
                const ZydisEncodableInstruction& entry = entries[i];

                const ZydisInstructionDefinition* base_definition = nullptr;
                ZydisGetInstructionDefinition(
                    (ZydisInstructionEncoding)entry.encoding, entry.instruction_reference, &base_definition);

                const ZydisOperandDefinition* operandDefs = ZydisGetOperandDefinitions(base_definition);

                Generators::Instr instr((ZydisMnemonic)mnemonic);

                bool badCombination = false;
                for (uint8_t j = 0; j < base_definition->operand_count_visible; ++j)
                {
                    const ZydisOperandDefinition& opDef = operandDefs[j];

                    auto opGen = buildOpGenerators((ZydisMnemonic)mnemonic, opDef);
                    if (opGen.empty())
                    {
                        badCombination = true;
                        break;
                    }

                    instr.addOpGen(std::move(opGen));
                }

                if (badCombination)
                    continue;

                instrs.push_back(std::move(instr));
            }
        }

        return instrs;
    }

    static std::string getHex(const uint8_t* data, size_t length)
    {
        std::string result;
        for (size_t i = 0; i < length; i++)
        {
            result += std::format("{:02X} ", data[i]);
        }
        return result;
    }

    static std::string getInstrText(const ZydisEncoderRequest& req)
    {
        auto opString = std::string{};
        for (size_t i = 0; i < req.operand_count; i++)
        {
            if (i > 0)
                opString += ", ";
            switch (req.operands[i].type)
            {
                case ZYDIS_OPERAND_TYPE_REGISTER:
                    opString += ZydisRegisterGetString(req.operands[i].reg.value);
                    break;
                case ZYDIS_OPERAND_TYPE_MEMORY:
                    opString += "MEM";
                    break;
                case ZYDIS_OPERAND_TYPE_POINTER:
                    opString += "PTR";
                    break;
                case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                    opString += std::format("{}", req.operands[i].imm.s);
                    break;
            }
        }

        return std::format("{} {}", ZydisMnemonicGetString(req.mnemonic), opString);
    }

    struct EncodeResult
    {
        ZyanStatus status{};
        uint8_t buf[15]{};
        uint8_t size{};
    };

    EncodeResult checkEncode(ZydisEncoderRequest req, ZydisMachineMode mode)
    {
        req.machine_mode = mode;

        EncodeResult res{};

        ZyanUSize len = sizeof(res.buf);
        if (res.status = ZydisEncoderEncodeInstruction(&req, res.buf, &len); res.status != ZYAN_STATUS_SUCCESS)
        {
            return res;
        }

        res.size = static_cast<uint8_t>(len);
        return res;
    }

    template<bool TEnabled> struct CondLockGuard
    {
        std::mutex& mtx;
        bool enabled;

        CondLockGuard(std::mutex& mtx)
            : mtx{ mtx }
        {
            if constexpr (TEnabled)
            {
                mtx.lock();
            }
        }

        ~CondLockGuard()
        {
            if constexpr (TEnabled)
            {
                mtx.unlock();
            }
        }
    };

    template<bool TBuildInParallel>
    InstructionEntries buildInstructionsImpl(ZydisMachineMode mode, const Filter& filter, ProgressReportFn reporter)
    {
        InstructionEntries res;

        std::mutex mtx;
        std::atomic<size_t> progress{};
        std::atomic<size_t> countInvalid{};

        static constexpr auto kExecutionPolicy = []() {
            if constexpr (TBuildInParallel)
                return std::execution::par;
            else
                return std::execution::seq;
        }();

        auto instrGenerators = createGenerators(filter);
        std::for_each(kExecutionPolicy, instrGenerators.begin(), instrGenerators.end(), [&](auto& instr) {
            for (;;)
            {
                auto req = instr.current();

                auto encodeRes = checkEncode(req, mode);
                bool isValid = encodeRes.status == ZYAN_STATUS_SUCCESS;

                if (isValid)
                {
                    CondLockGuard<TBuildInParallel> lock(mtx);

                    const auto entryOffset = static_cast<uint32_t>(res.instrData.size());

                    res.instrData.push_back(encodeRes.size);
                    res.instrData.insert(res.instrData.end(), encodeRes.buf, encodeRes.buf + encodeRes.size);

                    res.entryOffsets.push_back(entryOffset);
                }
                else
                {
                    countInvalid++;
                }

                if (!instr.advance())
                    break;
            }

            progress++;

            if (reporter)
                reporter(progress.load(), instrGenerators.size());
        });

        return res;
    }

    InstructionEntries buildInstructions(
        ZydisMachineMode mode, const Filter& filter, bool buildInParallel, ProgressReportFn reporter)
    {
        auto entries = [&]() {
            if (buildInParallel)
            {
                return buildInstructionsImpl<true>(mode, filter, reporter);
            }
            else
            {
                return buildInstructionsImpl<false>(mode, filter, reporter);
            }
        }();

        // Sort by length and bytes.
        std::sort(entries.entryOffsets.begin(), entries.entryOffsets.end(), [&](auto entryA, auto entryB) {
            const auto aLen = entries.instrData[entryA];
            const auto bLen = entries.instrData[entryB];

            if (aLen != bLen)
                return aLen < bLen;

            const auto aData = entries.instrData.data() + entryA + 1;
            const auto bData = entries.instrData.data() + entryB + 1;

            return std::lexicographical_compare(aData, aData + aLen, bData, bData + bLen);
        });

        // Remove entries where the data is identical.
        entries.entryOffsets.erase(
            std::unique(
                entries.entryOffsets.begin(), entries.entryOffsets.end(),
                [&](auto entryA, auto entryB) {
                    const auto aLen = entries.instrData[entryA];
                    const auto bLen = entries.instrData[entryB];

                    if (aLen != bLen)
                        return false;

                    const auto aData = entries.instrData.data() + entryA + 1;
                    const auto bData = entries.instrData.data() + entryB + 1;

                    return std::equal(aData, aData + aLen, bData);
                }),
            entries.entryOffsets.end());

        return entries;
    }

} // namespace x86Tester::Generator