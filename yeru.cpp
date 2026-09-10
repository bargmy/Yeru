#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mmsystem.h>
#include <psapi.h>
#include <cmath>
#include <random>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <filesystem>

namespace fs = std::filesystem;

const uint8_t MAGIC_HEADER[7] = {0x00, 0x13, 0x13, 0x72, 0x48, 0x00, 0x50};
const uint8_t MAGIC_FOOTER[7] = {0x13, 0x40, 0x40, 0x72, 0x48, 0x00, 0x50};

enum Opcode : uint8_t {
    OP_HALT          = 0x00,
    OP_LOAD_CONST    = 0x01,
    OP_LOAD_VAR      = 0x02,
    OP_STORE_VAR     = 0x03,
    OP_PRINT         = 0x04,
    OP_INPUT         = 0x05,
    OP_EQ            = 0x06,
    OP_NEQ           = 0x07,
    OP_JUMP          = 0x08,
    OP_JUMP_IF_FALSE = 0x09,
    OP_POP           = 0x0A,
    OP_NPKT          = 0x0B,
    OP_RUN           = 0x0C,
    OP_CLS           = 0x0D,
    OP_KINP          = 0x0E,
    OP_ADVL          = 0x0F,
    OP_MKFL          = 0x10,
    OP_MKDR          = 0x11,
    OP_CHFL          = 0x12,
    OP_RPFL          = 0x13,
    OP_RDFL          = 0x14,
    OP_CPRT          = 0x15,
    OP_WAIT          = 0x16,

    OP_SUB           = 0x17,
    OP_MUL           = 0x18,
    OP_DIV           = 0x19,
    OP_MOD           = 0x1A,
    OP_POW           = 0x1B,
    OP_BAND          = 0x1C,
    OP_BOR           = 0x1D,
    OP_BXOR          = 0x1E,
    OP_BNOT          = 0x1F,
    OP_BSHL          = 0x20,
    OP_BSHR          = 0x21,
    OP_BROL          = 0x22,
    OP_BROR          = 0x23,
    OP_RAND          = 0x24,
    OP_SQRT          = 0x25,
    OP_ABS           = 0x26,
    OP_SIN           = 0x27,
    OP_COS           = 0x28,
    OP_ATAN2         = 0x29,

    OP_SLEN          = 0x2A,
    OP_SSUB          = 0x2B,
    OP_SFIND         = 0x2C,
    OP_SREP          = 0x2D,
    OP_SUPPER        = 0x2E,
    OP_SLOWER        = 0x2F,
    OP_STRIM         = 0x30,
    OP_ORD           = 0x31,
    OP_CHR           = 0x32,

    OP_CALL          = 0x33,
    OP_RET           = 0x34,

    OP_INKEY         = 0x35,
    OP_KEYDOWN       = 0x36,
    OP_KEYUP         = 0x37,
    OP_KEYMOD        = 0x38,
    OP_MOUSEX        = 0x39,
    OP_MOUSEY        = 0x3A,
    OP_MOUSEBTN      = 0x3B,
    OP_MOUSEWHEEL    = 0x3C,

    OP_TERMW         = 0x3D,
    OP_TERMH         = 0x3E,
    OP_CURPOS        = 0x3F,
    OP_CURHIDE       = 0x40,
    OP_CURSHOW       = 0x41,
    OP_TERMALTSCR    = 0x42,

    OP_RAMFREE       = 0x43,
    OP_RAMTOTAL      = 0x44,
    OP_RAMPROC       = 0x45,
    OP_CPUUSAGE      = 0x46,
    OP_CPUCORES      = 0x47,
    OP_TIMEUS        = 0x48,
    OP_TIMEMS        = 0x49,
    OP_TIMENOW       = 0x4A,
    OP_SLEEPMS       = 0x4B,
    OP_ARGVLEN       = 0x4C,
    OP_ARGVGET       = 0x4D,
    OP_ENVGET        = 0x4E,
    OP_ENVSET        = 0x4F,
    OP_EXIT          = 0x50,
    OP_EXEC          = 0x51,

    OP_FLEXISTS      = 0x52,
    OP_FLSIZE        = 0x53,
    OP_FLREAD        = 0x54,
    OP_FLWRITE       = 0x55,
    OP_FLAPPEND      = 0x56,
    OP_FLDEL         = 0x57,
    OP_DIRMAKE       = 0x58,

    OP_BEEP          = 0x59,
    OP_SFXPLAY       = 0x5A,
    OP_SFXSTOP       = 0x5B
};

const char* opcode_name(uint8_t op) {
    switch (op) {
        case OP_HALT:          return "HALT";
        case OP_LOAD_CONST:    return "LOAD_CONST";
        case OP_LOAD_VAR:      return "LOAD_VAR";
        case OP_STORE_VAR:     return "STORE_VAR";
        case OP_PRINT:         return "PRINT";
        case OP_INPUT:         return "INPUT";
        case OP_EQ:            return "EQ";
        case OP_NEQ:           return "NEQ";
        case OP_JUMP:          return "JUMP";
        case OP_JUMP_IF_FALSE: return "JUMP_IF_FALSE";
        case OP_POP:           return "POP";
        case OP_NPKT:          return "NPKT";
        case OP_RUN:           return "RUN";
        case OP_CLS:           return "CLS";
        case OP_KINP:          return "KINP";
        case OP_ADVL:          return "ADVL";
        case OP_MKFL:          return "MKFL";
        case OP_MKDR:          return "MKDR";
        case OP_CHFL:          return "CHFL";
        case OP_RPFL:          return "RPFL";
        case OP_RDFL:          return "RDFL";
        case OP_CPRT:          return "CPRT";
        case OP_WAIT:          return "WAIT";
        case OP_SUB:           return "SUB";
        case OP_MUL:           return "MUL";
        case OP_DIV:           return "DIV";
        case OP_MOD:           return "MOD";
        case OP_POW:           return "POW";
        case OP_BAND:          return "BAND";
        case OP_BOR:           return "BOR";
        case OP_BXOR:          return "BXOR";
        case OP_BNOT:          return "BNOT";
        case OP_BSHL:          return "BSHL";
        case OP_BSHR:          return "BSHR";
        case OP_BROL:          return "BROL";
        case OP_BROR:          return "BROR";
        case OP_RAND:          return "RAND";
        case OP_SQRT:          return "SQRT";
        case OP_ABS:           return "ABS";
        case OP_SIN:           return "SIN";
        case OP_COS:           return "COS";
        case OP_ATAN2:         return "ATAN2";
        case OP_SLEN:          return "SLEN";
        case OP_SSUB:          return "SSUB";
        case OP_SFIND:         return "SFIND";
        case OP_SREP:          return "SREP";
        case OP_SUPPER:        return "SUPPER";
        case OP_SLOWER:        return "SLOWER";
        case OP_STRIM:         return "STRIM";
        case OP_ORD:           return "ORD";
        case OP_CHR:           return "CHR";
        case OP_CALL:          return "CALL";
        case OP_RET:           return "RET";
        case OP_INKEY:         return "INKEY";
        case OP_KEYDOWN:       return "KEYDOWN";
        case OP_KEYUP:         return "KEYUP";
        case OP_KEYMOD:        return "KEYMOD";
        case OP_MOUSEX:        return "MOUSEX";
        case OP_MOUSEY:        return "MOUSEY";
        case OP_MOUSEBTN:      return "MOUSEBTN";
        case OP_MOUSEWHEEL:    return "MOUSEWHEEL";
        case OP_TERMW:         return "TERMW";
        case OP_TERMH:         return "TERMH";
        case OP_CURPOS:        return "CURPOS";
        case OP_CURHIDE:       return "CURHIDE";
        case OP_CURSHOW:       return "CURSHOW";
        case OP_TERMALTSCR:    return "TERMALTSCR";
        case OP_RAMFREE:       return "RAMFREE";
        case OP_RAMTOTAL:      return "RAMTOTAL";
        case OP_RAMPROC:       return "RAMPROC";
        case OP_CPUUSAGE:      return "CPUUSAGE";
        case OP_CPUCORES:      return "CPUCORES";
        case OP_TIMEUS:        return "TIMEUS";
        case OP_TIMEMS:        return "TIMEMS";
        case OP_TIMENOW:       return "TIMENOW";
        case OP_SLEEPMS:       return "SLEEPMS";
        case OP_ARGVLEN:       return "ARGVLEN";
        case OP_ARGVGET:       return "ARGVGET";
        case OP_ENVGET:        return "ENVGET";
        case OP_ENVSET:        return "ENVSET";
        case OP_EXIT:          return "EXIT";
        case OP_EXEC:          return "EXEC";
        case OP_FLEXISTS:      return "FLEXISTS";
        case OP_FLSIZE:        return "FLSIZE";
        case OP_FLREAD:        return "FLREAD";
        case OP_FLWRITE:       return "FLWRITE";
        case OP_FLAPPEND:      return "FLAPPEND";
        case OP_FLDEL:         return "FLDEL";
        case OP_DIRMAKE:       return "DIRMAKE";
        case OP_BEEP:          return "BEEP";
        case OP_SFXPLAY:       return "SFXPLAY";
        case OP_SFXSTOP:       return "SFXSTOP";
        default:               return "UNKNOWN";
    }
}

const uint16_t LOWER_BASE = 0x0000;
const uint16_t TITLE_BASE = 0x44A8;
const uint16_t UPPER_BASE = 0x8950;
const uint16_t PAIR_LOWER = 0xCDF8;
const uint16_t PAIR_TITLE = 0xD09C;
const uint16_t RAW_BASE   = 0xD340;

bool encode_triplet(char a, char b, char c, uint16_t& code) {
    if (std::islower(a) && std::islower(b) && std::islower(c)) {
        code = LOWER_BASE + (a - 'a') * 676 + (b - 'a') * 26 + (c - 'a');
        return true;
    }
    if (std::isupper(a) && std::islower(b) && std::islower(c)) {
        code = TITLE_BASE + (a - 'A') * 676 + (b - 'a') * 26 + (c - 'a');
        return true;
    }
    if (std::isupper(a) && std::isupper(b) && std::isupper(c)) {
        code = UPPER_BASE + (a - 'A') * 676 + (b - 'A') * 26 + (c - 'A');
        return true;
    }
    return false;
}

std::string decode_code(uint16_t code) {
    if (code < TITLE_BASE) {
        uint16_t idx = code - LOWER_BASE;
        return std::string{char('a' + idx / 676), char('a' + (idx / 26) % 26), char('a' + idx % 26)};
    } else if (code < UPPER_BASE) {
        uint16_t idx = code - TITLE_BASE;
        return std::string{char('A' + idx / 676), char('a' + (idx / 26) % 26), char('a' + idx % 26)};
    } else if (code < PAIR_LOWER) {
        uint16_t idx = code - UPPER_BASE;
        return std::string{char('A' + idx / 676), char('A' + (idx / 26) % 26), char('A' + idx % 26)};
    } else if (code < PAIR_TITLE) {
        uint16_t idx = code - PAIR_LOWER;
        return std::string{char('a' + idx / 26), char('a' + idx % 26)};
    } else if (code < RAW_BASE) {
        uint16_t idx = code - PAIR_TITLE;
        return std::string{char('A' + idx / 26), char('a' + idx % 26)};
    } else {
        return std::string{char(code - RAW_BASE)};
    }
}

std::vector<uint8_t> compress_string_trihex(const std::string& text) {
    std::vector<uint8_t> out;
    size_t i = 0, n = text.size();
    while (i < n) {
        if (i + 2 < n) {
            uint16_t code;
            if (encode_triplet(text[i], text[i+1], text[i+2], code)) {
                out.push_back(uint8_t(code >> 8));
                out.push_back(uint8_t(code & 0xFF));
                i += 3;
                continue;
            }
        }
        if (i + 1 < n) {
            char a = text[i], b = text[i+1];
            if (std::islower(a) && std::islower(b)) {
                uint16_t code = PAIR_LOWER + (a - 'a') * 26 + (b - 'a');
                out.push_back(uint8_t(code >> 8));
                out.push_back(uint8_t(code & 0xFF));
                i += 2;
                continue;
            } else if (std::isupper(a) && std::islower(b)) {
                uint16_t code = PAIR_TITLE + (a - 'A') * 26 + (b - 'a');
                out.push_back(uint8_t(code >> 8));
                out.push_back(uint8_t(code & 0xFF));
                i += 2;
                continue;
            }
        }
        uint16_t code = RAW_BASE + (uint8_t)text[i];
        out.push_back(uint8_t(code >> 8));
        out.push_back(uint8_t(code & 0xFF));
        i++;
    }
    return out;
}

std::string decompress_string_trihex(const uint8_t* data, size_t len) {
    std::string res;
    for (size_t i = 0; i + 1 < len; i += 2) {
        uint16_t code = (uint16_t(data[i]) << 8) | data[i+1];
        res += decode_code(code);
    }
    return res;
}

struct Constant {
    enum Type { TYPE_STR = 1, TYPE_INT = 2, TYPE_FLOAT = 3, TYPE_BOOL = 4, TYPE_TRIHEX = 5 } type;
    std::string str_val;
    int64_t int_val = 0;
    double float_val = 0.0;
    bool bool_val = false;

    std::string as_string() const {
        if (type == TYPE_STR || type == TYPE_TRIHEX) return str_val;
        if (type == TYPE_INT) return std::to_string(int_val);
        if (type == TYPE_FLOAT) return std::to_string(float_val);
        if (type == TYPE_BOOL) return bool_val ? "true" : "false";
        return "";
    }
};

class ConstantPool {
public:
    std::vector<Constant> constants;
    std::unordered_map<std::string, uint32_t> lookup;

    uint32_t add_str(const std::string& s) {
        if (lookup.count(s)) return lookup[s];
        uint32_t idx = (uint32_t)constants.size();
        Constant c;
        c.type = Constant::TYPE_STR;
        c.str_val = s;
        constants.push_back(c);
        lookup[s] = idx;
        return idx;
    }

    uint32_t add_int(int64_t val) {
        std::string k = "int:" + std::to_string(val);
        if (lookup.count(k)) return lookup[k];
        uint32_t idx = (uint32_t)constants.size();
        Constant c;
        c.type = Constant::TYPE_INT;
        c.int_val = val;
        constants.push_back(c);
        lookup[k] = idx;
        return idx;
    }

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        uint32_t count = (uint32_t)constants.size();
        out.push_back(uint8_t((count >> 24) & 0xFF));
        out.push_back(uint8_t((count >> 16) & 0xFF));
        out.push_back(uint8_t((count >> 8) & 0xFF));
        out.push_back(uint8_t(count & 0xFF));

        for (const auto& c : constants) {
            if (c.type == Constant::TYPE_STR) {
                auto trihex = compress_string_trihex(c.str_val);
                if (trihex.size() < c.str_val.size()) {
                    out.push_back(5);
                    uint32_t len = (uint32_t)trihex.size();
                    out.push_back(uint8_t((len >> 24) & 0xFF));
                    out.push_back(uint8_t((len >> 16) & 0xFF));
                    out.push_back(uint8_t((len >> 8) & 0xFF));
                    out.push_back(uint8_t(len & 0xFF));
                    out.insert(out.end(), trihex.begin(), trihex.end());
                } else {
                    out.push_back(1);
                    uint32_t len = (uint32_t)c.str_val.size();
                    out.push_back(uint8_t((len >> 24) & 0xFF));
                    out.push_back(uint8_t((len >> 16) & 0xFF));
                    out.push_back(uint8_t((len >> 8) & 0xFF));
                    out.push_back(uint8_t(len & 0xFF));
                    out.insert(out.end(), c.str_val.begin(), c.str_val.end());
                }
            } else if (c.type == Constant::TYPE_INT) {
                out.push_back(2);
                out.push_back(0); out.push_back(0); out.push_back(0); out.push_back(8);
                for (int i = 7; i >= 0; i--) {
                    out.push_back(uint8_t((c.int_val >> (i * 8)) & 0xFF));
                }
            } else {
                out.push_back(1);
                out.push_back(0); out.push_back(0); out.push_back(0); out.push_back(0);
            }
        }
        return out;
    }

    static ConstantPool deserialize(const uint8_t* data, size_t& offset, size_t total_len) {
        ConstantPool pool;
        if (offset + 4 > total_len) return pool;
        uint32_t count = (uint32_t(data[offset]) << 24) |
                         (uint32_t(data[offset + 1]) << 16) |
                         (uint32_t(data[offset + 2]) << 8) |
                         uint32_t(data[offset + 3]);
        offset += 4;

        for (uint32_t i = 0; i < count && offset < total_len; i++) {
            uint8_t ctype = data[offset++];
            if (offset + 4 > total_len) break;
            uint32_t clen = (uint32_t(data[offset]) << 24) |
                            (uint32_t(data[offset+1]) << 16) |
                            (uint32_t(data[offset+2]) << 8) |
                            uint32_t(data[offset+3]);
            offset += 4;
            Constant c;
            if (ctype == 1) {
                c.type = Constant::TYPE_STR;
                c.str_val = std::string((char*)&data[offset], clen);
            } else if (ctype == 5) {
                c.type = Constant::TYPE_STR;
                c.str_val = decompress_string_trihex(&data[offset], clen);
            } else if (ctype == 2) {
                c.type = Constant::TYPE_INT;
                int64_t val = 0;
                for (size_t b = 0; b < clen && b < 8; b++) {
                    val = (val << 8) | data[offset + b];
                }
                c.int_val = val;
            } else {
                c.type = Constant::TYPE_STR;
                c.str_val = std::string((char*)&data[offset], clen);
            }
            offset += clen;
            pool.constants.push_back(c);
        }
        return pool;
    }
};

class Compiler {
public:
    ConstantPool constants;
    std::vector<uint8_t> code;
    std::unordered_map<std::string, uint32_t> labels;
    std::vector<std::pair<size_t, std::string>> jump_fixups;
    std::unordered_map<std::string, uint8_t> var_slots;

    static std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, (last - first + 1));
    }

    uint8_t get_var_slot(std::string name) {
        name = trim(name);
        if (name.empty()) return 0;
        if (var_slots.count(name)) return var_slots[name];
        uint8_t slot = (uint8_t)var_slots.size();
        var_slots[name] = slot;
        return slot;
    }

    static std::vector<std::string> split_yeru_args(const std::string& body, size_t max_args = 0) {
        std::vector<std::string> args;
        size_t i = 0, n = body.size();
        while (i < n) {
            while (i < n && (body[i] == ' ' || body[i] == '\t')) i++;
            if (i >= n) break;
            if (max_args > 0 && args.size() + 1 == max_args) {
                std::string rem = trim(body.substr(i));
                while (!rem.empty() && rem.front() == '_') rem.erase(rem.begin());
                rem = trim(rem);
                if (!rem.empty()) args.push_back(rem);
                break;
            }
            if (body[i] == '"') {
                size_t end_q = body.find('"', i + 1);
                if (end_q == std::string::npos) {
                    args.push_back(body.substr(i));
                    break;
                }
                args.push_back(body.substr(i, end_q - i + 1));
                i = end_q + 1;
                if (i < n && (body[i] == '_' || body[i] == ' ' || body[i] == '\t')) i++;
            } else {
                size_t start = i;
                while (i < n && body[i] != '"' && body[i] != '_' && body[i] != ' ' && body[i] != '\t') {
                    i++;
                }
                std::string s = body.substr(start, i - start);
                s = trim(s);
                if (!s.empty()) args.push_back(s);
                if (i < n && (body[i] == '_' || body[i] == ' ' || body[i] == '\t')) i++;
            }
        }
        return args;
    }

    void emit_expression(const std::string& expr) {
        std::string s = expr;
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.pop_back();

        if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
            std::string unesc;
            for (size_t i = 1; i + 1 < s.size(); i++) {
                if (s[i] == '\\' && i + 2 < s.size()) {
                    if (s[i+1] == 'n') { unesc += '\n'; i++; }
                    else if (s[i+1] == 't') { unesc += '\t'; i++; }
                    else if (s[i+1] == '"') { unesc += '"'; i++; }
                    else if (s[i+1] == '\\') { unesc += '\\'; i++; }
                    else { unesc += s[i+1]; i++; }
                } else {
                    unesc += s[i];
                }
            }
            uint32_t idx = constants.add_str(unesc);
            code.push_back(OP_LOAD_CONST);
            code.push_back(uint8_t((idx >> 24) & 0xFF));
            code.push_back(uint8_t((idx >> 16) & 0xFF));
            code.push_back(uint8_t((idx >> 8) & 0xFF));
            code.push_back(uint8_t(idx & 0xFF));
            return;
        }

        bool is_int = !s.empty();
        size_t start = (s[0] == '-' || s[0] == '+') ? 1 : 0;
        if (start == 1 && s.size() == 1) is_int = false;
        for (size_t i = start; i < s.size(); i++) {
            if (!std::isdigit(s[i])) { is_int = false; break; }
        }
        if (is_int) {
            int64_t v = std::stoll(s);
            uint32_t idx = constants.add_int(v);
            code.push_back(OP_LOAD_CONST);
            code.push_back(uint8_t((idx >> 24) & 0xFF));
            code.push_back(uint8_t((idx >> 16) & 0xFF));
            code.push_back(uint8_t((idx >> 8) & 0xFF));
            code.push_back(uint8_t(idx & 0xFF));
            return;
        }

        if (var_slots.count(s)) {
            code.push_back(OP_LOAD_VAR);
            code.push_back(var_slots[s]);
        } else {
            uint32_t idx = constants.add_str(s);
            code.push_back(OP_LOAD_CONST);
            code.push_back(uint8_t((idx >> 24) & 0xFF));
            code.push_back(uint8_t((idx >> 16) & 0xFF));
            code.push_back(uint8_t((idx >> 8) & 0xFF));
            code.push_back(uint8_t(idx & 0xFF));
        }
    }

    struct ParsedItem {
        bool is_label;
        int indent;
        std::string text;
    };

    size_t compile_item(const std::vector<ParsedItem>& items, size_t cur) {
        int indent = items[cur].indent;
        std::string cmd = items[cur].text;

        if (cmd.rfind("prt_", 0) == 0) {
            emit_expression(cmd.substr(4));
            code.push_back(OP_PRINT);
            return cur + 1;
        }

        if (cmd.find("_inp_") != std::string::npos) {
            size_t p = cmd.find("_inp_");
            std::string var = cmd.substr(0, p);
            std::string prompt = cmd.substr(p + 5);
            emit_expression(prompt);
            code.push_back(OP_INPUT);
            uint8_t slot = get_var_slot(var);
            code.push_back(OP_STORE_VAR);
            code.push_back(slot);
            return cur + 1;
        }

        if (cmd.rfind("if_", 0) == 0) {
            std::string rest = cmd.substr(3);
            bool is_neq = false;
            std::string vname, val_part;
            if (rest.find("!=") != std::string::npos) {
                is_neq = true;
                size_t p = rest.find("!=");
                vname = rest.substr(0, p);
                val_part = rest.substr(p + 2);
            } else if (rest.find("==") != std::string::npos) {
                is_neq = false;
                size_t p = rest.find("==");
                vname = rest.substr(0, p);
                val_part = rest.substr(p + 2);
            } else if (rest.find("__") != std::string::npos) {
                is_neq = true;
                size_t p = rest.find("__");
                vname = rest.substr(0, p);
                val_part = rest.substr(p + 2);
            } else if (rest.find("_") != std::string::npos) {
                is_neq = false;
                size_t p = rest.find("_");
                vname = rest.substr(0, p);
                val_part = rest.substr(p + 1);
            }
            uint8_t slot = get_var_slot(vname);
            code.push_back(OP_LOAD_VAR);
            code.push_back(slot);
            emit_expression(val_part);
            code.push_back(is_neq ? OP_NEQ : OP_EQ);

            code.push_back(OP_JUMP_IF_FALSE);
            size_t fixup = code.size();
            code.push_back(0); code.push_back(0); code.push_back(0); code.push_back(0);

            size_t child = cur + 1;
            while (child < items.size()) {
                if (items[child].is_label) break;
                if (items[child].indent > indent) {
                    child = compile_item(items, child);
                } else break;
            }

            uint32_t end_target = (uint32_t)code.size();
            code[fixup] = uint8_t((end_target >> 24) & 0xFF);
            code[fixup + 1] = uint8_t((end_target >> 16) & 0xFF);
            code[fixup + 2] = uint8_t((end_target >> 8) & 0xFF);
            code[fixup + 3] = uint8_t(end_target & 0xFF);
            return child;
        }

        if (cmd.find('=') != std::string::npos) {
            size_t eq = cmd.find('=');
            std::string vname = cmd.substr(0, eq);
            std::string val = cmd.substr(eq + 1);
            vname = trim(vname);
            emit_expression(val);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(vname));
            return cur + 1;
        }

        if (cmd.rfind("npkt_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5));
            emit_expression(args.size() > 0 ? args[0] : "\"\"");
            emit_expression(args.size() > 1 ? args[1] : "\"\"");
            code.push_back(OP_NPKT);
            return cur + 1;
        }

        if (cmd.rfind("run_", 0) == 0) {
            emit_expression(cmd.substr(4));
            code.push_back(OP_RUN);
            return cur + 1;
        }

        if (cmd == "cls") {
            code.push_back(OP_CLS);
            return cur + 1;
        }

        if (cmd.rfind("kinp_", 0) == 0) {
            emit_expression(cmd.substr(5));
            code.push_back(OP_KINP);

            code.push_back(OP_JUMP_IF_FALSE);
            size_t fixup = code.size();
            code.push_back(0); code.push_back(0); code.push_back(0); code.push_back(0);

            size_t child = cur + 1;
            while (child < items.size()) {
                if (items[child].is_label) break;
                if (items[child].indent > indent) {
                    child = compile_item(items, child);
                } else break;
            }
            uint32_t end_target = (uint32_t)code.size();
            code[fixup] = uint8_t((end_target >> 24) & 0xFF);
            code[fixup + 1] = uint8_t((end_target >> 16) & 0xFF);
            code[fixup + 2] = uint8_t((end_target >> 8) & 0xFF);
            code[fixup + 3] = uint8_t(end_target & 0xFF);
            return child;
        }

        if (cmd.rfind("stvl_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5));
            emit_expression(args.size() > 1 ? args[1] : "\"\"");
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args[0]));
            return cur + 1;
        }

        if (cmd.rfind("advl_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5));
            uint8_t slot = get_var_slot(args[0]);
            code.push_back(OP_LOAD_VAR);
            code.push_back(slot);
            emit_expression(args.size() > 1 ? args[1] : "\"\"");
            code.push_back(OP_ADVL);
            code.push_back(OP_STORE_VAR);
            code.push_back(slot);
            return cur + 1;
        }

        if (cmd.rfind("mkfl_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5));
            emit_expression(args.size() > 0 ? args[0] : "\"\"");
            emit_expression(args.size() > 1 ? args[1] : "\"\"");
            code.push_back(OP_MKFL);
            return cur + 1;
        }

        if (cmd.rfind("mkdr_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5));
            emit_expression(args.size() > 0 ? args[0] : "\"\"");
            code.push_back(OP_MKDR);
            return cur + 1;
        }

        if (cmd.rfind("chfl_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5));
            emit_expression(args[0]);
            if (args.size() == 2) {
                emit_expression("0");
                emit_expression(args[1]);
            } else {
                emit_expression(args[1]);
                emit_expression(args[2]);
            }
            code.push_back(OP_CHFL);
            return cur + 1;
        }

        if (cmd.rfind("rpfl_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5));
            emit_expression(args[0]);
            emit_expression(args[1]);
            emit_expression(args[2]);
            code.push_back(OP_RPFL);
            return cur + 1;
        }

        if (cmd.rfind("rdfl_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5));
            std::string filename = args.size() > 0 ? args[0] : "\"\"";
            std::string line_expr = "0";
            std::string var_name = "";
            if (args.size() == 2) {
                line_expr = "0";
                var_name = args[1];
            } else if (args.size() >= 3) {
                line_expr = args[1];
                var_name = args[2];
            }
            emit_expression(filename);
            emit_expression(line_expr);
            uint8_t slot = get_var_slot(var_name);
            code.push_back(OP_RDFL);
            code.push_back(slot);
            return cur + 1;
        }

        if (cmd.rfind("cprt_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5));
            emit_expression(args.size() > 0 ? args[0] : "\"\"");
            emit_expression(args.size() > 1 ? args[1] : "\"\"");
            code.push_back(OP_CPRT);
            return cur + 1;
        }

        if (cmd.rfind("wait_", 0) == 0) {
            emit_expression(cmd.substr(5));
            code.push_back(OP_WAIT);
            return cur + 1;
        }

        if (cmd.rfind("jmp_", 0) == 0) {
            std::string target = cmd.substr(4);
            code.push_back(OP_JUMP);
            jump_fixups.push_back({code.size(), target});
            code.push_back(0); code.push_back(0); code.push_back(0); code.push_back(0);
            return cur + 1;
        }

        if (cmd.rfind("ram_free_", 0) == 0) {
            std::string var = cmd.substr(9);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_RAMFREE);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("ram_total_", 0) == 0) {
            std::string var = cmd.substr(10);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_RAMTOTAL);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("ram_proc_", 0) == 0) {
            std::string var = cmd.substr(9);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_RAMPROC);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("cpu_usage_", 0) == 0) {
            std::string var = cmd.substr(10);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_CPUUSAGE);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("cpu_cores_", 0) == 0) {
            std::string var = cmd.substr(10);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_CPUCORES);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("time_us_", 0) == 0) {
            std::string var = cmd.substr(8);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_TIMEUS);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("time_ms_", 0) == 0) {
            std::string var = cmd.substr(8);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_TIMEMS);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("time_now_", 0) == 0) {
            std::string var = cmd.substr(9);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_TIMENOW);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("sleep_ms_", 0) == 0) {
            emit_expression(cmd.substr(9));
            code.push_back(OP_SLEEPMS);
            return cur + 1;
        }
        if (cmd.rfind("argv_len_", 0) == 0) {
            std::string var = cmd.substr(9);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_ARGVLEN);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("argv_get_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(9), 2);
            emit_expression(args.size() > 0 ? args[0] : "0");
            code.push_back(OP_ARGVGET);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }
        if (cmd.rfind("env_get_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(8), 2);
            emit_expression(args.size() > 0 ? args[0] : "\"\"");
            code.push_back(OP_ENVGET);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }
        if (cmd.rfind("env_set_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(8), 2);
            emit_expression(args.size() > 0 ? args[0] : "\"\"");
            emit_expression(args.size() > 1 ? args[1] : "\"\"");
            code.push_back(OP_ENVSET);
            return cur + 1;
        }
        if (cmd.rfind("exit_", 0) == 0) {
            emit_expression(cmd.substr(5));
            code.push_back(OP_EXIT);
            return cur + 1;
        }
        if (cmd.rfind("exec_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 2);
            emit_expression(args.size() > 0 ? args[0] : "\"\"");
            code.push_back(OP_EXEC);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }

        if (cmd.rfind("inkey_", 0) == 0) {
            std::string var = cmd.substr(6);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_INKEY);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("keydown_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(8), 2);
            emit_expression(args.size() > 0 ? args[0] : "\"\"");
            code.push_back(OP_KEYDOWN);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }
        if (cmd.rfind("keyup_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(6), 2);
            emit_expression(args.size() > 0 ? args[0] : "\"\"");
            code.push_back(OP_KEYUP);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }
        if (cmd.rfind("key_mod_", 0) == 0) {
            std::string var = cmd.substr(8);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_KEYMOD);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("mouse_x_", 0) == 0) {
            std::string var = cmd.substr(8);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_MOUSEX);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("mouse_y_", 0) == 0) {
            std::string var = cmd.substr(8);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_MOUSEY);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("mouse_btn_", 0) == 0) {
            std::string var = cmd.substr(10);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_MOUSEBTN);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("mouse_wheel_", 0) == 0) {
            std::string var = cmd.substr(12);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_MOUSEWHEEL);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("term_w_", 0) == 0) {
            std::string var = cmd.substr(7);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_TERMW);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("term_h_", 0) == 0) {
            std::string var = cmd.substr(7);
            while (!var.empty() && var.back() == ' ') var.pop_back();
            code.push_back(OP_TERMH);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(var));
            return cur + 1;
        }
        if (cmd.rfind("curpos_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(7), 2);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "0");
            code.push_back(OP_CURPOS);
            return cur + 1;
        }
        if (cmd == "cursor_hide") {
            code.push_back(OP_CURHIDE);
            return cur + 1;
        }
        if (cmd == "cursor_show") {
            code.push_back(OP_CURSHOW);
            return cur + 1;
        }
        if (cmd.rfind("term_alt_screen_", 0) == 0) {
            emit_expression(cmd.substr(16));
            code.push_back(OP_TERMALTSCR);
            return cur + 1;
        }

        if (cmd.rfind("sub_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(4), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "0");
            code.push_back(OP_SUB);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("mul_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(4), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "0");
            code.push_back(OP_MUL);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("div_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(4), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "1");
            code.push_back(OP_DIV);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("mod_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(4), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "1");
            code.push_back(OP_MOD);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("pow_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(4), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "0");
            code.push_back(OP_POW);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("band_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "0");
            code.push_back(OP_BAND);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("bor_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(4), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "0");
            code.push_back(OP_BOR);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("bxor_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "0");
            code.push_back(OP_BXOR);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("bnot_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 2);
            emit_expression(args.size() > 0 ? args[0] : "0");
            code.push_back(OP_BNOT);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("bshl_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "0");
            code.push_back(OP_BSHL);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("bshr_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "0");
            code.push_back(OP_BSHR);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("brol_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "0");
            code.push_back(OP_BROL);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("bror_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "0");
            code.push_back(OP_BROR);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("rand_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "100");
            code.push_back(OP_RAND);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("sqrt_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 2);
            emit_expression(args.size() > 0 ? args[0] : "0");
            code.push_back(OP_SQRT);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("abs_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(4), 2);
            emit_expression(args.size() > 0 ? args[0] : "0");
            code.push_back(OP_ABS);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("sin_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(4), 2);
            emit_expression(args.size() > 0 ? args[0] : "0");
            code.push_back(OP_SIN);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("cos_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(4), 2);
            emit_expression(args.size() > 0 ? args[0] : "0");
            code.push_back(OP_COS);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }
        if (cmd.rfind("atan2_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(6), 3);
            emit_expression(args.size() > 0 ? args[0] : "0");
            emit_expression(args.size() > 1 ? args[1] : "0");
            code.push_back(OP_ATAN2);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : (args.size() > 0 ? args[0] : "")));
            return cur + 1;
        }

        if (cmd.rfind("slen_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 2);
            emit_expression(args.size() > 0 ? args[0] : "");
            code.push_back(OP_SLEN);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }
        if (cmd.rfind("ssub_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 4);
            emit_expression(args.size() > 0 ? args[0] : "");
            emit_expression(args.size() > 1 ? args[1] : "0");
            emit_expression(args.size() > 2 ? args[2] : "-1");
            code.push_back(OP_SSUB);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 3 ? args[3] : ""));
            return cur + 1;
        }
        if (cmd.rfind("sfind_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(6), 3);
            emit_expression(args.size() > 0 ? args[0] : "");
            emit_expression(args.size() > 1 ? args[1] : "");
            code.push_back(OP_SFIND);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 2 ? args[2] : ""));
            return cur + 1;
        }
        if (cmd.rfind("srep_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 4);
            emit_expression(args.size() > 0 ? args[0] : "");
            emit_expression(args.size() > 1 ? args[1] : "");
            emit_expression(args.size() > 2 ? args[2] : "");
            code.push_back(OP_SREP);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 3 ? args[3] : ""));
            return cur + 1;
        }
        if (cmd.rfind("supper_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(7), 2);
            emit_expression(args.size() > 0 ? args[0] : "");
            code.push_back(OP_SUPPER);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }
        if (cmd.rfind("slower_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(7), 2);
            emit_expression(args.size() > 0 ? args[0] : "");
            code.push_back(OP_SLOWER);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }
        if (cmd.rfind("strim_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(6), 2);
            emit_expression(args.size() > 0 ? args[0] : "");
            code.push_back(OP_STRIM);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }
        if (cmd.rfind("ord_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(4), 2);
            emit_expression(args.size() > 0 ? args[0] : "");
            code.push_back(OP_ORD);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }
        if (cmd.rfind("chr_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(4), 2);
            emit_expression(args.size() > 0 ? args[0] : "0");
            code.push_back(OP_CHR);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }

        if (cmd.rfind("call_", 0) == 0) {
            std::string target = cmd.substr(5);
            code.push_back(OP_CALL);
            jump_fixups.push_back({code.size(), target});
            code.push_back(0); code.push_back(0); code.push_back(0); code.push_back(0);
            return cur + 1;
        }
        if (cmd == "ret") {
            code.push_back(OP_RET);
            return cur + 1;
        }

        if (cmd.rfind("fl_exists_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(10), 2);
            emit_expression(args.size() > 0 ? args[0] : "");
            code.push_back(OP_FLEXISTS);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }
        if (cmd.rfind("fl_size_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(8), 2);
            emit_expression(args.size() > 0 ? args[0] : "");
            code.push_back(OP_FLSIZE);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }
        if (cmd.rfind("fl_read_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(8), 2);
            emit_expression(args.size() > 0 ? args[0] : "");
            code.push_back(OP_FLREAD);
            code.push_back(OP_STORE_VAR);
            code.push_back(get_var_slot(args.size() > 1 ? args[1] : ""));
            return cur + 1;
        }
        if (cmd.rfind("fl_write_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(9), 2);
            emit_expression(args.size() > 0 ? args[0] : "");
            emit_expression(args.size() > 1 ? args[1] : "");
            code.push_back(OP_FLWRITE);
            return cur + 1;
        }
        if (cmd.rfind("fl_append_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(10), 2);
            emit_expression(args.size() > 0 ? args[0] : "");
            emit_expression(args.size() > 1 ? args[1] : "");
            code.push_back(OP_FLAPPEND);
            return cur + 1;
        }
        if (cmd.rfind("fl_del_", 0) == 0) {
            emit_expression(cmd.substr(7));
            code.push_back(OP_FLDEL);
            return cur + 1;
        }
        if (cmd.rfind("dir_make_", 0) == 0) {
            emit_expression(cmd.substr(9));
            code.push_back(OP_DIRMAKE);
            return cur + 1;
        }

        if (cmd.rfind("beep_", 0) == 0) {
            auto args = split_yeru_args(cmd.substr(5), 2);
            emit_expression(args.size() > 0 ? args[0] : "800");
            emit_expression(args.size() > 1 ? args[1] : "100");
            code.push_back(OP_BEEP);
            return cur + 1;
        }
        if (cmd.rfind("sfx_play_", 0) == 0) {
            emit_expression(cmd.substr(9));
            code.push_back(OP_SFXPLAY);
            return cur + 1;
        }
        if (cmd == "sfx_stop") {
            code.push_back(OP_SFXSTOP);
            return cur + 1;
            return cur + 1;
        }

        return cur + 1;
    }

    std::vector<uint8_t> compile_source(const std::string& source) {
        std::istringstream stream(source);
        std::string line;
        std::vector<ParsedItem> items;

        while (std::getline(stream, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
            size_t start = 0;
            while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) start++;
            if (start >= line.size()) continue;
            std::string trimmed = line.substr(start);
            if (trimmed[0] == '#' || trimmed.rfind("//", 0) == 0) continue;

            if (trimmed[0] == ':') {
                items.push_back({true, 0, trimmed.substr(1)});
                continue;
            }

            int dashes = 0;
            while (dashes < (int)trimmed.size() && trimmed[dashes] == '-') dashes++;
            if (dashes == 0) continue;
            std::string cmd = trimmed.substr(dashes);
            while (!cmd.empty() && cmd.front() == ' ') cmd.erase(cmd.begin());
            items.push_back({false, dashes, cmd});

            if (cmd.rfind("if_", 0) == 0) {
                std::string rest = cmd.substr(3);
                std::string vname;
                if (rest.find("!=") != std::string::npos) vname = rest.substr(0, rest.find("!="));
                else if (rest.find("==") != std::string::npos) vname = rest.substr(0, rest.find("=="));
                else if (rest.find("__") != std::string::npos) vname = rest.substr(0, rest.find("__"));
                else if (rest.find("_") != std::string::npos) vname = rest.substr(0, rest.find("_"));
                while (!vname.empty() && (vname.back() == ' ' || vname.back() == '\t')) vname.pop_back();
                while (!vname.empty() && (vname.front() == ' ' || vname.front() == '\t')) vname.erase(vname.begin());
                if (!vname.empty()) get_var_slot(vname);
            } else if (cmd.find('=') != std::string::npos) {
                std::string v = cmd.substr(0, cmd.find('='));
                while (!v.empty() && v.back() == ' ') v.pop_back();
                if (!v.empty()) get_var_slot(v);
            } else if (cmd.rfind("rdfl_", 0) == 0) {
                auto rargs = split_yeru_args(cmd.substr(5));
                if (rargs.size() == 2) get_var_slot(rargs[1]);
                else if (rargs.size() >= 3) get_var_slot(rargs[2]);
            } else if (cmd.find("_inp_") != std::string::npos) {
                std::string v = cmd.substr(0, cmd.find("_inp_"));
                while (!v.empty() && v.back() == ' ') v.pop_back();
                if (!v.empty()) get_var_slot(v);
            } else if (cmd.rfind("stvl_", 0) == 0) {
                auto sargs = split_yeru_args(cmd.substr(5));
                if (!sargs.empty()) get_var_slot(sargs[0]);
            }
            else if (cmd.rfind("ram_free_", 0) == 0) { get_var_slot(cmd.substr(9)); }
            else if (cmd.rfind("ram_total_", 0) == 0) { get_var_slot(cmd.substr(10)); }
            else if (cmd.rfind("ram_proc_", 0) == 0) { get_var_slot(cmd.substr(9)); }
            else if (cmd.rfind("cpu_usage_", 0) == 0) { get_var_slot(cmd.substr(10)); }
            else if (cmd.rfind("cpu_cores_", 0) == 0) { get_var_slot(cmd.substr(10)); }
            else if (cmd.rfind("time_us_", 0) == 0) { get_var_slot(cmd.substr(8)); }
            else if (cmd.rfind("time_ms_", 0) == 0) { get_var_slot(cmd.substr(8)); }
            else if (cmd.rfind("time_now_", 0) == 0) { get_var_slot(cmd.substr(9)); }
            else if (cmd.rfind("argv_len_", 0) == 0) { get_var_slot(cmd.substr(9)); }
            else if (cmd.rfind("argv_get_", 0) == 0) { auto a = split_yeru_args(cmd.substr(9), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("env_get_", 0) == 0) { auto a = split_yeru_args(cmd.substr(8), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("exec_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("inkey_", 0) == 0) { get_var_slot(cmd.substr(6)); }
            else if (cmd.rfind("keydown_", 0) == 0) { auto a = split_yeru_args(cmd.substr(8), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("keyup_", 0) == 0) { auto a = split_yeru_args(cmd.substr(6), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("key_mod_", 0) == 0) { get_var_slot(cmd.substr(8)); }
            else if (cmd.rfind("mouse_x_", 0) == 0) { get_var_slot(cmd.substr(8)); }
            else if (cmd.rfind("mouse_y_", 0) == 0) { get_var_slot(cmd.substr(8)); }
            else if (cmd.rfind("mouse_btn_", 0) == 0) { get_var_slot(cmd.substr(10)); }
            else if (cmd.rfind("mouse_wheel_", 0) == 0) { get_var_slot(cmd.substr(12)); }
            else if (cmd.rfind("term_w_", 0) == 0) { get_var_slot(cmd.substr(7)); }
            else if (cmd.rfind("term_h_", 0) == 0) { get_var_slot(cmd.substr(7)); }
            else if (cmd.rfind("sub_", 0) == 0) { auto a = split_yeru_args(cmd.substr(4), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("mul_", 0) == 0) { auto a = split_yeru_args(cmd.substr(4), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("div_", 0) == 0) { auto a = split_yeru_args(cmd.substr(4), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("mod_", 0) == 0) { auto a = split_yeru_args(cmd.substr(4), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("pow_", 0) == 0) { auto a = split_yeru_args(cmd.substr(4), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("band_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("bor_", 0) == 0) { auto a = split_yeru_args(cmd.substr(4), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("bxor_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("bnot_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 2); if (a.size() > 1) get_var_slot(a[1]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("bshl_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("bshr_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("brol_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("bror_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("rand_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("sqrt_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 2); if (a.size() > 1) get_var_slot(a[1]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("abs_", 0) == 0) { auto a = split_yeru_args(cmd.substr(4), 2); if (a.size() > 1) get_var_slot(a[1]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("sin_", 0) == 0) { auto a = split_yeru_args(cmd.substr(4), 2); if (a.size() > 1) get_var_slot(a[1]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("cos_", 0) == 0) { auto a = split_yeru_args(cmd.substr(4), 2); if (a.size() > 1) get_var_slot(a[1]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("atan2_", 0) == 0) { auto a = split_yeru_args(cmd.substr(6), 3); if (a.size() > 2) get_var_slot(a[2]); else if (!a.empty()) get_var_slot(a[0]); }
            else if (cmd.rfind("slen_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("ssub_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 4); if (a.size() > 3) get_var_slot(a[3]); }
            else if (cmd.rfind("sfind_", 0) == 0) { auto a = split_yeru_args(cmd.substr(6), 3); if (a.size() > 2) get_var_slot(a[2]); }
            else if (cmd.rfind("srep_", 0) == 0) { auto a = split_yeru_args(cmd.substr(5), 4); if (a.size() > 3) get_var_slot(a[3]); }
            else if (cmd.rfind("supper_", 0) == 0) { auto a = split_yeru_args(cmd.substr(7), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("slower_", 0) == 0) { auto a = split_yeru_args(cmd.substr(7), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("strim_", 0) == 0) { auto a = split_yeru_args(cmd.substr(6), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("ord_", 0) == 0) { auto a = split_yeru_args(cmd.substr(4), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("chr_", 0) == 0) { auto a = split_yeru_args(cmd.substr(4), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("fl_exists_", 0) == 0) { auto a = split_yeru_args(cmd.substr(10), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("fl_size_", 0) == 0) { auto a = split_yeru_args(cmd.substr(8), 2); if (a.size() > 1) get_var_slot(a[1]); }
            else if (cmd.rfind("fl_read_", 0) == 0) { auto a = split_yeru_args(cmd.substr(8), 2); if (a.size() > 1) get_var_slot(a[1]); }
        }

        size_t idx = 0;
        while (idx < items.size()) {
            if (items[idx].is_label) {
                labels[items[idx].text] = (uint32_t)code.size();
                idx++;
            } else {
                idx = compile_item(items, idx);
            }
        }
        code.push_back(OP_HALT);

        for (const auto& fix : jump_fixups) {
            if (labels.count(fix.second)) {
                uint32_t addr = labels[fix.second];
                code[fix.first] = uint8_t((addr >> 24) & 0xFF);
                code[fix.first + 1] = uint8_t((addr >> 16) & 0xFF);
                code[fix.first + 2] = uint8_t((addr >> 8) & 0xFF);
                code[fix.first + 3] = uint8_t(addr & 0xFF);
            }
        }

        auto const_bytes = constants.serialize();
        std::vector<uint8_t> out;
        out.insert(out.end(), MAGIC_HEADER, MAGIC_HEADER + 7);
        out.insert(out.end(), const_bytes.begin(), const_bytes.end());
        uint32_t clen = (uint32_t)code.size();
        out.push_back(uint8_t((clen >> 24) & 0xFF));
        out.push_back(uint8_t((clen >> 16) & 0xFF));
        out.push_back(uint8_t((clen >> 8) & 0xFF));
        out.push_back(uint8_t(clen & 0xFF));
        out.insert(out.end(), code.begin(), code.end());
        out.insert(out.end(), MAGIC_FOOTER, MAGIC_FOOTER + 7);
        return out;
    }
};

const std::unordered_map<std::string, std::string> ANSI_COLORS = {
    {"red",     "\033[91m"},
    {"green",   "\033[92m"},
    {"yellow",  "\033[93m"},
    {"blue",    "\033[94m"},
    {"magenta", "\033[95m"},
    {"purple",  "\033[95m"},
    {"cyan",    "\033[96m"},
    {"white",   "\033[97m"},
    {"gray",    "\033[90m"},
    {"grey",    "\033[90m"},
    {"reset",   "\033[0m"}
};

inline std::string colorize_text(const std::string& text) {
    if (text.find('[') == std::string::npos) return text;
    std::string res = text;
    for (const auto& pair : ANSI_COLORS) {
        std::string tag = "[" + pair.first + "]";
        size_t pos = 0;
        while ((pos = res.find(tag, pos)) != std::string::npos) {
            res.replace(pos, tag.length(), pair.second);
            pos += pair.second.length();
        }
    }
    return res;
}

struct FrameLimiter {
    double target_fps = 0.0;
    LARGE_INTEGER freq;
    LONGLONG next_frame_ticks = 0;
    LONGLONG frame_ticks = 0;
    bool initialized = false;

    void set_fps(double fps) {
        target_fps = fps;
        if (target_fps > 0.0) {
            timeBeginPeriod(1);
            QueryPerformanceFrequency(&freq);
            frame_ticks = LONGLONG(double(freq.QuadPart) / target_fps);
            LARGE_INTEGER now;
            QueryPerformanceCounter(&now);
            next_frame_ticks = now.QuadPart + frame_ticks;
            initialized = true;
        }
    }

    ~FrameLimiter() {
        if (initialized) {
            timeEndPeriod(1);
        }
    }

    void wait_frame() {
        if (target_fps <= 0.0 || !initialized) return;
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);

        if (now.QuadPart < next_frame_ticks) {
            LONGLONG remaining_ticks = next_frame_ticks - now.QuadPart;
            double remaining_ms = (double(remaining_ticks) * 1000.0) / double(freq.QuadPart);
            if (remaining_ms > 2.0) {
                Sleep(DWORD(remaining_ms - 1.5));
            }
            do {
                QueryPerformanceCounter(&now);
            } while (now.QuadPart < next_frame_ticks);
        } else {
            if (now.QuadPart - next_frame_ticks > frame_ticks * 2) {
                next_frame_ticks = now.QuadPart;
            }
        }
        next_frame_ticks += frame_ticks;
    }
};

class VirtualMachine {
public:
    std::vector<uint8_t> raw_data;
    ConstantPool constants;
    std::vector<uint8_t> code;
    size_t ip = 0;
    std::vector<std::string> stack;
    std::unordered_map<uint8_t, std::string> registers;
    FrameLimiter limiter;
    bool first_cls = true;
    std::vector<size_t> call_stack;
    static inline std::vector<std::string> cli_args;

    VirtualMachine(const std::vector<uint8_t>& binary, double fps = 0.0) : raw_data(binary) {
        limiter.set_fps(fps);
        load_binary();
    }

    void load_binary() {
        if (raw_data.size() < 18) {
            std::cerr << "ERR - binary too small\n";
            exit(1);
        }
        if (std::memcmp(raw_data.data(), MAGIC_HEADER, 7) != 0) {
            std::cerr << "ERR - invalid magic header\n";
            exit(1);
        }
        if (std::memcmp(raw_data.data() + raw_data.size() - 7, MAGIC_FOOTER, 7) != 0) {
            std::cerr << "ERR - invalid magic footer\n";
            exit(1);
        }

        size_t offset = 7;
        constants = ConstantPool::deserialize(raw_data.data(), offset, raw_data.size() - 7);
        if (offset + 4 > raw_data.size() - 7) return;

        uint32_t clen = (uint32_t(raw_data[offset]) << 24) |
                        (uint32_t(raw_data[offset+1]) << 16) |
                        (uint32_t(raw_data[offset+2]) << 8) |
                        uint32_t(raw_data[offset+3]);
        offset += 4;
        code.assign(raw_data.begin() + offset, raw_data.begin() + offset + clen);
    }

    static int64_t to_int(const std::string& s, int64_t default_val = 0) {
        if (s.empty()) return default_val;
        try {
            size_t idx = 0;
            return std::stoll(s, &idx);
        } catch (...) {
            return default_val;
        }
    }

    static uint32_t to_uint(const std::string& s, uint32_t default_val = 0) {
        if (s.empty()) return default_val;
        try {
            size_t idx = 0;
            return (uint32_t)std::stoul(s, &idx);
        } catch (...) {
            return default_val;
        }
    }

    static double to_double(const std::string& s, double default_val = 0.0) {
        if (s.empty()) return default_val;
        try {
            size_t idx = 0;
            return std::stod(s, &idx);
        } catch (...) {
            return default_val;
        }
    }

    static int get_vk_code(const std::string& k) {
        std::string s = k;
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"') s = s.substr(1, s.size() - 2);
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        if (s == "space") return VK_SPACE;
        if (s == "enter" || s == "return") return VK_RETURN;
        if (s == "esc" || s == "escape") return VK_ESCAPE;
        if (s == "up") return VK_UP;
        if (s == "down") return VK_DOWN;
        if (s == "left") return VK_LEFT;
        if (s == "right") return VK_RIGHT;
        if (s == "tab") return VK_TAB;
        if (s == "shift") return VK_SHIFT;
        if (s == "ctrl") return VK_CONTROL;
        if (s.size() == 1) return std::toupper(s[0]);
        bool is_num = true;
        for (char c : s) if (!std::isdigit(c)) is_num = false;
        if (is_num && !s.empty()) return std::stoi(s);
        return 0;
    }

    void execute_subprogram(const std::string& target) {
        std::string resolved = "";
        if (fs::is_regular_file(target)) {
            resolved = target;
        } else if (fs::is_directory(target)) {
            std::vector<std::string> cands = {
                (fs::path(target) / "main.yeru").string(),
                (fs::path(target) / "main.yu").string(),
                (fs::path(target) / "index.yeru").string(),
                (fs::path(target) / "index.yu").string()
            };
            for (const auto& c : cands) {
                if (fs::is_regular_file(c)) { resolved = c; break; }
            }
            if (resolved.empty()) {
                for (const auto& entry : fs::directory_iterator(target)) {
                    std::string p = entry.path().string();
                    if (p.rfind(".yeru") != std::string::npos || p.rfind(".yu") != std::string::npos) {
                        execute_subprogram(p);
                    }
                }
                return;
            }
        } else {
            if (fs::is_regular_file(target + ".yeru")) resolved = target + ".yeru";
            else if (fs::is_regular_file(target + ".yu")) resolved = target + ".yu";
        }

        if (resolved.empty() || !fs::is_regular_file(resolved)) {
            std::cout << "ERR - run_command failed, " << target << " doesnt exist.\n";
            return;
        }

        std::vector<uint8_t> bin;
        if (resolved.rfind(".yeru") != std::string::npos) {
            std::ifstream f(resolved);
            std::string src((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            Compiler comp;
            bin = comp.compile_source(src);
        } else {
            std::ifstream f(resolved, std::ios::binary);
            bin.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        }

        VirtualMachine sub_vm(bin, this->limiter.target_fps);
        sub_vm.registers = this->registers;
        sub_vm.run();
        this->registers = sub_vm.registers;
    }

    void run() {
        while (ip < code.size()) {
            uint8_t op = code[ip++];
            if (op == OP_HALT) break;

            else if (op == OP_LOAD_CONST) {
                uint32_t idx = (uint32_t(code[ip]) << 24) |
                               (uint32_t(code[ip+1]) << 16) |
                               (uint32_t(code[ip+2]) << 8) |
                               uint32_t(code[ip+3]);
                ip += 4;
                stack.push_back(constants.constants[idx].as_string());
            }
            else if (op == OP_LOAD_VAR) {
                uint8_t slot = code[ip++];
                stack.push_back(registers[slot]);
            }
            else if (op == OP_STORE_VAR) {
                uint8_t slot = code[ip++];
                std::string v = stack.empty() ? "" : stack.back();
                if (!stack.empty()) stack.pop_back();
                registers[slot] = v;
            }
            else if (op == OP_PRINT) {
                std::string v = stack.empty() ? "" : stack.back();
                if (!stack.empty()) stack.pop_back();
                if (v.find('[') == std::string::npos) {
                    std::cout.write(v.data(), v.size());
                    std::cout.put('\n');
                } else {
                    std::string c = colorize_text(v);
                    std::cout.write(c.data(), c.size());
                    std::cout.put('\n');
                }
            }
            else if (op == OP_INPUT) {
                std::string prompt = stack.empty() ? "" : stack.back();
                if (!stack.empty()) stack.pop_back();
                std::cout << prompt;
                if (!prompt.empty() && prompt.back() != ' ') std::cout << " ";
                std::string line;
                if (!std::getline(std::cin, line)) exit(0);
                stack.push_back(line);
            }
            else if (op == OP_EQ) {
                std::string b = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                stack.push_back(a == b ? "1" : "0");
            }
            else if (op == OP_NEQ) {
                std::string b = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                stack.push_back(a != b ? "1" : "0");
            }
            else if (op == OP_JUMP) {
                uint32_t target = (uint32_t(code[ip]) << 24) |
                                  (uint32_t(code[ip+1]) << 16) |
                                  (uint32_t(code[ip+2]) << 8) |
                                  uint32_t(code[ip+3]);
                ip = target;
            }
            else if (op == OP_JUMP_IF_FALSE) {
                uint32_t target = (uint32_t(code[ip]) << 24) |
                                  (uint32_t(code[ip+1]) << 16) |
                                  (uint32_t(code[ip+2]) << 8) |
                                  uint32_t(code[ip+3]);
                ip += 4;
                std::string cond = stack.empty() ? "" : stack.back();
                if (!stack.empty()) stack.pop_back();
                if (cond == "0" || cond.empty() || cond == "false") {
                    ip = target;
                }
            }
            else if (op == OP_POP) {
                if (!stack.empty()) stack.pop_back();
            }
            else if (op == OP_NPKT) {
                std::string pkt = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string ip_dest = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();

                std::string host = ip_dest;
                int port = 9999;
                size_t c = ip_dest.rfind(':');
                if (c != std::string::npos) {
                    host = ip_dest.substr(0, c);
                    try { port = std::stoi(ip_dest.substr(c + 1)); } catch (...) {}
                }

                WSADATA wsa;
                WSAStartup(MAKEWORD(2, 2), &wsa);
                SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

                std::vector<uint8_t> raw_bytes;
                if (pkt.rfind("0x", 0) == 0 || pkt.rfind("0X", 0) == 0) {
                    for (size_t b = 2; b + 1 < pkt.size(); b += 2) {
                        uint8_t byte = (uint8_t)std::strtol(pkt.substr(b, 2).c_str(), nullptr, 16);
                        raw_bytes.push_back(byte);
                    }
                } else {
                    raw_bytes.assign(pkt.begin(), pkt.end());
                }
                sendto(s, (const char*)raw_bytes.data(), (int)raw_bytes.size(), 0, (sockaddr*)&addr, sizeof(addr));
                closesocket(s);
            }
            else if (op == OP_RUN) {
                std::string target = stack.empty() ? "" : stack.back();
                if (!stack.empty()) stack.pop_back();
                execute_subprogram(target);
            }
            else if (op == OP_CLS) {
                if (limiter.target_fps > 0.0) {
                    limiter.wait_frame();
                }
                if (first_cls) {
                    std::cout << "\033[2J\033[H";
                    first_cls = false;
                } else {
                    std::cout << "\033[H";
                }
            }
            else if (op == OP_KINP) {
                std::string k = stack.empty() ? "" : stack.back();
                if (!stack.empty()) stack.pop_back();
                int vk = get_vk_code(k);
                bool pressed = false;
                if (vk) {
                    pressed = (GetAsyncKeyState(vk) & 0x8000) != 0;
                }
                stack.push_back(pressed ? "1" : "0");
            }
            else if (op == OP_ADVL) {
                std::string b = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();

                bool a_int = !a.empty(), b_int = !b.empty();
                for (size_t i = (a.size() && a[0] == '-' ? 1 : 0); i < a.size(); i++) if (!std::isdigit(a[i])) a_int = false;
                for (size_t i = (b.size() && b[0] == '-' ? 1 : 0); i < b.size(); i++) if (!std::isdigit(b[i])) b_int = false;
                if (a == "-" || a.empty()) a_int = false;
                if (b == "-" || b.empty()) b_int = false;

                if (a_int && b_int) {
                    int64_t sum = to_int(a) + to_int(b);
                    stack.push_back(std::to_string(sum));
                } else {
                    stack.push_back(a + b);
                }
            }
            else if (op == OP_MKFL) {
                std::string content = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string filename = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                try {
                    fs::path p(filename);
                    if (p.has_parent_path()) fs::create_directories(p.parent_path());
                    std::ofstream out(filename, std::ios::binary);
                    out << content;
                } catch (const std::exception& e) {
                    std::cout << "ERR - mkfl failed: " << e.what() << "\n";
                }
            }
            else if (op == OP_MKDR) {
                std::string dirname = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                try {
                    fs::create_directories(dirname);
                } catch (const std::exception& e) {
                    std::cout << "ERR - mkdr failed: " << e.what() << "\n";
                }
            }
            else if (op == OP_CHFL) {
                std::string content = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string line_str = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string filename = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();

                int line_num = 0;
                try { line_num = std::stoi(line_str); } catch (...) {}

                try {
                    if (line_num <= 0) {
                        std::ofstream out(filename, std::ios::binary);
                        out << content;
                    } else {
                        std::ifstream in(filename);
                        std::vector<std::string> lines;
                        std::string l;
                        while (std::getline(in, l)) lines.push_back(l);
                        in.close();
                        while ((int)lines.size() < line_num) lines.push_back("");
                        lines[line_num - 1] = content;
                        std::ofstream out(filename);
                        for (const auto& line_out : lines) out << line_out << "\n";
                    }
                } catch (const std::exception& e) {
                    std::cout << "ERR - chfl failed: " << e.what() << "\n";
                }
            }
            else if (op == OP_RPFL) {
                std::string replace_str = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string search_str = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string filename = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();

                try {
                    if (!fs::is_regular_file(filename)) {
                        std::cout << "ERR - rpfl failed, " << filename << " doesnt exist.\n";
                    } else {
                        std::ifstream in(filename);
                        std::string str((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                        in.close();
                        size_t pos = 0;
                        while ((pos = str.find(search_str, pos)) != std::string::npos) {
                            str.replace(pos, search_str.length(), replace_str);
                            pos += replace_str.length();
                        }
                        std::ofstream out(filename);
                        out << str;
                    }
                } catch (const std::exception& e) {
                    std::cout << "ERR - rpfl failed: " << e.what() << "\n";
                }
            }
            else if (op == OP_RDFL) {
                uint8_t slot = code[ip++];
                std::string line_str = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string filename = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();

                int line_num = 0;
                try { line_num = std::stoi(line_str); } catch (...) {}

                try {
                    if (!fs::is_regular_file(filename)) {
                        std::cout << "ERR - rdfl failed, " << filename << " doesnt exist.\n";
                        registers[slot] = "";
                    } else if (line_num <= 0) {
                        std::ifstream in(filename, std::ios::binary);
                        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                        registers[slot] = content;
                    } else {
                        std::ifstream in(filename);
                        std::string line;
                        int cur_line = 1;
                        std::string target_content = "";
                        while (std::getline(in, line)) {
                            if (cur_line == line_num) {
                                if (!line.empty() && line.back() == '\r') line.pop_back();
                                target_content = line;
                                break;
                            }
                            cur_line++;
                        }
                        registers[slot] = target_content;
                    }
                } catch (const std::exception& e) {
                    std::cout << "ERR - rdfl failed: " << e.what() << "\n";
                    registers[slot] = "";
                }
            }
            else if (op == OP_CPRT) {
                std::string text_val = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string color_val = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                if (color_val.size() >= 2 && color_val.front() == '"' && color_val.back() == '"') {
                    color_val = color_val.substr(1, color_val.size() - 2);
                }
                std::transform(color_val.begin(), color_val.end(), color_val.begin(), ::tolower);
                std::string color_code = "";
                if (ANSI_COLORS.count(color_val)) color_code = ANSI_COLORS.at(color_val);
                std::string reset_code = color_code.empty() ? "" : ANSI_COLORS.at("reset");
                std::cout << color_code << colorize_text(text_val) << reset_code << "\n";
            }
            else if (op == OP_WAIT) {
                std::string sec_str = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                if (sec_str.size() >= 2 && sec_str.front() == '"' && sec_str.back() == '"') {
                    sec_str = sec_str.substr(1, sec_str.size() - 2);
                }
                double sec = 0.0;
                try { sec = std::stod(sec_str); } catch (...) {}
                if (sec > 0.0) {
                    Sleep((DWORD)(sec * 1000.0));
                }
            }

            else if (op == OP_SUB) {
                std::string b = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                bool is_float = (a.find('.') != std::string::npos || b.find('.') != std::string::npos);
                if (is_float) {
                    double res = to_double(a) - to_double(b);
                    stack.push_back(std::to_string(res));
                } else {
                    int64_t res = to_int(a) - to_int(b);
                    stack.push_back(std::to_string(res));
                }
            }
            else if (op == OP_MUL) {
                std::string b = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                bool is_float = (a.find('.') != std::string::npos || b.find('.') != std::string::npos);
                if (is_float) {
                    double res = to_double(a) * to_double(b);
                    stack.push_back(std::to_string(res));
                } else {
                    int64_t res = to_int(a) * to_int(b);
                    stack.push_back(std::to_string(res));
                }
            }
            else if (op == OP_DIV) {
                std::string b = stack.empty() ? "1" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                bool is_float = (a.find('.') != std::string::npos || b.find('.') != std::string::npos);
                if (is_float) {
                    double den = to_double(b, 1.0);
                    double res = (den == 0.0) ? 0.0 : (to_double(a) / den);
                    stack.push_back(std::to_string(res));
                } else {
                    int64_t den = to_int(b, 1);
                    int64_t res = (den == 0) ? 0 : (to_int(a) / den);
                    stack.push_back(std::to_string(res));
                }
            }
            else if (op == OP_MOD) {
                std::string b = stack.empty() ? "1" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                int64_t den = to_int(b, 1);
                int64_t res = (den == 0) ? 0 : (to_int(a) % den);
                stack.push_back(std::to_string(res));
            }
            else if (op == OP_POW) {
                std::string b = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                double base = to_double(a);
                double exp = to_double(b);
                double res = std::pow(base, exp);
                if (a.find('.') == std::string::npos && b.find('.') == std::string::npos && exp >= 0) {
                    stack.push_back(std::to_string((int64_t)res));
                } else {
                    stack.push_back(std::to_string(res));
                }
            }
            else if (op == OP_BAND) {
                std::string b = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                int64_t res = to_int(a) & to_int(b);
                stack.push_back(std::to_string(res));
            }
            else if (op == OP_BOR) {
                std::string b = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                int64_t res = to_int(a) | to_int(b);
                stack.push_back(std::to_string(res));
            }
            else if (op == OP_BXOR) {
                std::string b = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                int64_t res = to_int(a) ^ to_int(b);
                stack.push_back(std::to_string(res));
            }
            else if (op == OP_BNOT) {
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                int64_t res = ~to_int(a);
                stack.push_back(std::to_string(res));
            }
            else if (op == OP_BSHL) {
                std::string b = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                int64_t sh = to_int(b);
                int64_t res = (sh >= 0 && sh < 64) ? (to_int(a) << sh) : 0;
                stack.push_back(std::to_string(res));
            }
            else if (op == OP_BSHR) {
                std::string b = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                int64_t sh = to_int(b);
                int64_t res = (sh >= 0 && sh < 64) ? ((uint64_t)to_int(a) >> sh) : 0;
                stack.push_back(std::to_string(res));
            }
            else if (op == OP_BROL) {
                std::string b = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                uint32_t val = to_uint(a);
                uint32_t rot = (uint32_t)(to_uint(b) & 31);
                uint32_t res = (val << rot) | (val >> (32 - rot));
                stack.push_back(std::to_string((int64_t)res));
            }
            else if (op == OP_BROR) {
                std::string b = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                uint32_t val = to_uint(a);
                uint32_t rot = (uint32_t)(to_uint(b) & 31);
                uint32_t res = (val >> rot) | (val << (32 - rot));
                stack.push_back(std::to_string((int64_t)res));
            }
            else if (op == OP_RAND) {
                std::string b = stack.empty() ? "100" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                int64_t min_v = to_int(a, 0);
                int64_t max_v = to_int(b, 100);
                if (min_v > max_v) std::swap(min_v, max_v);
                static std::mt19937_64 rng(std::random_device{}());
                std::uniform_int_distribution<int64_t> dist(min_v, max_v);
                stack.push_back(std::to_string(dist(rng)));
            }
            else if (op == OP_SQRT) {
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                double val = to_double(a);
                double res = (val >= 0.0) ? std::sqrt(val) : 0.0;
                stack.push_back(std::to_string(res));
            }
            else if (op == OP_ABS) {
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                if (a.find('.') != std::string::npos) {
                    double val = std::abs(to_double(a));
                    stack.push_back(std::to_string(val));
                } else {
                    int64_t val = std::abs(to_int(a));
                    stack.push_back(std::to_string(val));
                }
            }
            else if (op == OP_SIN) {
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                double val = to_double(a);
                stack.push_back(std::to_string(std::sin(val)));
            }
            else if (op == OP_COS) {
                std::string a = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                double val = to_double(a);
                stack.push_back(std::to_string(std::cos(val)));
            }
            else if (op == OP_ATAN2) {
                std::string x_str = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string y_str = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                double y = to_double(y_str);
                double x = to_double(x_str);
                stack.push_back(std::to_string(std::atan2(y, x)));
            }

            else if (op == OP_SLEN) {
                std::string s = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                stack.push_back(std::to_string(s.length()));
            }
            else if (op == OP_SSUB) {
                std::string len_s = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string start_s = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string src = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                int64_t st = to_int(start_s);
                int64_t ln = to_int(len_s);
                if (st < 0) st = 0;
                if ((size_t)st >= src.length() || ln <= 0) {
                    stack.push_back("");
                } else {
                    stack.push_back(src.substr((size_t)st, (size_t)ln));
                }
            }
            else if (op == OP_SFIND) {
                std::string needle = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string haystack = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                size_t pos = haystack.find(needle);
                stack.push_back(pos == std::string::npos ? "-1" : std::to_string(pos));
            }
            else if (op == OP_SREP) {
                std::string repl = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string target = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string src = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                if (!target.empty()) {
                    size_t pos = 0;
                    while ((pos = src.find(target, pos)) != std::string::npos) {
                        src.replace(pos, target.length(), repl);
                        pos += repl.length();
                    }
                }
                stack.push_back(src);
            }
            else if (op == OP_SUPPER) {
                std::string s = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                for (char& c : s) c = (char)std::toupper((unsigned char)c);
                stack.push_back(s);
            }
            else if (op == OP_SLOWER) {
                std::string s = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                for (char& c : s) c = (char)std::tolower((unsigned char)c);
                stack.push_back(s);
            }
            else if (op == OP_STRIM) {
                std::string s = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                size_t first = s.find_first_not_of(" \t\r\n");
                if (first == std::string::npos) {
                    stack.push_back("");
                } else {
                    size_t last = s.find_last_not_of(" \t\r\n");
                    stack.push_back(s.substr(first, (last - first + 1)));
                }
            }
            else if (op == OP_ORD) {
                std::string s = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                uint8_t ch = s.empty() ? 0 : (uint8_t)s[0];
                stack.push_back(std::to_string((int)ch));
            }
            else if (op == OP_CHR) {
                std::string code_s = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                int val = (int)to_int(code_s);
                std::string res(1, (char)(uint8_t)val);
                stack.push_back(res);
            }

            else if (op == OP_CALL) {
                uint32_t target = (uint32_t(code[ip]) << 24) |
                                  (uint32_t(code[ip+1]) << 16) |
                                  (uint32_t(code[ip+2]) << 8) |
                                  uint32_t(code[ip+3]);
                ip += 4;
                call_stack.push_back(ip);
                ip = target;
            }
            else if (op == OP_RET) {
                if (!call_stack.empty()) {
                    ip = call_stack.back();
                    call_stack.pop_back();
                } else {
                    break;
                }
            }

            else if (op == OP_RAMFREE) {
                MEMORYSTATUSEX memInfo;
                memInfo.dwLength = sizeof(MEMORYSTATUSEX);
                GlobalMemoryStatusEx(&memInfo);
                stack.push_back(std::to_string(memInfo.ullAvailPhys / (1024 * 1024)));
            }
            else if (op == OP_RAMTOTAL) {
                MEMORYSTATUSEX memInfo;
                memInfo.dwLength = sizeof(MEMORYSTATUSEX);
                GlobalMemoryStatusEx(&memInfo);
                stack.push_back(std::to_string(memInfo.ullTotalPhys / (1024 * 1024)));
            }
            else if (op == OP_RAMPROC) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
                    stack.push_back(std::to_string(pmc.WorkingSetSize / 1024));
                } else {
                    stack.push_back("0");
                }
            }
            else if (op == OP_CPUUSAGE) {
                static ULARGE_INTEGER lastCPU, lastSysCPU, lastUserCPU;
                static int numProcessors = -1;
                static bool initialized = false;
                if (!initialized) {
                    SYSTEM_INFO sysInfo;
                    FILETIME ftime, fsys, fuser;
                    GetSystemInfo(&sysInfo);
                    numProcessors = sysInfo.dwNumberOfProcessors;
                    GetSystemTimeAsFileTime(&ftime);
                    memcpy(&lastCPU, &ftime, sizeof(FILETIME));
                    GetProcessTimes(GetCurrentProcess(), &ftime, &ftime, &fsys, &fuser);
                    memcpy(&lastSysCPU, &fsys, sizeof(FILETIME));
                    memcpy(&lastUserCPU, &fuser, sizeof(FILETIME));
                    initialized = true;
                    stack.push_back("0");
                } else {
                    FILETIME ftime, fsys, fuser;
                    ULARGE_INTEGER now, sys, user;
                    GetSystemTimeAsFileTime(&ftime);
                    memcpy(&now, &ftime, sizeof(FILETIME));
                    GetProcessTimes(GetCurrentProcess(), &ftime, &ftime, &fsys, &fuser);
                    memcpy(&sys, &fsys, sizeof(FILETIME));
                    memcpy(&user, &fuser, sizeof(FILETIME));
                    int64_t percent = 0;
                    if (now.QuadPart > lastCPU.QuadPart) {
                        percent = (int64_t)(((sys.QuadPart - lastSysCPU.QuadPart) + (user.QuadPart - lastUserCPU.QuadPart)) * 100 / (now.QuadPart - lastCPU.QuadPart) / numProcessors);
                    }
                    lastCPU = now;
                    lastSysCPU = sys;
                    lastUserCPU = user;
                    stack.push_back(std::to_string(percent));
                }
            }
            else if (op == OP_CPUCORES) {
                SYSTEM_INFO sysInfo;
                GetSystemInfo(&sysInfo);
                stack.push_back(std::to_string(sysInfo.dwNumberOfProcessors));
            }
            else if (op == OP_TIMEUS) {
                static LARGE_INTEGER freq;
                static bool has_freq = false;
                if (!has_freq) {
                    QueryPerformanceFrequency(&freq);
                    has_freq = true;
                }
                LARGE_INTEGER count;
                QueryPerformanceCounter(&count);
                int64_t us = (int64_t)((count.QuadPart * 1000000LL) / freq.QuadPart);
                stack.push_back(std::to_string(us));
            }
            else if (op == OP_TIMEMS) {
                static LARGE_INTEGER freq;
                static bool has_freq = false;
                if (!has_freq) {
                    QueryPerformanceFrequency(&freq);
                    has_freq = true;
                }
                LARGE_INTEGER count;
                QueryPerformanceCounter(&count);
                int64_t ms = (int64_t)((count.QuadPart * 1000LL) / freq.QuadPart);
                stack.push_back(std::to_string(ms));
            }
            else if (op == OP_TIMENOW) {
                SYSTEMTIME st;
                GetLocalTime(&st);
                char buf[64];
                snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                         st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
                stack.push_back(std::string(buf));
            }
            else if (op == OP_SLEEPMS) {
                std::string ms_s = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                int ms = (int)to_int(ms_s);
                if (ms > 0) Sleep((DWORD)ms);
            }
            else if (op == OP_ARGVLEN) {
                stack.push_back(std::to_string(cli_args.size()));
            }
            else if (op == OP_ARGVGET) {
                std::string idx_s = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                size_t idx = (size_t)to_uint(idx_s);
                stack.push_back(idx < cli_args.size() ? cli_args[idx] : "");
            }
            else if (op == OP_ENVGET) {
                std::string name = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                char buf[1024];
                DWORD r = GetEnvironmentVariableA(name.c_str(), buf, sizeof(buf));
                if (r > 0 && r < sizeof(buf)) {
                    stack.push_back(std::string(buf));
                } else {
                    const char* val = std::getenv(name.c_str());
                    stack.push_back(val ? std::string(val) : "");
                }
            }
            else if (op == OP_ENVSET) {
                std::string val = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string name = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                SetEnvironmentVariableA(name.c_str(), val.c_str());
            }
            else if (op == OP_EXIT) {
                std::string code_s = stack.empty() ? "0" : stack.back(); if (!stack.empty()) stack.pop_back();
                int ex_code = (int)to_int(code_s);
                exit(ex_code);
            }
            else if (op == OP_EXEC) {
                std::string cmd = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string out = "";
                FILE* pipe = _popen(cmd.c_str(), "r");
                if (pipe) {
                    char buf[512];
                    while (fgets(buf, sizeof(buf), pipe) != nullptr) {
                        out += buf;
                    }
                    _pclose(pipe);
                }
                stack.push_back(out);
            }

            else if (op == OP_INKEY) {
                HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
                DWORD numEvents = 0;
                std::string res = "";
                if (hIn != INVALID_HANDLE_VALUE && GetNumberOfConsoleInputEvents(hIn, &numEvents) && numEvents > 0) {
                    INPUT_RECORD ir[32];
                    DWORD read = 0;
                    if (ReadConsoleInput(hIn, ir, 32, &read)) {
                        for (DWORD i = 0; i < read; i++) {
                            if (ir[i].EventType == KEY_EVENT && ir[i].Event.KeyEvent.bKeyDown) {
                                char ch = ir[i].Event.KeyEvent.uChar.AsciiChar;
                                if (ch != 0) {
                                    res = std::string(1, ch);
                                    break;
                                } else {
                                    WORD vk = ir[i].Event.KeyEvent.wVirtualKeyCode;
                                    if (vk == VK_UP) res = "up";
                                    else if (vk == VK_DOWN) res = "down";
                                    else if (vk == VK_LEFT) res = "left";
                                    else if (vk == VK_RIGHT) res = "right";
                                    else if (vk == VK_ESCAPE) res = "esc";
                                    else if (vk == VK_RETURN) res = "enter";
                                    else if (vk == VK_SPACE) res = "space";
                                    if (!res.empty()) break;
                                }
                            }
                        }
                    }
                }
                stack.push_back(res);
            }
            else if (op == OP_KEYDOWN) {
                std::string k = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                int vk = get_vk_code(k);
                bool pressed = false;
                if (vk) pressed = (GetAsyncKeyState(vk) & 0x8000) != 0;
                stack.push_back(pressed ? "1" : "0");
            }
            else if (op == OP_KEYUP) {
                std::string k = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                int vk = get_vk_code(k);
                bool up = true;
                if (vk) up = (GetAsyncKeyState(vk) & 0x8000) == 0;
                stack.push_back(up ? "1" : "0");
            }
            else if (op == OP_KEYMOD) {
                int mod = 0;
                if (GetAsyncKeyState(VK_SHIFT) & 0x8000)   mod |= 1;
                if (GetAsyncKeyState(VK_CONTROL) & 0x8000) mod |= 2;
                if (GetAsyncKeyState(VK_MENU) & 0x8000)    mod |= 4;
                stack.push_back(std::to_string(mod));
            }
            else if (op == OP_MOUSEX) {
                POINT pt;
                GetCursorPos(&pt);
                HWND hConsole = GetConsoleWindow();
                if (hConsole) ScreenToClient(hConsole, &pt);
                stack.push_back(std::to_string(pt.x));
            }
            else if (op == OP_MOUSEY) {
                POINT pt;
                GetCursorPos(&pt);
                HWND hConsole = GetConsoleWindow();
                if (hConsole) ScreenToClient(hConsole, &pt);
                stack.push_back(std::to_string(pt.y));
            }
            else if (op == OP_MOUSEBTN) {
                int btn = 0;
                if (GetAsyncKeyState(VK_LBUTTON) & 0x8000)  btn |= 1;
                if (GetAsyncKeyState(VK_RBUTTON) & 0x8000)  btn |= 2;
                if (GetAsyncKeyState(VK_MBUTTON) & 0x8000)  btn |= 4;
                stack.push_back(std::to_string(btn));
            }
            else if (op == OP_MOUSEWHEEL) {
                stack.push_back("0");
            }
            else if (op == OP_TERMW) {
                CONSOLE_SCREEN_BUFFER_INFO csbi;
                HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
                int w = 80;
                if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
                    w = csbi.srWindow.Right - csbi.srWindow.Left + 1;
                }
                stack.push_back(std::to_string(w));
            }
            else if (op == OP_TERMH) {
                CONSOLE_SCREEN_BUFFER_INFO csbi;
                HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
                int h = 25;
                if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
                    h = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
                }
                stack.push_back(std::to_string(h));
            }
            else if (op == OP_CURPOS) {
                std::string col_s = stack.empty() ? "1" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string row_s = stack.empty() ? "1" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::cout << "\033[" << row_s << ";" << col_s << "H";
            }
            else if (op == OP_CURHIDE) {
                std::cout << "\033[?25l";
            }
            else if (op == OP_CURSHOW) {
                std::cout << "\033[?25h";
            }
            else if (op == OP_TERMALTSCR) {
                std::string en_s = stack.empty() ? "1" : stack.back(); if (!stack.empty()) stack.pop_back();
                if (en_s == "1" || en_s == "true") {
                    std::cout << "\033[?1049h";
                } else {
                    std::cout << "\033[?1049l";
                }
            }

            else if (op == OP_FLEXISTS) {
                std::string path = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                stack.push_back(fs::exists(path) ? "1" : "0");
            }
            else if (op == OP_FLSIZE) {
                std::string path = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                try {
                    if (fs::is_regular_file(path)) {
                        stack.push_back(std::to_string(fs::file_size(path)));
                    } else {
                        stack.push_back("-1");
                    }
                } catch (...) {
                    stack.push_back("-1");
                }
            }
            else if (op == OP_FLREAD) {
                std::string path = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                try {
                    if (fs::is_regular_file(path)) {
                        std::ifstream in(path, std::ios::binary);
                        std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                        stack.push_back(s);
                    } else {
                        stack.push_back("");
                    }
                } catch (...) {
                    stack.push_back("");
                }
            }
            else if (op == OP_FLWRITE) {
                std::string data = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string path = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                try {
                    fs::path p(path);
                    if (p.has_parent_path()) fs::create_directories(p.parent_path());
                    std::ofstream out(path, std::ios::binary);
                    out << data;
                } catch (const std::exception& e) {
                    std::cout << "ERR - fl_write failed: " << e.what() << "\n";
                }
            }
            else if (op == OP_FLAPPEND) {
                std::string data = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string path = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                try {
                    fs::path p(path);
                    if (p.has_parent_path()) fs::create_directories(p.parent_path());
                    std::ofstream out(path, std::ios::binary | std::ios::app);
                    out << data;
                } catch (const std::exception& e) {
                    std::cout << "ERR - fl_append failed: " << e.what() << "\n";
                }
            }
            else if (op == OP_FLDEL) {
                std::string path = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                try {
                    fs::remove_all(path);
                } catch (const std::exception& e) {
                    std::cout << "ERR - fl_del failed: " << e.what() << "\n";
                }
            }
            else if (op == OP_DIRMAKE) {
                std::string path = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                try {
                    fs::create_directories(path);
                } catch (const std::exception& e) {
                    std::cout << "ERR - dir_make failed: " << e.what() << "\n";
                }
            }

            else if (op == OP_BEEP) {
                std::string dur_s = stack.empty() ? "200" : stack.back(); if (!stack.empty()) stack.pop_back();
                std::string freq_s = stack.empty() ? "750" : stack.back(); if (!stack.empty()) stack.pop_back();
                DWORD freq = 750, dur = 200;
                try { freq = (DWORD)std::stoul(freq_s); } catch (...) {}
                try { dur = (DWORD)std::stoul(dur_s); } catch (...) {}
                Beep(freq, dur);
            }
            else if (op == OP_SFXPLAY) {
                std::string path = stack.empty() ? "" : stack.back(); if (!stack.empty()) stack.pop_back();
                PlaySoundA(path.c_str(), NULL, SND_ASYNC | SND_FILENAME);
            }
            else if (op == OP_SFXSTOP) {
                PlaySoundA(NULL, NULL, 0);
            }

        }
    }
};

void disassemble_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        std::cout << "ERR - cannot open " << path << "\n";
        return;
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (data.size() < 14) { std::cout << "ERR - file too small\n"; return; }

    std::cout << "============================================================\n";
    std::cout << " YERU NATIVE BYTECODE DISASSEMBLY: " << path << "\n";
    std::cout << "============================================================\n";
    std::cout << "[Total Size]   : " << data.size() << " bytes\n";
    std::cout << "------------------------------------------------------------\n";

    size_t offset = 7;
    ConstantPool pool = ConstantPool::deserialize(data.data(), offset, data.size() - 7);
    std::cout << "CONSTANT POOL (" << pool.constants.size() << " items):\n";
    for (size_t i = 0; i < pool.constants.size(); i++) {
        std::cout << "  #" << i << " = \"" << pool.constants[i].as_string() << "\"\n";
    }
    std::cout << "------------------------------------------------------------\n";

    uint32_t clen = (uint32_t(data[offset]) << 24) |
                    (uint32_t(data[offset+1]) << 16) |
                    (uint32_t(data[offset+2]) << 8) |
                    uint32_t(data[offset+3]);
    offset += 4;
    std::cout << "BYTECODE (" << clen << " bytes):\n";

    size_t ip = 0;
    while (ip < clen) {
        size_t cur = ip;
        uint8_t op = data[offset + ip++];
        std::cout << "  " << cur << "\t" << opcode_name(op);
        if (op == OP_LOAD_CONST) {
            uint32_t arg = (uint32_t(data[offset + ip]) << 24) |
                           (uint32_t(data[offset + ip + 1]) << 16) |
                           (uint32_t(data[offset + ip + 2]) << 8) |
                           uint32_t(data[offset + ip + 3]);
            ip += 4;
            std::cout << " #" << arg << " (\"" << pool.constants[arg].as_string() << "\")";
        } else if (op == OP_LOAD_VAR || op == OP_STORE_VAR || op == OP_RDFL) {
            uint8_t slot = data[offset + ip++];
            std::cout << " reg_" << (int)slot;
        } else if (op == OP_JUMP || op == OP_JUMP_IF_FALSE || op == OP_CALL) {
            uint32_t target = (uint32_t(data[offset + ip]) << 24) |
                              (uint32_t(data[offset + ip + 1]) << 16) |
                              (uint32_t(data[offset + ip + 2]) << 8) |
                              uint32_t(data[offset + ip + 3]);
            ip += 4;
            std::cout << " -> " << target;

        }
        std::cout << "\n";
    }
    std::cout << "============================================================\n";
}

int main(int argc, char* argv[]) {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);
    SetConsoleOutputCP(CP_UTF8);

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }

    if (argc < 2) {
        std::cout << "Usage:\n";
        std::cout << "  yeru compile <file.yeru> [-o <out.yu>]\n";
        std::cout << "  yeru run <file.yu | file.yeru> [--fps <N>]\n";
        std::cout << "  yeru disasm <file.yu>\n";
        return 0;
    }

    double target_fps = 0.0;
    const char* env_fps = std::getenv("YERU_FPS");
    if (env_fps) {
        try { target_fps = std::stod(env_fps); } catch (...) {}
    }

    std::vector<std::string> args;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--fps" || a == "-fps" || a == "-f") {
            if (i + 1 < argc) {
                try { target_fps = std::stod(argv[++i]); } catch (...) {}
            }
        } else if (a.rfind("--fps=", 0) == 0) {
            try { target_fps = std::stod(a.substr(6)); } catch (...) {}
        } else {
            args.push_back(a);
        }
    }

    if (args.empty()) {
        std::cout << "ERR - specify a file to run\n";
        return 1;
    }

    std::string cmd = args[0];

    if (cmd == "compile" || cmd == "-c") {
        if (args.size() < 2) {
            std::cout << "ERR - specify file to compile\n";
            return 1;
        }
        std::string src = args[1];
        std::string out = src.rfind(".yeru") != std::string::npos ? src.substr(0, src.rfind(".yeru")) + ".yu" : src + ".yu";
        if (args.size() >= 4 && args[2] == "-o") out = args[3];

        std::ifstream f(src);
        if (!f.is_open()) {
            std::cout << "ERR - cannot open " << src << "\n";
            return 1;
        }
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        Compiler comp;
        auto bin = comp.compile_source(content);
        std::ofstream out_f(out, std::ios::binary);
        out_f.write((char*)bin.data(), bin.size());
        std::cout << "compiled: " << src << " -> " << out << "\n";
        return 0;
    }

    if (cmd == "disasm" || cmd == "-d") {
        if (args.size() < 2) {
            std::cout << "ERR - specify file to disassemble\n";
            return 1;
        }
        disassemble_file(args[1]);
        return 0;
    }

    std::string target = (cmd == "run" || cmd == "-r") ? (args.size() >= 2 ? args[1] : "") : cmd;
    if (target.empty()) {
        std::cout << "ERR - specify a file to run\n";
        return 1;
    }

    std::vector<std::string> prog_args;
    size_t target_idx = 0;
    for (size_t i = 0; i < args.size(); i++) {
        if (args[i] == target) { target_idx = i; break; }
    }
    for (size_t i = target_idx; i < args.size(); i++) {
        prog_args.push_back(args[i]);
    }
    VirtualMachine::cli_args = prog_args;

    std::vector<uint8_t> bin;
    if (target.rfind(".yeru") != std::string::npos) {
        std::ifstream f(target);
        if (!f.is_open()) {
            std::cout << "ERR - cannot open " << target << "\n";
            return 1;
        }
        std::string src((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        Compiler comp;
        bin = comp.compile_source(src);
    } else {
        std::ifstream f(target, std::ios::binary);
        if (!f.is_open()) {
            std::cout << "ERR - cannot open " << target << "\n";
            return 1;
        }
        bin.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    }

    std::cout << "\033[?25l";

    VirtualMachine vm(bin, target_fps);
    vm.run();

    std::cout << "\033[?25h" << std::flush;
    return 0;
}
