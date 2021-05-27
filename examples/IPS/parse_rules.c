/* Copyright @ Github.com/Rsysz */

#include "parse_rules.h"
#include <pcre.h>

/**
 * Parse variable from rule
 */
static string
parseVar(const string &varStr) {
        size_t seg = varStr.find('[');
        if (seg == string::npos) {
                if (VAR_MAP.find(varStr) != VAR_MAP.end())
                        return VAR_MAP.at(varStr);
                return varStr;
        }
        size_t comma = varStr.find(',', ++seg);
        string tmpVar = varStr;
        while (comma != string::npos) {
                string tmp(varStr.substr(seg, comma - seg));
                if (VAR_MAP.find(tmp) != VAR_MAP.end()) {
                        tmpVar.replace(seg, comma - seg, VAR_MAP.at(tmp));
                }
                seg = comma + 1;
                comma = varStr.find_first_of(",]", seg);
        }
        return tmpVar;
}

/**
 * Split string from line
 */
static void
splitRule(vector<string> &rule, const string &str, const char delim = ' ') {
        int current, previous = 0;
        for (int i = 0; i < 7; ++i) {
                current = str.find(delim, previous);
                rule.push_back(parseVar(str.substr(previous, current - previous)));
                previous = current + 1;
        }
}

/**
 * Parse flags from pcre
 */
static unsigned
parseFlags(const string &flagsStr) {
        unsigned flags = HS_FLAG_PREFILTER;
        for (const auto &c : flagsStr) {
                switch (c) {
                        case 'i':
                                flags |= HS_FLAG_CASELESS;
                                break;
                        case 'm':
                                flags |= HS_FLAG_MULTILINE;
                                break;
                        case 's':
                                flags |= HS_FLAG_DOTALL;
                                break;
                        case 'x':
                                flags |= PCRE_EXTENDED;
                                break;
                        case 'H':
                                flags |= HS_FLAG_SINGLEMATCH;
                                break;
                        case 'V':
                                flags |= HS_FLAG_ALLOWEMPTY;
                                break;
                        case '8':
                                flags |= HS_FLAG_UTF8;
                                break;
                        case 'W':
                                flags |= HS_FLAG_UCP;
                                break;
                        case '\r':  // stray carriage-return
                                break;
                        default:
                                // cerr << "Unsupported flag \'" << c << "\'" << endl;
                                return 0;
                }
        }
        return flags;
}

static void
convPort(string bus, vector<uint16_t> &minPort, vector<uint16_t> &maxPort) {
        size_t colon = bus.find(':');
        if (colon != string::npos) {
                uint16_t start = 1, end = 65535;
                if (colon != 0) {
                        // cout << bus.substr(0, colon) << endl;
                        start = stoi(bus.substr(0, colon));
                }
                if (colon != bus.size() - 1) {
                        // cout << bus.substr(colon + 1) << endl;
                        end = stoi(bus.substr(colon + 1));
                }
                minPort.push_back(rte_cpu_to_be_16(start));
                maxPort.push_back(rte_cpu_to_be_16(end));
                return;
        }
        // cout << bus << endl;
        minPort.push_back(rte_cpu_to_be_16(stoi(bus)));
        maxPort.push_back(rte_cpu_to_be_16(stoi(bus)));
}

static void
parsePort(const string &bus, vector<uint16_t> &minPort, vector<uint16_t> &maxPort) {
        if (bus == "0") {
                minPort.push_back(0);
                maxPort.push_back(0);
                return;
        }
        size_t seg = bus.find('[');
        if (seg != string::npos) {
                size_t comma = bus.find_first_of(",]", ++seg);
                while (comma != string::npos) {
                        convPort(bus.substr(seg, comma - seg), minPort, maxPort);
                        seg = comma + 1;
                        comma = bus.find_first_of(",]", seg);
                }
        } else
                convPort(bus, minPort, maxPort);
}

static void
convAddr(string net, vector<uint32_t> &ip, vector<uint32_t> &mask) {
        uint32_t network;
        uint32_t netmask = 0xFFFFFFFF;
        size_t slash = net.rfind('/');
        if (slash == string::npos) {
                inet_pton(AF_INET, net.c_str(), &network);
        } else {
                inet_pton(AF_INET, net.substr(0, slash).c_str(), &network);
                uint64_t mask = 1UL << 32;
                uint64_t cidr = 1UL << (32 - stoi(net.substr(slash + 1)));
                netmask = rte_cpu_to_be_32(mask - cidr);
        }
        ip.push_back(network);
        mask.push_back(netmask);
}

static void
parseAddr(const string &net, vector<uint32_t> &ip, vector<uint32_t> &mask) {
        if (net == "0") {
                ip.push_back(0);
                mask.push_back(0);
                return;
        }
        size_t seg = net.find('[');
        if (seg != string::npos) {
                size_t comma = net.find_first_of(",]", ++seg);
                while (comma != string::npos) {
                        convAddr(net.substr(seg, comma - seg), ip, mask);
                        seg = comma + 1;
                        comma = net.find_first_of(",]", seg);
                }
        } else
                convAddr(net, ip, mask);
}

RuleTuple::RuleTuple(vector<string> &rule) : srcAddr(rule[2]), srcBus(rule[3]), dstAddr(rule[5]), dstBus(rule[6]) {
        parseAddr(rule[2], srcIp, srcMask);
        parsePort(rule[3], srcMinPort, srcMaxPort);
        parseAddr(rule[5], dstIp, dstMask);
        parsePort(rule[6], dstMinPort, dstMaxPort);
}
/*
static void
ReplaceAll(string &str, const string& from, const string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
}
*/
static void
splitBinary(string &pattern, string str, const char delim = ' ') {
        vector<string> bytecode;
        int current, previous = 0;
        current = str.find(delim);
        while (current != string::npos) {
                bytecode.push_back(str.substr(previous, current - previous));
                previous = current + 1;
                current = str.find(delim, previous);
        }
        bytecode.push_back(str.substr(previous, current - previous));
        for (auto &n : bytecode) {
                pattern += "\\x" + n;
        }
}
/*
|00 0A|
0123456
| = 7C cause match error
*/
static void
convBinary(string &pattern, string content, unsigned &flags) {
        // cout << content << endl;
        for (auto ch = content.begin(); ch != content.end(); ++ch) {
                if (*ch == '|') {
                        size_t binaryStart = distance(content.begin(), ch);
                        size_t binaryEnd = content.find('|', ++binaryStart);
                        splitBinary(pattern, content.substr(binaryStart, binaryEnd - binaryStart));
                        ch = content.begin() + binaryEnd;  // END |
                } else if (*ch == '[') {
                        pattern += "\\[";
                } else if (*ch == ']') {
                        pattern += "\\]";
                } else if (*ch == '(') {
                        pattern += "\\(";
                } else if (*ch == ')') {
                        pattern += "\\)";
                } else if (*ch == '^') {
                        pattern += "\\^";
                } else if (*ch == '?') {
                        pattern += "\\?";
                } else if (*ch == '+') {
                        pattern += "\\+";
                } else if (*ch == '*') {
                        pattern += "\\*";
                } else if (*ch == '.') {
                        pattern += "\\.";
                } else if (*ch == '\\') {
                        pattern += "\\\\";
                } else {
                        pattern += *ch;
                }
        }
}

static bool
parseContent(string &content, string &pattern, unsigned &flags) {
        size_t patternEnd = content.find("\"");
        convBinary(pattern, content.substr(0, patternEnd), flags);

        size_t comma = content.find(",");
        while (comma != string::npos) {
                size_t seg = content.find_first_of(",;", ++comma);
                string tmp = content.substr(comma, seg - comma);
                comma = content.find_first_of(",;", ++seg);
                if (tmp == "nocase") {
                        flags |= HS_FLAG_CASELESS;
                } else if (tmp == "fast_pattern") {
                        flags |= HS_FLAG_PREFILTER;
                } else {
                        return true;
                }
        }
        return false;
}

/**
 * Parse rules from pattern file
 */
static void
parseFile(const char *filename, RulesHashMp &rules) {
        ifstream inFile(filename);
        if (!inFile.good()) {
                cerr << "ERROR: Can't open pattern file \"" << filename << "\"" << endl;
                exit(-1);
        }
        while (!inFile.eof()) {
                string line;
                getline(inFile, line);

                // if line is empty, or a comment, we can skip it
                if (line.empty() || line[0] == '#') {
                        continue;
                }

                string pattern;
                unsigned flags;
                size_t featureStart = line.find("pcre:\"/");
                if (featureStart == string::npos) {
                        // Content
                        featureStart = line.find("content:\"");
                        if (featureStart == string::npos) {
                                // cerr << "ERROR: no content in rule" << endl;
                                continue;
                        }
                        size_t space = line.find(";", featureStart) + 1;
                        if (space != line.find("metadata:") - 1) {
                                // cerr << "ERROR: multiple content" << endl;
                                continue;
                        }
                        string content = line.substr(featureStart + 9, space - featureStart - 9);
                        flags = 0;
                        if (parseContent(content, pattern, flags)) {
                                continue;
                        }
                } else {
                        // Pcre
                        size_t pcreEnd = line.find("\"", featureStart + 6);
                        const string expr(line.substr(featureStart + 6, pcreEnd - featureStart - 6));
                        size_t flagsStart = expr.find_last_of('/');
                        if (flagsStart == string::npos) {
                                cerr << "ERROR: no trailing '/' char" << endl;
                                continue;
                        }
                        string flagsStr(expr.substr(flagsStart + 1, expr.size() - flagsStart));
                        pattern = expr.substr(1, flagsStart - 1);
                        flags = parseFlags(flagsStr);
                        if (!flags)
                                continue;
                }
                // Msg
                size_t msgStart = line.find("msg:\"");
                size_t msgEnd = line.find("\"", msgStart + 5);
                string msg(line.substr(msgStart + 5, msgEnd - msgStart - 5));
                // Rule
                vector<string> rule;
                splitRule(rule, line);
                //<action> <protocol> <src_ip> <src_port> <direction> <dst_ip> <dst_port> (msg pattern flags)
                if (PROTO_MAP.find(rule[1]) != PROTO_MAP.end()) {
                        rules[PROTO_MAP.at(rule[1])][RuleTuple(rule)].info.push_back(
                            RuleInfo(ACTION_MAP.at(rule[0]), msg, pattern, flags));
                }
                // Added rule to hashmp
        }
}

static void
buildDatabase(RuleDB &data, unsigned int mode) {
        hs_database_t *db;
        hs_compile_error_t *compileErr;
        hs_error_t err;

        vector<const char *> pattern;
        vector<unsigned> flags;
        vector<unsigned> ids;

        for (auto &i : data.info) {
                pattern.push_back(i.pattern.c_str());
                flags.push_back(i.flags);
                ids.push_back(ids.size());
        }
        // hs_compile_lit_multi();
        err = hs_compile_multi(pattern.data(), flags.data(), ids.data(), pattern.size(), mode, NULL, &db, &compileErr);

        if (err != HS_SUCCESS) {
                if (compileErr->expression < 0) {
                        // The error does not refer to a particular expression.
                        cerr << "ERROR: " << compileErr->message << endl;
                } else {
                        cerr << "ERROR: Pattern '" << pattern[compileErr->expression]
                             << "' failed compilation with error: " << compileErr->message << endl;
                }
                // As the compileErr pointer points to dynamically allocated memory, if
                // we get an error, we must be sure to release it. This is not
                // necessary when no error is detected.
                hs_free_compile_error(compileErr);
                exit(-1);
        }

        data.db = db;
}

static void
buildProtocolDatabase(uint8_t protocol, RulesHashMp &rules, unsigned int mode) {
        if (rules.find(protocol) != rules.end()) {
                Clock clock;
                clock.start();
                for (auto &i : rules.at(protocol)) {
                        // i.first RuleTuple
                        // i.second RuleDB
                        cout << i.first.srcAddr << " " << i.first.srcBus << " " << i.first.dstAddr << " "
                             << i.first.dstBus << " " << endl;
                        buildDatabase(i.second, mode);
                }
                auto it = find_if(PROTO_MAP.begin(), PROTO_MAP.end(),
                                  [&protocol](const pair<string, uint8_t> &p) { return p.second == protocol; });
                clock.stop();
                cout << "Protocol " << it->first << " Hyperscan " << (mode == HS_MODE_STREAM ? "streaming" : "block")
                     << " mode database compiled in " << clock.seconds() << " seconds." << endl;
        }
}

RulesHashMp *
databasesFromFile(const char *filename) {
        RulesHashMp *rules = new RulesHashMp;
        parseFile(filename, *rules);
        /* Build Protocl Database */
        buildProtocolDatabase(IP_PROTOCOL_TCP, *rules, HS_MODE_STREAM);
        buildProtocolDatabase(IP_PROTOCOL_UDP, *rules, HS_MODE_STREAM);
        buildProtocolDatabase(IP_PROTOCOL_ICMP, *rules, HS_MODE_BLOCK);
        buildProtocolDatabase(IP_PROTOCOL_OTHER, *rules, HS_MODE_BLOCK);
        return rules;
}

// void updateDatabases();
