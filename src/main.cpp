// Static extraction of syscall expectations from preprocessed translation units.
// No analyzed program is compiled, linked, or executed.
#include <algorithm>
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/Expr.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Lex/Lexer.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <cstdlib>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace clang;
namespace J = llvm::json;
static llvm::cl::OptionCategory Category("syscall expectation extraction");
static llvm::cl::list<std::string>
    Functions("function", llvm::cl::desc("Function to analyze (repeatable)"),
              llvm::cl::cat(Category));
static llvm::cl::list<std::string>
    Syscalls("syscall", llvm::cl::desc("Syscall to report (repeatable)"),
             llvm::cl::cat(Category));
static llvm::cl::opt<bool>
    AllFunctions("all-functions",
                 llvm::cl::desc("Analyze every function defined by the original source"),
                 llvm::cl::init(false), llvm::cl::cat(Category));
static llvm::cl::opt<unsigned> LoopLimit("loop-limit", llvm::cl::init(128),
                                         llvm::cl::cat(Category));
static llvm::cl::opt<std::string>
    Bitcode("bitcode", llvm::cl::desc("Optional sibling LLVM bitcode used to infer the target"),
            llvm::cl::value_desc("file.bc"), llvm::cl::cat(Category));
static llvm::cl::opt<std::string>
    Target("target", llvm::cl::desc("Override the Clang target triple"),
           llvm::cl::value_desc("triple"), llvm::cl::cat(Category));
static llvm::cl::opt<std::string>
    SourceFile("source-file", llvm::cl::desc("Override the original source path from line markers"),
               llvm::cl::value_desc("path"), llvm::cl::cat(Category));
static llvm::cl::opt<std::string>
    InputFile(llvm::cl::Positional, llvm::cl::desc("<preprocessed .i/.ii>"),
              llvm::cl::Required, llvm::cl::cat(Category));

static std::string PrimarySource;
static std::string TargetOrigin = "host_default";
static std::vector<std::string> StartupWarnings;
static std::map<int64_t, std::string> SyscallNames;

static std::optional<std::string> lineMarkerFile(llvm::StringRef line) {
  line = line.trim();
  if (!line.consume_front("#"))
    return std::nullopt;
  line = line.ltrim();
  size_t digits = line.find_first_not_of("0123456789");
  if (digits == llvm::StringRef::npos || digits == 0)
    return std::nullopt;
  line = line.drop_front(digits).ltrim();
  if (!line.consume_front("\""))
    return std::nullopt;
  size_t end = line.find('"');
  if (end == llvm::StringRef::npos)
    return std::nullopt;
  llvm::StringRef file = line.take_front(end);
  if (file.starts_with("<") && file.ends_with(">"))
    return std::nullopt;
  return file.str();
}

static bool parseInteger(llvm::StringRef text, int64_t &value) {
  text = text.trim();
  while (text.size() >= 2 && text.front() == '(' && text.back() == ')')
    text = text.drop_front().drop_back().trim();
  std::string storage = text.str();
  char *end = nullptr;
  long long parsed = std::strtoll(storage.c_str(), &end, 0);
  if (end == storage.c_str())
    return false;
  while (*end == 'u' || *end == 'U' || *end == 'l' || *end == 'L' ||
         *end == ' ' || *end == '\t')
    ++end;
  if (*end)
    return false;
  value = parsed;
  return true;
}

static bool inspectPreprocessedInput(llvm::StringRef path) {
  auto input = llvm::MemoryBuffer::getFile(path);
  if (!input) {
    llvm::errs() << "Unable to read input: " << input.getError().message() << "\n";
    return false;
  }
  llvm::StringRef text = input.get()->getBuffer();
  while (!text.empty()) {
    auto split = text.split('\n');
    llvm::StringRef line = split.first;
    text = split.second;
    if (PrimarySource.empty())
      if (auto file = lineMarkerFile(line))
        PrimarySource = *file;

    line = line.trim();
    constexpr llvm::StringLiteral Prefix("#define __NR_");
    if (!line.consume_front(Prefix))
      continue;
    size_t space = line.find_first_of(" \t");
    if (space == llvm::StringRef::npos)
      continue;
    llvm::StringRef name = line.take_front(space);
    int64_t number;
    if (name.empty() || name == "Linux" || name == "syscalls" ||
        name == "arch_specific_syscall" ||
        !parseInteger(line.drop_front(space), number))
      continue;
    SyscallNames.try_emplace(number, name.str());
  }
  if (PrimarySource.empty())
    StartupWarnings.push_back("original source path was not found in line markers");
  return true;
}

static std::optional<std::string> bitcodeTarget(llvm::StringRef path) {
  auto input = llvm::MemoryBuffer::getFile(path);
  if (!input) {
    StartupWarnings.push_back("unable to read bitcode target metadata: " +
                              input.getError().message());
    return std::nullopt;
  }
  auto triple = llvm::getBitcodeTargetTriple(input.get()->getMemBufferRef());
  if (!triple) {
    StartupWarnings.push_back("unable to parse bitcode target metadata: " +
                              llvm::toString(triple.takeError()));
    return std::nullopt;
  }
  if (triple->empty()) {
    StartupWarnings.push_back("bitcode does not contain a target triple");
    return std::nullopt;
  }
  return *triple;
}

// Symbolic values deliberately preserve unknowns rather than inventing
// constants.
struct V {
  enum Kind {
    Unknown,
    Integer,
    String,
    Record,
    Array,
    Pointer,
    Result,
    Error,
    Expression
  } kind = Unknown;
  int64_t number = 0;
  bool unsignedInteger = false;
  std::string text;
  std::map<std::string, V> fields;
  std::vector<V> items;
  const ValueDecl *root = nullptr;
  std::vector<std::string> path;
  static V unknown(std::string s) {
    V v;
    v.text = std::move(s);
    return v;
  }
  static V integer(int64_t n, bool isUnsigned = false) {
    V v;
    v.kind = Integer;
    v.number = n;
    v.unsignedInteger = isUnsigned;
    return v;
  }
  static V string(std::string s) {
    V v;
    v.kind = String;
    v.text = std::move(s);
    return v;
  }
  static V symbol(Kind k, int id, std::string encoding = "libc") {
    V v;
    v.kind = k;
    v.number = id;
    v.text = encoding;
    return v;
  }
  static V expr(std::string op, std::vector<V> args) {
    V v;
    v.kind = Expression;
    v.text = std::move(op);
    v.items = std::move(args);
    return v;
  }
};
static J::Value json(const V &v) {
  switch (v.kind) {
  case V::Integer:
    return v.unsignedInteger ? J::Value(uint64_t(v.number))
                             : J::Value(v.number);
  case V::String:
    return v.text;
  case V::Record: {
    J::Object o;
    for (auto &p : v.fields)
      o[p.first] = json(p.second);
    return o;
  }
  case V::Array: {
    J::Array a;
    for (auto &x : v.items)
      a.push_back(json(x));
    return a;
  }
  case V::Result:
    return J::Object{{"result_of", v.number}, {"encoding", v.text}};
  case V::Error:
    return J::Object{{"errno_of", v.number}};
  case V::Expression: {
    J::Array a;
    for (auto &x : v.items)
      a.push_back(json(x));
    return J::Object{{"op", v.text}, {"args", std::move(a)}};
  }
  case V::Pointer: {
    J::Array p;
    for (auto &x : v.path)
      p.push_back(x);
    return J::Object{
        {"pointer", v.root ? v.root->getNameAsString() : "unknown"},
        {"path", std::move(p)}};
  }
  default:
    return J::Object{{"unknown", v.text}};
  }
}
static bool same(const V &a, const V &b) {
  if (a.kind != b.kind || a.number != b.number || a.text != b.text ||
      a.root != b.root || a.path != b.path ||
      a.items.size() != b.items.size() || a.fields.size() != b.fields.size())
    return false;
  for (size_t i = 0; i < a.items.size(); i++)
    if (!same(a.items[i], b.items[i]))
      return false;
  auto x = a.fields.begin(), y = b.fields.begin();
  for (; x != a.fields.end(); ++x, ++y)
    if (x->first != y->first || !same(x->second, y->second))
      return false;
  return true;
}
static V operation(std::string op, const V &a, const V &b) {
  if (a.kind == V::Integer && b.kind == V::Integer) {
    int64_t x = a.number, y = b.number;
    bool u = a.unsignedInteger || b.unsignedInteger;
    uint64_t ux = x, uy = y;
    if (op == "==")
      return V::integer(x == y);
    if (op == "!=")
      return V::integer(x != y);
    if (op == "<")
      return V::integer(u ? ux < uy : x < y);
    if (op == "<=")
      return V::integer(u ? ux <= uy : x <= y);
    if (op == ">")
      return V::integer(u ? ux > uy : x > y);
    if (op == ">=")
      return V::integer(u ? ux >= uy : x >= y);
    if (op == "&&")
      return V::integer(x && y);
    if (op == "||")
      return V::integer(x || y);
    if (op == "&")
      return V::integer(x & y, u);
    if (op == "|")
      return V::integer(x | y, u);
    if (op == "^")
      return V::integer(x ^ y, u);
    // Unsigned arithmetic avoids host UB. Destination casts are handled by
    // Clang types.
    if (op == "+")
      return V::integer(ux + uy, u);
    if (op == "-")
      return V::integer(ux - uy, u);
    if (op == "*")
      return V::integer(ux * uy, u);
    if (op == "/" && y && u)
      return V::integer(ux / uy, true);
    if (op == "%" && y && u)
      return V::integer(ux % uy, true);
    if (op == "/" && y && !(x == INT64_MIN && y == -1))
      return V::integer(x / y);
    if (op == "%" && y && !(x == INT64_MIN && y == -1))
      return V::integer(x % y);
    if (op == "<<" && y >= 0 && y < 64)
      return V::integer(ux << y, u);
    if (op == ">>" && y >= 0 && y < 64)
      return V::integer(u ? ux >> y : uint64_t(x >> y), u);
  }
  return V::expr(std::move(op), {a, b});
}
static V negate(const V &v) {
  if (v.kind == V::Integer)
    return V::integer(!v.number);
  return V::expr("!", {v});
}
static void references(const V &v, std::set<int> &ids) {
  if (v.kind == V::Result || v.kind == V::Error)
    ids.insert(v.number);
  for (auto &x : v.items)
    references(x, ids);
  for (auto &p : v.fields)
    references(p.second, ids);
}
static bool concrete(const V &v) {
  if (v.kind == V::Unknown || v.kind == V::Expression || v.kind == V::Result ||
      v.kind == V::Error || v.kind == V::Pointer)
    return false;
  for (auto &x : v.items)
    if (!concrete(x))
      return false;
  for (auto &p : v.fields)
    if (!concrete(p.second))
      return false;
  return true;
}

struct State {
  std::map<const ValueDecl *, V> env;
  std::vector<V> guards;
  int lastCall = -1;
};
struct Observation {
  V predicate;
  std::vector<V> guards;
};
struct Invocation {
  int id;
  std::string name;
  std::vector<V> args;
  std::vector<Observation> observations;
  bool complete = true;
};
struct Constraint {
  std::string op;
  int64_t value;
};
struct FinalResult {
  std::optional<Constraint> ret;
  std::optional<Constraint> error;
};
enum Flow { Normal, Returned, Continued, Broken, Skipped, Unsupported };
struct Outcome {
  Flow flow = Normal;
  V value;
};

class Extractor {
  ASTContext &C;
  SourceManager &SM;
  std::map<std::string, const FunctionDecl *> definitions;
  std::vector<Invocation> calls;
  J::Array records;
  J::Array functions;
  std::set<std::string> seenRecords;
  std::set<std::string> incompleteReasons;
  unsigned depth = 0;
  bool analysisIncomplete = false;

public:
  explicit Extractor(ASTContext &c) : C(c), SM(c.getSourceManager()) {}
  J::Value location(SourceLocation loc) {
    auto p = SM.getPresumedLoc(SM.getExpansionLoc(loc));
    if (p.isInvalid())
      return nullptr;
    return J::Object{{"file", p.getFilename()},
                     {"line", p.getLine()},
                     {"column", p.getColumn()}};
  }
  std::string source(const Stmt *s) {
    if (!s)
      return "";
    auto range = SM.getExpansionRange(s->getSourceRange());
    return Lexer::getSourceText(range, SM, C.getLangOpts()).str();
  }
  std::string macro(const Stmt *s) {
    if (!s || !s->getBeginLoc().isMacroID())
      return "";
    auto loc = SM.getExpansionLoc(s->getBeginLoc());
    return Lexer::getSourceText(CharSourceRange::getTokenRange(loc, loc), SM,
                                C.getLangOpts())
        .str();
  }
  void warn(const Stmt *, std::string reason) {
    analysisIncomplete = true;
    incompleteReasons.insert(std::move(reason));
  }
  V zero(QualType t) {
    if (auto *a = C.getAsConstantArrayType(t)) {
      V v;
      v.kind = V::Array;
      auto n = a->getSize().getLimitedValue(4097);
      if (n > 4096)
        return V::unknown("array too large");
      for (uint64_t i = 0; i < n; i++)
        v.items.push_back(zero(a->getElementType()));
      return v;
    }
    if (auto *r = t->getAs<RecordType>()) {
      if (r->getDecl()->isUnion())
        return V::unknown("union initialization unsupported");
      V v;
      v.kind = V::Record;
      for (auto *f : r->getDecl()->fields())
        v.fields[f->getNameAsString()] = zero(f->getType());
      return v;
    }
    return V::integer(0);
  }
  V load(const V &p, State &s) {
    if (p.kind != V::Pointer)
      return V::unknown("dereference of unresolved pointer");
    auto it = s.env.find(p.root);
    if (it == s.env.end())
      return V::unknown("uninitialized object");
    V v = it->second;
    for (auto &part : p.path) {
      if (v.kind == V::Record) {
        auto f = v.fields.find(part);
        if (f == v.fields.end())
          return V::unknown("unknown field");
        V next = f->second;
        v = std::move(next);
      } else if (v.kind == V::Array && part.size() > 1 && part[0] == '#') {
        unsigned i = std::stoul(part.substr(1));
        if (i >= v.items.size())
          return V::unknown("array bounds");
        V next = v.items[i];
        v = std::move(next);
      } else
        return V::unknown("unresolved memory path");
    }
    return v;
  }
  void store(const V &p, V v, State &s) {
    if (p.kind != V::Pointer || !p.root)
      return;
    V *slot = &s.env[p.root];
    for (auto &part : p.path) {
      if (slot->kind == V::Record)
        slot = &slot->fields[part];
      else if (slot->kind == V::Array && part.size() > 1 && part[0] == '#') {
        unsigned i = std::stoul(part.substr(1));
        if (i >= slot->items.size())
          return;
        slot = &slot->items[i];
      } else {
        *slot = V::unknown("unsupported memory write");
        return;
      }
    }
    *slot = std::move(v);
  }
  V address(const Expr *e, State &s) {
    e = e->IgnoreParenImpCasts();
    if (auto *d = dyn_cast<DeclRefExpr>(e)) {
      V v;
      v.kind = V::Pointer;
      v.root = d->getDecl();
      return v;
    }
    if (auto *u = dyn_cast<UnaryOperator>(e))
      if (u->getOpcode() == UO_Deref)
        return eval(u->getSubExpr(), s);
    if (auto *m = dyn_cast<MemberExpr>(e)) {
      V p = m->isArrow() ? eval(m->getBase(), s) : address(m->getBase(), s);
      if (p.kind == V::Pointer)
        p.path.push_back(m->getMemberDecl()->getNameAsString());
      return p;
    }
    if (auto *a = dyn_cast<ArraySubscriptExpr>(e)) {
      V p = address(a->getBase(), s), i = eval(a->getIdx(), s);
      if (p.kind == V::Pointer && i.kind == V::Integer && i.number >= 0)
        p.path.push_back("#" + std::to_string(i.number));
      else
        return V::unknown("symbolic array index");
      return p;
    }
    return V::unknown("unsupported lvalue");
  }
  V snapshot(V v, State &s, unsigned nesting = 0) {
    if (nesting > 8)
      return V::unknown("pointer cycle");
    if (v.kind == V::Pointer) {
      V out;
      out.kind = V::Record;
      out.fields["pointee"] = snapshot(load(v, s), s, nesting + 1);
      return out;
    }
    for (auto &x : v.items)
      x = snapshot(x, s, nesting + 1);
    for (auto &p : v.fields)
      p.second = snapshot(p.second, s, nesting + 1);
    return v;
  }
  V cast(V v, QualType type) {
    if (v.kind != V::Integer || !type->isIntegerType())
      return v;
    unsigned bits = C.getIntWidth(type);
    v.unsignedInteger = type->isUnsignedIntegerType();
    if (bits < 64) {
      uint64_t mask = (uint64_t(1) << bits) - 1, n = uint64_t(v.number) & mask;
      if (type->isSignedIntegerType() && (n & (uint64_t(1) << (bits - 1))))
        n |= ~mask;
      v.number = n;
    }
    return v;
  }
  V eval(const Expr *e, State &s) {
    if (!e)
      return V::unknown("missing expression");
    if (auto *p = dyn_cast<ParenExpr>(e))
      return eval(p->getSubExpr(), s);
    if (auto *x = dyn_cast<CastExpr>(e)) {
      if (x->getCastKind() == CK_ArrayToPointerDecay) {
        if (auto *str =
                dyn_cast<StringLiteral>(x->getSubExpr()->IgnoreParenImpCasts()))
          return V::string(str->getString().str());
        return address(x->getSubExpr(), s);
      }
      return cast(eval(x->getSubExpr(), s), x->getType());
    }
    if (auto *str = dyn_cast<StringLiteral>(e))
      return V::string(str->getString().str());
    if (auto *d = dyn_cast<DeclRefExpr>(e)) {
      auto it = s.env.find(d->getDecl());
      if (it != s.env.end())
        return it->second;
      if (auto *v = dyn_cast<VarDecl>(d->getDecl())) {
        if (v->hasGlobalStorage())
          return V::unknown("global:" + v->getNameAsString());
      }
    }
    Expr::EvalResult constant;
    if (!e->HasSideEffects(C) && e->EvaluateAsInt(constant, C)) {
      auto &n = constant.Val.getInt();
      if (n.getBitWidth() > 64)
        return V::unknown("integer wider than 64 bits");
      return V::integer(n.isUnsigned() ? n.getZExtValue() : n.getSExtValue(),
                        n.isUnsigned());
    }
    if (isa<ImplicitValueInitExpr>(e))
      return zero(e->getType());
    if (auto *list = dyn_cast<InitListExpr>(e)) {
      if (list->isSyntacticForm() && list->getSemanticForm())
        list = list->getSemanticForm();
      V v = zero(e->getType());
      if (v.kind == V::Array) {
        for (unsigned i = 0; i < list->getNumInits() && i < v.items.size(); i++)
          v.items[i] = eval(list->getInit(i), s);
      } else if (auto *r = e->getType()->getAs<RecordType>()) {
        unsigned i = 0;
        for (auto *f : r->getDecl()->fields()) {
          if (i < list->getNumInits())
            v.fields[f->getNameAsString()] = eval(list->getInit(i), s);
          ++i;
        }
      }
      return v;
    }
    if (auto *m = dyn_cast<MemberExpr>(e))
      return load(address(m, s), s);
    if (auto *a = dyn_cast<ArraySubscriptExpr>(e))
      return load(address(a, s), s);
    if (auto *u = dyn_cast<UnaryOperator>(e)) {
      if (u->getOpcode() == UO_AddrOf)
        return address(u->getSubExpr(), s);
      if (u->getOpcode() == UO_Deref) {
        auto *call = dyn_cast<CallExpr>(u->getSubExpr()->IgnoreParenImpCasts());
        if (call && call->getDirectCallee() &&
            call->getDirectCallee()->getName() == "__errno_location")
          return s.lastCall >= 0
                     ? V::symbol(V::Error, s.lastCall)
                     : V::unknown("errno has no known originating call");
        return load(eval(u->getSubExpr(), s), s);
      }
      V a = eval(u->getSubExpr(), s);
      if (u->isIncrementDecrementOp()) {
        V b = operation(u->isIncrementOp() ? "+" : "-", a, V::integer(1));
        store(address(u->getSubExpr(), s), b, s);
        return u->isPostfix() ? a : b;
      }
      if (u->getOpcode() == UO_LNot)
        return negate(a);
      if (u->getOpcode() == UO_Minus)
        return a.kind == V::Integer
                   ? V::integer(uint64_t(0) - uint64_t(a.number))
                   : V::expr("neg", {a});
      if (u->getOpcode() == UO_Not && a.kind == V::Integer)
        return V::integer(~a.number);
      if (u->getOpcode() == UO_Plus)
        return a;
      return V::unknown("unsupported unary expression");
    }
    if (auto *b = dyn_cast<BinaryOperator>(e)) {
      if (b->getOpcode() == BO_Assign) {
        V v = eval(b->getRHS(), s);
        store(address(b->getLHS(), s), v, s);
        return v;
      }
      V a = eval(b->getLHS(), s);
      if (b->getOpcode() == BO_LAnd && a.kind == V::Integer && !a.number)
        return V::integer(0);
      if (b->getOpcode() == BO_LOr && a.kind == V::Integer && a.number)
        return V::integer(1);
      V rhs = eval(b->getRHS(), s);
      if (b->isCompoundAssignmentOp()) {
        std::string op = b->getOpcodeStr().str();
        op.pop_back();
        V v = operation(op, a, rhs);
        store(address(b->getLHS(), s), v, s);
        return v;
      }
      if (b->getOpcode() == BO_Comma)
        return rhs;
      return cast(operation(b->getOpcodeStr().str(), a, rhs), e->getType());
    }
    if (auto *q = dyn_cast<ConditionalOperator>(e)) {
      V cond = eval(q->getCond(), s);
      if (cond.kind == V::Integer)
        return eval(cond.number ? q->getTrueExpr() : q->getFalseExpr(), s);
      if (q->getTrueExpr()->HasSideEffects(C) ||
          q->getFalseExpr()->HasSideEffects(C))
        return V::unknown("conditional side effects");
      V yes = eval(q->getTrueExpr(), s), no = eval(q->getFalseExpr(), s);
      // Prove the common wrapper transformation: r >= 0 ? r : -errno.
      if (cond.kind == V::Expression && cond.text == ">=" &&
          cond.items.size() == 2 && same(cond.items[0], yes) &&
          same(cond.items[1], V::integer(0)) && yes.kind == V::Result &&
          no.kind == V::Expression && no.text == "neg" &&
          no.items.size() == 1 && no.items[0].kind == V::Error &&
          no.items[0].number == yes.number) {
        yes.text = "negative_errno";
        return yes;
      }
      return V::expr("?:", {cond, yes, no});
    }
    if (auto *call = dyn_cast<CallExpr>(e))
      return invoke(call, s);
    if (e->HasSideEffects(C)) {
      warn(e, "unsupported expression with side effects");
      for (auto &p : s.env)
        p.second = V::unknown("state invalidated by unsupported expression");
      s.lastCall = -1;
    }
    return V::unknown("unsupported expression:" +
                      std::string(e->getStmtClassName()));
  }
  bool wrapper(const FunctionDecl *f) {
    // Only inline straight-line wrappers. General helpers remain opaque.
    auto *body = dyn_cast_or_null<CompoundStmt>(f->getBody());
    if (!body || body->size() > 8)
      return false;
    bool returns = false;
    for (auto *x : body->body()) {
      if (isa<ReturnStmt>(x))
        returns = true;
      else if (!isa<DeclStmt>(x))
        return false;
    }
    return returns;
  }
  V invoke(const CallExpr *call, State &s) {
    const FunctionDecl *callee = call->getDirectCallee();
    std::string name = callee ? callee->getNameAsString() : "<indirect>";
    std::vector<V> args;
    for (auto *a : call->arguments())
      args.push_back(eval(a, s));
    if (name == "syscall") {
      if (args.empty())
        return V::unknown("syscall without number");
      std::string syscallName = source(call->getArg(0));
      if (syscallName.rfind("__NR_", 0) == 0)
        syscallName.erase(0, 5);
      else if (syscallName.rfind("SYS_", 0) == 0)
        syscallName.erase(0, 4);
      else if (args[0].kind == V::Integer) {
        auto known = SyscallNames.find(args[0].number);
        syscallName = known == SyscallNames.end()
                          ? "number:" + std::to_string(args[0].number)
                          : known->second;
      } else
        syscallName = "number:unknown";
      int id = calls.size();
      std::vector<V> inputs;
      for (unsigned i = 1; i < args.size(); i++)
        inputs.push_back(snapshot(args[i], s));
      calls.push_back({id, syscallName, inputs, {}});
      s.lastCall = id;
      // Kernel writes are unknown unless a future extension supplies a model.
      for (unsigned i = 1; i < args.size(); i++)
        if (args[i].kind == V::Pointer)
          store(args[i], V::unknown("memory may be written by syscall"), s);
      return V::symbol(V::Result, id);
    }
    auto it = definitions.find(name);
    if (it != definitions.end() && depth < 8 && wrapper(it->second)) {
      State child = s;
      unsigned i = 0;
      for (auto *p : it->second->parameters())
        child.env[p] =
            i < args.size() ? args[i++] : V::unknown("missing argument");
      ++depth;
      auto out = execute(it->second->getBody(), child);
      --depth;
      // Preserve caller object mutations and errno provenance.
      for (auto &p : s.env) {
        auto x = child.env.find(p.first);
        if (x != child.env.end())
          p.second = x->second;
      }
      s.lastCall = child.lastCall;
      if (out.flow == Returned)
        return out.value;
      return V::unknown("wrapper did not return");
    }
    s.lastCall = -1; // Never attach a stale errno to an earlier syscall.
    for (auto &v : args)
      if (v.kind == V::Pointer)
        store(v, V::unknown("memory may be written by opaque call:" + name), s);
    return V::unknown("return of opaque call:" + name);
  }
  void observation(std::string op, V a, V b, State &s) {
    V pred = operation(op, a, b);
    std::set<int> ids;
    references(pred, ids);
    for (int id : ids)
      if (id >= 0 && unsigned(id) < calls.size())
        calls[id].observations.push_back({pred, s.guards});
  }
  bool assertion(const DoStmt *d, State &s, std::string m) {
    bool namedAssertion = m.rfind("EXPECT_", 0) == 0 ||
                          m.rfind("ASSERT_", 0) == 0;
    std::string op;
    if (namedAssertion) {
      std::string suffix = m.substr(m.find('_') + 1);
      if (suffix == "EQ") op = "==";
      else if (suffix == "NE") op = "!=";
      else if (suffix == "GE") op = ">=";
      else if (suffix == "GT") op = ">";
      else if (suffix == "LE") op = "<=";
      else if (suffix == "LT") op = "<";
      else if (suffix == "TRUE") op = "!=";
      else if (suffix == "FALSE") op = "==";
      else {
        warn(d, "unsupported assertion macro:" + m);
        return true;
      }
    }
    auto *body = dyn_cast<CompoundStmt>(d->getBody());
    if (!body)
      return false;
    V a = V::unknown("assertion operand"), b = a;
    bool haveA = false, haveB = false;
    for (auto *stmt : body->body()) {
      if (auto *ds = dyn_cast<DeclStmt>(stmt))
        for (auto *decl : ds->decls())
          if (auto *v = dyn_cast<VarDecl>(decl)) {
            if (v->getName() == "__exp") {
              a = eval(v->getInit(), s);
              haveA = true;
            }
            if (v->getName() == "__seen") {
              b = eval(v->getInit(), s);
              haveB = true;
            }
          }
      if (op.empty())
        if (auto *branch = dyn_cast<IfStmt>(stmt)) {
          const Expr *condition = branch->getCond()->IgnoreParenImpCasts();
          if (auto *negation = dyn_cast<UnaryOperator>(condition))
            if (negation->getOpcode() == UO_LNot)
              condition = negation->getSubExpr()->IgnoreParenImpCasts();
          if (auto *comparison = dyn_cast<BinaryOperator>(condition))
            if (comparison->isComparisonOp())
              op = comparison->getOpcodeStr().str();
        }
    }
    if (!haveA || !haveB) {
      if (!namedAssertion)
        return false;
      warn(d, "unrecognized assertion expansion");
      return true;
    }
    if (op.empty()) {
      warn(d, "assertion comparison was not recovered");
      return true;
    }
    observation(op, a, b, s);
    return true;
  }
  State join(const State &a, const State &b, const State &before) {
    State out = before;
    for (auto &p : a.env) {
      auto q = b.env.find(p.first);
      out.env[p.first] = (q != b.env.end() && same(p.second, q->second))
                             ? p.second
                             : V::unknown("value differs across branches");
    }
    for (auto &p : b.env)
      if (!a.env.count(p.first))
        out.env[p.first] = V::unknown("value missing on branch");
    out.lastCall = a.lastCall == b.lastCall ? a.lastCall : -1;
    return out;
  }
  Outcome execute(const Stmt *stmt, State &s) {
    if (!stmt)
      return {};
    std::string m = macro(stmt);
    if (m == "TH_LOG")
      return {}; // Diagnostic macro; assertions handle their own failure path.
    if (auto *d = dyn_cast<DoStmt>(stmt)) {
      if (assertion(d, s, m))
        return {};
      std::string text = source(d);
      if (text.find("fprintf") != std::string::npos &&
          text.find("# %s:%d:%s:") != std::string::npos)
        return {}; // Expanded diagnostic-only TH_LOG block.
    }
    if (auto *loop = dyn_cast<ForStmt>(stmt))
      if ((m.rfind("EXPECT_", 0) == 0 || m.rfind("ASSERT_", 0) == 0) ||
          (loop->getInc() && source(loop->getInc()).find("__bail") !=
                                 std::string::npos))
        return {}; // optional assertion failure handler
    if (m == "SKIP")
      return {Skipped, {}};
    if (auto *body = dyn_cast<CompoundStmt>(stmt)) {
      for (auto *x : body->body()) {
        auto out = execute(x, s);
        if (out.flow != Normal)
          return out;
      }
      return {};
    }
    if (auto *d = dyn_cast<DeclStmt>(stmt)) {
      for (auto *decl : d->decls())
        if (auto *v = dyn_cast<VarDecl>(decl))
          s.env[v] = v->hasInit()
                         ? eval(v->getInit(), s)
                         : V::unknown("uninitialized:" + v->getNameAsString());
      return {};
    }
    if (auto *r = dyn_cast<ReturnStmt>(stmt))
      return {Returned, eval(r->getRetValue(), s)};
    if (isa<ContinueStmt>(stmt))
      return {Continued, {}};
    if (isa<BreakStmt>(stmt))
      return {Broken, {}};
    if (isa<NullStmt>(stmt))
      return {};
    if (auto *i = dyn_cast<IfStmt>(stmt)) {
      if (i->getInit())
        execute(i->getInit(), s);
      V cond = eval(i->getCond(), s);
      if (cond.kind == V::Integer)
        return execute(cond.number ? i->getThen() : i->getElse(), s);
      State before = s, yes = s, no = s;
      yes.guards.push_back(cond);
      no.guards.push_back(negate(cond));
      Outcome x = execute(i->getThen(), yes), y = execute(i->getElse(), no);
      if (x.flow == Normal && y.flow == Normal) {
        s = join(yes, no, before);
        return {};
      }
      if (x.flow == Normal) {
        s = std::move(yes);
        return {};
      }
      if (y.flow == Normal) {
        s = std::move(no);
        return {};
      }
      if (x.flow == Returned && y.flow == Returned)
        return {Returned, V::expr("?:", {cond, x.value, y.value})};
      if (x.flow == y.flow)
        return x;
      warn(stmt, "incompatible branch control flow");
      return {Unsupported, {}};
    }
    if (auto *f = dyn_cast<ForStmt>(stmt)) {
      auto start = execute(f->getInit(), s);
      if (start.flow != Normal)
        return start;
      for (unsigned n = 0; n < LoopLimit; n++) {
        V cond = eval(f->getCond(), s);
        if (cond.kind != V::Integer) {
          warn(f, "loop condition is not statically concrete");
          return {Unsupported, {}};
        }
        if (!cond.number)
          return {};
        auto out = execute(f->getBody(), s);
        if (out.flow == Broken)
          return {};
        if (out.flow != Normal && out.flow != Continued)
          return out;
        eval(f->getInc(), s);
      }
      warn(f, "loop unroll limit reached");
      return {Unsupported, {}};
    }
    if (auto *e = dyn_cast<Expr>(stmt)) {
      eval(e, s);
      return {};
    }
    warn(stmt,
         "unsupported statement:" + std::string(stmt->getStmtClassName()));
    return {Unsupported, {}};
  }
  static std::optional<std::string> reverseComparison(llvm::StringRef op) {
    if (op == "==" || op == "!=") return op.str();
    if (op == ">") return "<";
    if (op == "<") return ">";
    if (op == ">=") return "<=";
    if (op == "<=") return ">=";
    return std::nullopt;
  }
  static bool satisfies(int64_t value, const Constraint &constraint) {
    if (constraint.op == "==") return value == constraint.value;
    if (constraint.op == "!=") return value != constraint.value;
    if (constraint.op == ">") return value > constraint.value;
    if (constraint.op == "<") return value < constraint.value;
    if (constraint.op == ">=") return value >= constraint.value;
    if (constraint.op == "<=") return value <= constraint.value;
    return false;
  }
  static bool addConstraint(std::optional<Constraint> &slot,
                            std::string op, int64_t value) {
    Constraint next{std::move(op), value};
    if (!slot) {
      slot = std::move(next);
      return true;
    }
    if (slot->op == next.op && slot->value == next.value)
      return true;
    if (slot->op == "==")
      return satisfies(slot->value, next);
    if (next.op == "==") {
      if (!satisfies(next.value, *slot)) return false;
      slot = std::move(next);
      return true;
    }
    return false;
  }
  static bool normalize(const V &predicate, int callId, FinalResult &result) {
    if (predicate.kind != V::Expression || predicate.items.size() != 2)
      return false;
    const V *left = &predicate.items[0], *right = &predicate.items[1];
    std::string op = predicate.text;
    if (left->kind == V::Integer &&
        (right->kind == V::Result || right->kind == V::Error)) {
      std::swap(left, right);
      auto reversed = reverseComparison(op);
      if (!reversed) return false;
      op = *reversed;
    }
    if (right->kind != V::Integer || left->number != callId)
      return false;
    if (left->kind == V::Error)
      return addConstraint(result.error, op, right->number);
    if (left->kind != V::Result)
      return false;
    if (left->text == "libc")
      return addConstraint(result.ret, op, right->number);
    if (left->text != "negative_errno")
      return false;
    if (op == "==" && right->number < 0 && right->number != INT64_MIN)
      return addConstraint(result.ret, "==", -1) &&
             addConstraint(result.error, "==", -right->number);
    if (right->number >= 0 &&
        (op == "==" || op == ">=" || op == ">"))
      return addConstraint(result.ret, op, right->number);
    return false;
  }
  static std::optional<FinalResult> finalResult(const Invocation &call) {
    FinalResult result;
    for (auto &observation : call.observations) {
      FinalResult withPredicate = result;
      if (!normalize(observation.predicate, call.id, withPredicate))
        return std::nullopt;
      result = std::move(withPredicate);
      // Simple guards on this call are part of the selected result scenario.
      // Guards on earlier calls or unknown environment state are intentionally
      // omitted from the compact syscall/result record.
      for (auto &guard : observation.guards) {
        FinalResult withGuard = result;
        if (normalize(guard, call.id, withGuard))
          result = std::move(withGuard);
      }
    }
    if (result.error) {
      if (result.ret && !satisfies(-1, *result.ret))
        return std::nullopt;
      result.ret = Constraint{"==", -1};
    }
    if (!result.ret && !result.error)
      return std::nullopt;
    return result;
  }
  static J::Object constraintJson(const Constraint &constraint) {
    return J::Object{{"op", constraint.op}, {"value", constraint.value}};
  }
  std::optional<J::Value> record(const Invocation &call) {
    if (!Syscalls.empty() &&
        std::find(Syscalls.begin(), Syscalls.end(), call.name) == Syscalls.end())
      return std::nullopt;
    if (call.observations.empty() || !call.complete ||
        std::any_of(call.args.begin(), call.args.end(),
                    [](const V &v) { return !concrete(v); }))
      return std::nullopt;
    auto result = finalResult(call);
    if (!result)
      return std::nullopt;
    J::Array args;
    for (auto &v : call.args)
      args.push_back(json(v));
    J::Object constraints;
    if (result->ret)
      constraints["ret"] = constraintJson(*result->ret);
    if (result->error)
      constraints["errno"] = constraintJson(*result->error);
    return J::Object{{"syscall", call.name},
                     {"args", std::move(args)},
                     {"result", std::move(constraints)}};
  }
  bool fromPrimarySource(const FunctionDecl *function) {
    if (PrimarySource.empty())
      return SM.isWrittenInMainFile(SM.getExpansionLoc(function->getLocation()));
    auto location = SM.getPresumedLoc(SM.getExpansionLoc(function->getLocation()));
    return location.isValid() && PrimarySource == location.getFilename();
  }
  void analyze(const FunctionDecl *function) {
    calls.clear();
    analysisIncomplete = false;
    incompleteReasons.clear();
    State state;
    for (auto *parameter : function->parameters())
      state.env[parameter] =
          V::unknown("function parameter:" + parameter->getNameAsString());
    execute(function->getBody(), state);
    for (auto &call : calls)
      call.complete = !analysisIncomplete;

    unsigned count = 0;
    for (auto &call : calls) {
      auto value = record(call);
      if (!value)
        continue;
      ++count;
      std::string key = llvm::formatv("{0}", *value).str();
      if (seenRecords.insert(key).second)
        records.push_back(std::move(*value));
    }
    J::Object result{{"function", function->getNameAsString()},
                     {"source", location(function->getLocation())},
                     {"invocation_count", calls.size()},
                     {"record_count", count}};
    if (analysisIncomplete) {
      result["status"] = "unsupported";
      result["reason"] = "unsupported_construct";
      J::Array reasons;
      for (auto &reason : incompleteReasons)
        reasons.push_back(reason);
      result["reasons"] = std::move(reasons);
    } else if (count) {
      result["status"] = "extracted";
    } else {
      result["status"] = "no_records";
      result["reason"] = "no_concrete_normalized_records";
    }
    functions.push_back(std::move(result));
  }
  void run(TranslationUnitDecl *unit) {
    for (auto *decl : unit->decls())
      if (auto *f = dyn_cast<FunctionDecl>(decl))
        if (f->doesThisDeclarationHaveABody())
          definitions[f->getNameAsString()] = f;

    if (AllFunctions)
      for (auto *decl : unit->decls())
        if (auto *function = dyn_cast<FunctionDecl>(decl))
          if (function->doesThisDeclarationHaveABody() &&
              !function->getName().empty() && fromPrimarySource(function))
            analyze(function);

    for (auto &name : Functions) {
      auto found = definitions.find(name);
      if (found != definitions.end()) {
        analyze(found->second);
        continue;
      }
      functions.push_back(J::Object{{"function", name},
                                    {"status", "unsupported"},
                                    {"reason", "function_not_found"},
                                    {"record_count", 0}});
    }
  }
  J::Value output() {
    J::Array warnings;
    for (auto &warning : StartupWarnings)
      warnings.push_back(warning);
    return J::Object{{"schema_version", 1},
                     {"artifact", InputFile.getValue()},
                     {"source", PrimarySource},
                     {"target", C.getTargetInfo().getTriple().str()},
                     {"target_source", TargetOrigin},
                     {"warnings", std::move(warnings)},
                     {"functions", std::move(functions)},
                     {"records", std::move(records)}};
  }
};

class Consumer : public ASTConsumer {
public:
  void HandleTranslationUnit(ASTContext &context) override {
    Extractor extractor(context);
    extractor.run(context.getTranslationUnitDecl());
    llvm::outs() << llvm::formatv("{0:2}\n", extractor.output());
  }
};
class Action : public ASTFrontendAction {
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &,
                                                 llvm::StringRef) override {
    return std::make_unique<Consumer>();
  }
};
int main(int argc, const char **argv) {
  llvm::cl::HideUnrelatedOptions(Category);
  llvm::cl::ParseCommandLineOptions(argc, argv);
  if (Functions.empty() == !AllFunctions) {
    llvm::errs() << "Specify either --all-functions or at least one --function.\n";
    return 2;
  }
  llvm::StringRef extension = llvm::sys::path::extension(InputFile);
  if (extension != ".i" && extension != ".ii") {
    llvm::errs() << "Input must be a preprocessed .i or .ii file.\n";
    return 2;
  }

  if (!SourceFile.empty())
    PrimarySource = SourceFile;
  if (!inspectPreprocessedInput(InputFile))
    return 2;

  std::string effectiveTarget = Target;
  if (!effectiveTarget.empty()) {
    TargetOrigin = "explicit";
  } else {
    llvm::SmallString<256> bitcodePath;
    if (!Bitcode.empty())
      bitcodePath = Bitcode;
    else {
      bitcodePath = InputFile;
      llvm::sys::path::replace_extension(bitcodePath, ".bc");
    }
    if (!bitcodePath.empty() && llvm::sys::fs::exists(bitcodePath))
      if (auto inferred = bitcodeTarget(bitcodePath)) {
        effectiveTarget = *inferred;
        TargetOrigin = "bitcode";
      }
  }

  std::vector<std::string> clangArguments{
      "-fsyntax-only", "-Wno-everything", "-x",
      extension == ".ii" ? "c++-cpp-output" : "cpp-output"};
  if (!effectiveTarget.empty())
    clangArguments.push_back("--target=" + effectiveTarget);
  tooling::FixedCompilationDatabase compilations(".", clangArguments);
  tooling::ClangTool tool(compilations, {InputFile});
  return tool.run(tooling::newFrontendActionFactory<Action>().get());
}
