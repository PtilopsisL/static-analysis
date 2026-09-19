// Extract concrete syscall expectations by analyzing original source with the
// exact command recorded in compile_commands.json. The analyzed program is
// never linked or executed.
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <clang/AST/ASTContext.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>
#include <clang/Analysis/CFG.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Lex/Lexer.h>
#include <clang/StaticAnalyzer/Core/AnalyzerOptions.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/CheckerManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h>
#include <clang/StaticAnalyzer/Frontend/AnalysisConsumer.h>
#include <clang/StaticAnalyzer/Frontend/CheckerRegistry.h>
#include <clang/Tooling/ArgumentsAdjusters.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/JSONCompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/JSON.h>

using namespace clang;
using namespace clang::ento;
namespace tooling = clang::tooling;
namespace json = llvm::json;

static llvm::cl::OptionCategory Category("syscall expectation extraction");
static llvm::cl::opt<std::string>
    CompDB("compdb", llvm::cl::desc("Path to compile_commands.json"),
           llvm::cl::value_desc("file"), llvm::cl::Required,
           llvm::cl::cat(Category));
static llvm::cl::opt<unsigned>
    UnitIndex("unit-index", llvm::cl::desc("Zero-based compile-command index"),
              llvm::cl::init(0), llvm::cl::cat(Category));
static llvm::cl::list<std::string>
    Functions("function",
              llvm::cl::desc("Top-level function to analyze (repeatable)"),
              llvm::cl::cat(Category));
static llvm::cl::opt<bool>
    AllFunctions("all-functions",
                 llvm::cl::desc("Analyze all source functions"),
                 llvm::cl::init(false), llvm::cl::cat(Category));
static llvm::cl::list<std::string>
    Syscalls("syscall", llvm::cl::desc("Syscall name to emit (repeatable)"),
             llvm::cl::cat(Category));

struct ConcreteValue {
  enum Kind { Integer, String, Object } kind = Integer;
  uint64_t bits = 0;
  bool isUnsigned = false;
  std::string text;
  std::map<std::string, ConcreteValue> fields;

  static ConcreteValue integer(uint64_t Bits, bool Unsigned) {
    ConcreteValue V;
    V.bits = Bits;
    V.isUnsigned = Unsigned;
    return V;
  }
  static ConcreteValue string(std::string Text) {
    ConcreteValue V;
    V.kind = String;
    V.text = std::move(Text);
    return V;
  }
  static ConcreteValue object(std::map<std::string, ConcreteValue> Fields) {
    ConcreteValue V;
    V.kind = Object;
    V.fields = std::move(Fields);
    return V;
  }
};

static json::Value toJSON(const ConcreteValue &V) {
  if (V.kind == ConcreteValue::String)
    return V.text;
  if (V.kind == ConcreteValue::Object) {
    json::Object O;
    for (const auto &[Name, Field] : V.fields)
      O[Name] = toJSON(Field);
    return O;
  }
  if (V.isUnsigned)
    return V.bits;
  return static_cast<int64_t>(V.bits);
}

struct ResultConstraint {
  std::string op;
  int64_t value = 0;
};

struct ConstraintSet {
  std::optional<ResultConstraint> ret;
  std::optional<ResultConstraint> error;
};

struct Invocation {
  std::string function;
  std::string syscall;
  std::vector<ConcreteValue> args;
  bool concrete = false;
};

struct Subject {
  const Invocation *call = nullptr;
  bool error = false;
  int sign = 1;
};

struct PendingConstraint {
  Subject subject;
  ResultConstraint result;
};

using ConstraintClause = std::vector<PendingConstraint>;
using Predicate = std::vector<ConstraintClause>;

struct PredicateBinding {
  SVal value;
  std::optional<Predicate> whenTrue;
  std::optional<Predicate> whenFalse;
};

class Collector {
  struct EmittedRecord {
    std::string function;
    std::string baseKey;
    std::string fullKey;
    ConstraintSet result;
    json::Object object;
  };

  std::set<std::string> SelectedFunctions;
  std::set<std::string> SelectedSyscalls;
  std::vector<std::unique_ptr<Invocation>> Invocations;
  std::vector<std::unique_ptr<ConstraintSet>> Constraints;
  std::vector<std::unique_ptr<PendingConstraint>> PendingConstraints;
  std::vector<std::unique_ptr<PredicateBinding>> PredicateBindings;
  std::set<std::string> SeenFunctions;
  std::vector<EmittedRecord> Records;

  static json::Object constraintJSON(const ResultConstraint &C) {
    return json::Object{{"op", C.op}, {"value", C.value}};
  }

  static bool equal(const std::optional<ResultConstraint> &LHS,
                    const std::optional<ResultConstraint> &RHS) {
    if (LHS.has_value() != RHS.has_value())
      return false;
    return !LHS || (LHS->op == RHS->op && LHS->value == RHS->value);
  }

  static bool subset(const ConstraintSet &LHS, const ConstraintSet &RHS) {
    return (!LHS.ret || equal(LHS.ret, RHS.ret)) &&
           (!LHS.error || equal(LHS.error, RHS.error));
  }

  static std::string render(const json::Value &Value) {
    std::string Text;
    llvm::raw_string_ostream OS(Text);
    OS << Value;
    OS.flush();
    return Text;
  }

public:
  Collector() {
    SelectedFunctions.insert(Functions.begin(), Functions.end());
    SelectedSyscalls.insert(Syscalls.begin(), Syscalls.end());
  }

  bool wantsFunction(llvm::StringRef Name) const {
    return AllFunctions || SelectedFunctions.empty() ||
           SelectedFunctions.count(Name.str());
  }

  bool wantsSyscall(llvm::StringRef Name) const {
    return SelectedSyscalls.empty() || SelectedSyscalls.count(Name.str());
  }

  void seeFunction(llvm::StringRef Name) {
    if (wantsFunction(Name))
      SeenFunctions.insert(Name.str());
  }

  const Invocation *makeInvocation(Invocation Value) {
    Invocations.push_back(std::make_unique<Invocation>(std::move(Value)));
    return Invocations.back().get();
  }

  const ConstraintSet *makeConstraints(ConstraintSet Value) {
    Constraints.push_back(std::make_unique<ConstraintSet>(std::move(Value)));
    return Constraints.back().get();
  }

  const PendingConstraint *makePendingConstraint(PendingConstraint Value) {
    PendingConstraints.push_back(
        std::make_unique<PendingConstraint>(std::move(Value)));
    return PendingConstraints.back().get();
  }

  const PredicateBinding *makePredicateBinding(PredicateBinding Value) {
    PredicateBindings.push_back(
        std::make_unique<PredicateBinding>(std::move(Value)));
    return PredicateBindings.back().get();
  }

  void emit(const Invocation *Call, const ConstraintSet *Result) {
    if (!Call || !Result || !Call->concrete || !wantsFunction(Call->function) ||
        !wantsSyscall(Call->syscall) || (!Result->ret && !Result->error))
      return;

    json::Array BaseArgs;
    for (const ConcreteValue &Arg : Call->args)
      BaseArgs.push_back(toJSON(Arg));
    std::string BaseKey = render(json::Object{{"syscall", Call->syscall},
                                              {"args", std::move(BaseArgs)}});
    for (auto It = Records.begin(); It != Records.end();) {
      if (It->function != Call->function || It->baseKey != BaseKey) {
        ++It;
        continue;
      }
      if (subset(*Result, It->result))
        return;
      if (subset(It->result, *Result)) {
        It = Records.erase(It);
        continue;
      }
      ++It;
    }

    json::Array Args;
    for (const ConcreteValue &Arg : Call->args)
      Args.push_back(toJSON(Arg));
    json::Object ResultObject;
    if (Result->ret)
      ResultObject["ret"] = constraintJSON(*Result->ret);
    if (Result->error) {
      ResultObject["errno"] = constraintJSON(*Result->error);
      if (!Result->ret)
        ResultObject["ret"] = constraintJSON({"==", -1});
    }
    json::Object Record{{"syscall", Call->syscall},
                        {"args", std::move(Args)},
                        {"result", std::move(ResultObject)}};
    std::string FullKey = render(json::Object(Record));
    Records.push_back({Call->function, std::move(BaseKey), std::move(FullKey),
                       *Result, std::move(Record)});
  }

  json::Array functionJSON() const {
    json::Array Result;
    for (const std::string &Name : SeenFunctions) {
      unsigned Count = std::count_if(
          Records.begin(), Records.end(),
          [&](const EmittedRecord &Record) { return Record.function == Name; });
      Result.push_back(
          json::Object{{"function", Name},
                       {"status", Count ? "extracted" : "no_records"},
                       {"records", Count}});
    }
    return Result;
  }

  json::Array recordJSON() {
    json::Array Result;
    std::set<std::string> Seen;
    std::sort(Records.begin(), Records.end(),
              [](const EmittedRecord &LHS, const EmittedRecord &RHS) {
                return LHS.fullKey < RHS.fullKey;
              });
    for (EmittedRecord &Record : Records) {
      if (Seen.insert(Record.fullKey).second)
        Result.push_back(std::move(Record.object));
    }
    return Result;
  }
};

static Collector *ActiveCollector = nullptr;

REGISTER_MAP_WITH_PROGRAMSTATE(SyscallBySymbol, SymbolRef, const Invocation *)
REGISTER_MAP_WITH_PROGRAMSTATE(ErrnoBySymbol, SymbolRef, const Invocation *)
REGISTER_MAP_WITH_PROGRAMSTATE(ConstraintsByCall, const Invocation *,
                               const ConstraintSet *)
REGISTER_MAP_WITH_PROGRAMSTATE(ConstraintByComparison, const BinaryOperator *,
                               const PendingConstraint *)
REGISTER_MAP_WITH_PROGRAMSTATE(PredicateByRegion, const MemRegion *,
                               const PredicateBinding *)
REGISTER_TRAIT_WITH_PROGRAMSTATE(CurrentErrnoOwner, const Invocation *)

static const FunctionDecl *topFunction(const LocationContext *LC) {
  while (LC && LC->getParent())
    LC = LC->getParent();
  return LC ? dyn_cast<FunctionDecl>(LC->getDecl()) : nullptr;
}

static llvm::StringRef functionName(const LocationContext *LC) {
  if (const FunctionDecl *FD = topFunction(LC))
    return FD->getName();
  return {};
}

static const Expr *ignoreExpr(const Expr *E) {
  return E ? E->IgnoreParenImpCasts() : nullptr;
}

static const StringLiteral *findStringRegion(const MemRegion *R) {
  while (R) {
    if (const auto *SR = dyn_cast<StringRegion>(R))
      return SR->getStringLiteral();
    const auto *Sub = dyn_cast<SubRegion>(R);
    R = Sub ? Sub->getSuperRegion() : nullptr;
  }
  return nullptr;
}

static std::optional<ConcreteValue> snapshotValue(SVal Value, QualType Type,
                                                  ProgramStateRef State,
                                                  const LocationContext *LC,
                                                  unsigned Depth = 0);

static std::optional<ConcreteValue>
snapshotRegion(const MemRegion *Region, QualType Type, ProgramStateRef State,
               const LocationContext *LC, unsigned Depth) {
  if (!Region || Depth > 8)
    return std::nullopt;
  Type = Type.getCanonicalType();
  if (const auto *RT = Type->getAs<RecordType>()) {
    const RecordDecl *RD = RT->getDecl()->getDefinition();
    if (!RD)
      return std::nullopt;
    std::map<std::string, ConcreteValue> Fields;
    SVal Base = loc::MemRegionVal(Region);
    for (const FieldDecl *Field : RD->fields()) {
      SVal FieldLoc = State->getLValue(Field, Base);
      const MemRegion *FieldRegion = FieldLoc.getAsRegion();
      if (!FieldRegion)
        return std::nullopt;
      auto FieldValue =
          snapshotValue(State->getSVal(FieldRegion, Field->getType()),
                        Field->getType(), State, LC, Depth + 1);
      if (!FieldValue)
        return std::nullopt;
      Fields.emplace(Field->getNameAsString(), std::move(*FieldValue));
    }
    return ConcreteValue::object(std::move(Fields));
  }
  return snapshotValue(State->getSVal(Region, Type), Type, State, LC,
                       Depth + 1);
}

static std::optional<ConcreteValue> snapshotValue(SVal Value, QualType Type,
                                                  ProgramStateRef State,
                                                  const LocationContext *LC,
                                                  unsigned Depth) {
  if (Depth > 8)
    return std::nullopt;
  if (const llvm::APSInt *Integer = Value.getAsInteger()) {
    if (Integer->getBitWidth() > 64)
      return std::nullopt;
    bool Unsigned = Integer->isUnsigned() || Type->isUnsignedIntegerType();
    uint64_t Bits = Unsigned ? Integer->getZExtValue()
                             : static_cast<uint64_t>(Integer->getSExtValue());
    return ConcreteValue::integer(Bits, Unsigned);
  }
  if (const MemRegion *Region = Value.getAsRegion()) {
    if (const StringLiteral *Literal = findStringRegion(Region))
      return ConcreteValue::string(Literal->getString().str());
    if (Type->isPointerType()) {
      auto Pointee =
          snapshotRegion(Region, Type->getPointeeType(), State, LC, Depth + 1);
      if (!Pointee)
        return std::nullopt;
      return ConcreteValue::object({{"pointee", std::move(*Pointee)}});
    }
  }
  return std::nullopt;
}

static bool namedCall(const CallEvent &Call, llvm::StringRef Name) {
  const auto *ND = dyn_cast_or_null<NamedDecl>(Call.getDecl());
  return ND && ND->getName() == Name;
}

static std::string syscallName(const CallEvent &Call, int64_t Number,
                               CheckerContext &C) {
  if (Call.getNumArgs()) {
    const Expr *E = Call.getArgExpr(0);
    if (E) {
      llvm::StringRef Macro = Lexer::getImmediateMacroName(
          E->getExprLoc(), C.getSourceManager(), C.getLangOpts());
      if (Macro.consume_front("__NR_") && !Macro.empty())
        return Macro.str();
    }
  }
  switch (Number) {
  case 434:
    return "pidfd_open";
  case 437:
    return "openat2";
  case 438:
    return "pidfd_getfd";
  default:
    return "number:" + std::to_string(Number);
  }
}

static bool valuePreservingIntegerConversion(QualType From, QualType To,
                                             ASTContext &Context) {
  if (From.isNull() || To.isNull() || !From->isIntegerType() ||
      !To->isIntegerType() || From->isBooleanType() || To->isBooleanType())
    return false;
  bool SameSignedness =
      (From->isSignedIntegerType() && To->isSignedIntegerType()) ||
      (From->isUnsignedIntegerType() && To->isUnsignedIntegerType());
  return SameSignedness && Context.getIntWidth(To) >= Context.getIntWidth(From);
}

static bool valuePreservingCast(const SymbolCast *Cast, ASTContext &Context) {
  return valuePreservingIntegerConversion(Cast->getOperand()->getType(),
                                          Cast->getType(), Context);
}

static int signOf(const SymExpr *Expression, SymbolRef Atom,
                  ASTContext &Context) {
  if (Expression == Atom)
    return 1;
  if (const auto *Cast = dyn_cast<SymbolCast>(Expression)) {
    if (!valuePreservingCast(Cast, Context))
      return 0;
    return signOf(Cast->getOperand(), Atom, Context);
  }
  if (const auto *Unary = dyn_cast<UnarySymExpr>(Expression)) {
    int Sign = signOf(Unary->getOperand(), Atom, Context);
    return Unary->getOpcode() == UO_Minus ? -Sign : 0;
  }
  return 0;
}

static std::optional<Subject> findSubject(SVal Value, ProgramStateRef State,
                                          QualType ObservedType,
                                          ASTContext &Context) {
  const SymExpr *Expression = Value.getAsSymbol(true);
  if (!Expression)
    return std::nullopt;
  std::optional<Subject> Found;
  for (SymbolRef Atom : Value.symbols()) {
    const Invocation *const *Call = State->get<SyscallBySymbol>(Atom);
    bool Error = false;
    if (!Call) {
      Call = State->get<ErrnoBySymbol>(Atom);
      Error = true;
    }
    if (!Call)
      continue;
    // The analyzer may represent a same-width signedness cast with the
    // original symbol. Check the AST operand type as well as SymbolCast nodes
    // so such a conversion cannot inherit the syscall's integer semantics.
    if (!valuePreservingIntegerConversion(Atom->getType(), ObservedType,
                                          Context))
      return std::nullopt;
    int Sign = signOf(Expression, Atom, Context);
    if (!Sign || (Found && Found->call != *Call))
      return std::nullopt;
    Found = Subject{*Call, Error, Sign};
  }
  return Found;
}

static std::string reversedComparison(BinaryOperatorKind Op) {
  switch (Op) {
  case BO_EQ:
    return "==";
  case BO_NE:
    return "!=";
  case BO_LT:
    return ">";
  case BO_LE:
    return ">=";
  case BO_GT:
    return "<";
  case BO_GE:
    return "<=";
  default:
    return {};
  }
}

static std::string directComparison(BinaryOperatorKind Op) {
  switch (Op) {
  case BO_EQ:
    return "==";
  case BO_NE:
    return "!=";
  case BO_LT:
    return "<";
  case BO_LE:
    return "<=";
  case BO_GT:
    return ">";
  case BO_GE:
    return ">=";
  default:
    return {};
  }
}

static std::string negateComparison(std::string Op) {
  if (Op == "<")
    return ">";
  if (Op == "<=")
    return ">=";
  if (Op == ">")
    return "<";
  if (Op == ">=")
    return "<=";
  return Op;
}

static std::string negateTruth(std::string Op) {
  if (Op == "==")
    return "!=";
  if (Op == "!=")
    return "==";
  if (Op == "<")
    return ">=";
  if (Op == "<=")
    return ">";
  if (Op == ">")
    return "<=";
  if (Op == ">=")
    return "<";
  return {};
}

static bool errnoConstraintHasPositiveSolution(const ResultConstraint &C) {
  if (C.op == "==")
    return C.value > 0;
  if (C.op == "!=")
    return true;
  if (C.op == "<")
    return C.value > 1;
  if (C.op == "<=")
    return C.value >= 1;
  return C.op == ">" || C.op == ">=";
}

static SVal currentValue(const Expr *Expression, CheckerContext &C) {
  SVal Value = C.getSVal(Expression);
  const auto *Ref = dyn_cast_or_null<DeclRefExpr>(ignoreExpr(Expression));
  const auto *Variable = Ref ? dyn_cast<VarDecl>(Ref->getDecl()) : nullptr;
  if (!Variable)
    return Value;
  Loc Location = C.getState()->getLValue(Variable, C.getLocationContext());
  return C.getState()->getSVal(Location, Variable->getType());
}

static std::optional<llvm::APSInt>
concreteInteger(const Expr *Expression, SVal Value, CheckerContext &C) {
  if (const llvm::APSInt *Integer = Value.getAsInteger())
    return *Integer;
  Expr::EvalResult Result;
  if (Expression->EvaluateAsInt(Result, C.getASTContext()))
    return Result.Val.getInt();
  return std::nullopt;
}

static std::optional<PendingConstraint>
extractComparison(const BinaryOperator *Compare, CheckerContext &C) {
  if (!Compare || !Compare->isComparisonOp())
    return std::nullopt;
  SVal LHS = currentValue(Compare->getLHS(), C);
  SVal RHS = currentValue(Compare->getRHS(), C);
  auto LeftSubject = findSubject(
      LHS, C.getState(), Compare->getLHS()->getType(), C.getASTContext());
  auto RightSubject = findSubject(
      RHS, C.getState(), Compare->getRHS()->getType(), C.getASTContext());
  auto LeftInteger = concreteInteger(Compare->getLHS(), LHS, C);
  auto RightInteger = concreteInteger(Compare->getRHS(), RHS, C);
  Subject S;
  std::optional<llvm::APSInt> Integer;
  std::string Op;
  if (LeftSubject && RightInteger) {
    S = *LeftSubject;
    Integer = RightInteger;
    Op = directComparison(Compare->getOpcode());
  } else if (RightSubject && LeftInteger) {
    S = *RightSubject;
    Integer = LeftInteger;
    Op = reversedComparison(Compare->getOpcode());
  } else {
    return std::nullopt;
  }
  if (!Integer || Integer->getBitWidth() > 64 || Op.empty())
    return std::nullopt;
  if (Integer->isUnsigned() &&
      Integer->getZExtValue() >
          static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
    return std::nullopt;
  int64_t Value = Integer->isUnsigned()
                      ? static_cast<int64_t>(Integer->getZExtValue())
                      : Integer->getSExtValue();
  if (S.sign < 0) {
    if (Value == INT64_MIN)
      return std::nullopt;
    Value = -Value;
    Op = negateComparison(std::move(Op));
  }
  return PendingConstraint{S, ResultConstraint{std::move(Op), Value}};
}

static std::optional<Predicate> andPredicate(const Predicate &LHS,
                                             const Predicate &RHS) {
  Predicate Result;
  if (LHS.empty() || RHS.empty())
    return Result;
  for (const ConstraintClause &Left : LHS) {
    for (const ConstraintClause &Right : RHS) {
      if (Result.size() >= 16)
        return std::nullopt;
      ConstraintClause Combined = Left;
      Combined.insert(Combined.end(), Right.begin(), Right.end());
      Result.push_back(std::move(Combined));
    }
  }
  return Result;
}

static std::optional<Predicate> orPredicate(const Predicate &LHS,
                                            const Predicate &RHS) {
  if (LHS.size() + RHS.size() > 16)
    return std::nullopt;
  Predicate Result = LHS;
  Result.insert(Result.end(), RHS.begin(), RHS.end());
  return Result;
}

static bool containsConstraint(const std::optional<Predicate> &Value) {
  if (!Value)
    return false;
  return std::any_of(
      Value->begin(), Value->end(),
      [](const ConstraintClause &Clause) { return !Clause.empty(); });
}

static std::optional<Predicate> extractPredicate(const Expr *Expression,
                                                 bool Expected,
                                                 CheckerContext &C,
                                                 unsigned Depth = 0) {
  if (!Expression || Depth > 24)
    return std::nullopt;
  Expression = ignoreExpr(Expression);

  if (const auto *Not = dyn_cast<UnaryOperator>(Expression)) {
    if (Not->getOpcode() == UO_LNot)
      return extractPredicate(Not->getSubExpr(), !Expected, C, Depth + 1);
  }

  if (const auto *Logical = dyn_cast<BinaryOperator>(Expression)) {
    if (Logical->getOpcode() == BO_LAnd || Logical->getOpcode() == BO_LOr) {
      auto Left = extractPredicate(Logical->getLHS(), Expected, C, Depth + 1);
      auto Right = extractPredicate(Logical->getRHS(), Expected, C, Depth + 1);
      if (!Left || !Right)
        return std::nullopt;
      bool NeedAnd = (Logical->getOpcode() == BO_LAnd) == Expected;
      return NeedAnd ? andPredicate(*Left, *Right) : orPredicate(*Left, *Right);
    }

    if (Logical->isComparisonOp()) {
      std::optional<PendingConstraint> Pending;
      if (const PendingConstraint *const *Cached =
              C.getState()->get<ConstraintByComparison>(Logical))
        Pending = **Cached;
      else
        Pending = extractComparison(Logical, C);
      if (!Pending)
        return std::nullopt;
      if (!Expected)
        Pending->result.op = negateTruth(std::move(Pending->result.op));
      if (Pending->subject.error &&
          !errnoConstraintHasPositiveSolution(Pending->result))
        return std::nullopt;
      return Predicate{{std::move(*Pending)}};
    }
  }

  if (const auto *Ref = dyn_cast<DeclRefExpr>(Expression)) {
    const auto *Variable = dyn_cast<VarDecl>(Ref->getDecl());
    if (Variable) {
      Loc Location = C.getState()->getLValue(Variable, C.getLocationContext());
      const MemRegion *Region = Location.getAsRegion();
      const PredicateBinding *const *Stored =
          Region ? C.getState()->get<PredicateByRegion>(Region) : nullptr;
      if (Stored && currentValue(Expression, C) == (*Stored)->value) {
        const std::optional<Predicate> &Result =
            Expected ? (*Stored)->whenTrue : (*Stored)->whenFalse;
        return Result;
      }
    }
  }

  SVal Current = currentValue(Expression, C);
  if (const llvm::APSInt *Integer = Current.getAsInteger()) {
    bool Actual = Integer->getBoolValue();
    return Actual == Expected ? Predicate{ConstraintClause{}} : Predicate{};
  }
  return std::nullopt;
}

static bool assertionMacroAt(SourceLocation Location, CheckerContext &C) {
  const SourceManager &SM = C.getSourceManager();
  for (unsigned Depth = 0; Location.isMacroID() && Depth < 16; ++Depth) {
    llvm::StringRef Name =
        Lexer::getImmediateMacroName(Location, SM, C.getLangOpts());
    if (Name == "CHECK_OP" || Name.starts_with("EXPECT_") ||
        Name.starts_with("ASSERT_"))
      return true;
    Location = SM.getImmediateMacroCallerLoc(Location);
  }
  return false;
}

static bool failureMacroAt(SourceLocation Location, CheckerContext &C) {
  const SourceManager &SM = C.getSourceManager();
  for (unsigned Depth = 0; Location.isMacroID() && Depth < 16; ++Depth) {
    if (Lexer::getImmediateMacroName(Location, SM, C.getLangOpts()) ==
        "KSFT_FAIL")
      return true;
    Location = SM.getImmediateMacroCallerLoc(Location);
  }
  return false;
}

static bool knownFailureCall(const CallExpr *Call) {
  const FunctionDecl *Callee = Call ? Call->getDirectCallee() : nullptr;
  if (!Callee)
    return false;
  llvm::StringRef Name = Callee->getName();
  return Name == "abort" || Name == "__assert_fail" ||
         Name == "ksft_exit_fail_msg" || Name == "bpf_test_failure" ||
         Name == "nolibc_test_failure" || Name == "test__fail";
}

static bool knownFailureReturn(const ReturnStmt *Return, CheckerContext &C) {
  return Return && Return->getRetValue() &&
         failureMacroAt(Return->getRetValue()->getExprLoc(), C);
}

static bool knownFailureEvent(const Stmt *Statement, CheckerContext &C) {
  if (const auto *Return = dyn_cast<ReturnStmt>(Statement))
    return knownFailureReturn(Return, C);
  if (const auto *Expression = dyn_cast<Expr>(Statement))
    return knownFailureCall(dyn_cast_or_null<CallExpr>(ignoreExpr(Expression)));
  return false;
}

static bool preservesSyscallContext(const CallEvent &Call) {
  const auto *ND = dyn_cast_or_null<NamedDecl>(Call.getDecl());
  if (!ND)
    return false;
  llvm::StringRef Name = ND->getName();
  return Name == "__errno_location" || Name == "fprintf" || Name == "printf" ||
         Name == "snprintf" || Name == "puts" || Name == "fputs" ||
         Name == "ksft_test_result" || Name == "expect_syseq" ||
         Name == "expect_syszr" || Name == "expect_syserr";
}

struct IntegerDomain {
  std::optional<int64_t> lower;
  std::optional<int64_t> upper;
  std::set<int64_t> excluded;
  bool empty = false;
};

static void normalizeDomain(IntegerDomain &Domain) {
  if (Domain.empty)
    return;
  auto Outside = [&](int64_t Value) {
    return (Domain.lower && Value < *Domain.lower) ||
           (Domain.upper && Value > *Domain.upper);
  };
  for (auto It = Domain.excluded.begin(); It != Domain.excluded.end();)
    if (Outside(*It))
      It = Domain.excluded.erase(It);
    else
      ++It;

  while (Domain.lower && Domain.excluded.erase(*Domain.lower)) {
    if (*Domain.lower == std::numeric_limits<int64_t>::max()) {
      Domain.empty = true;
      return;
    }
    ++*Domain.lower;
  }
  while (Domain.upper && Domain.excluded.erase(*Domain.upper)) {
    if (*Domain.upper == std::numeric_limits<int64_t>::min()) {
      Domain.empty = true;
      return;
    }
    --*Domain.upper;
  }
  if (Domain.lower && Domain.upper && *Domain.lower > *Domain.upper)
    Domain.empty = true;
}

static IntegerDomain constraintDomain(const ResultConstraint &Constraint) {
  IntegerDomain Domain;
  if (Constraint.op == "==") {
    Domain.lower = Constraint.value;
    Domain.upper = Constraint.value;
  } else if (Constraint.op == "!=") {
    Domain.excluded.insert(Constraint.value);
  } else if (Constraint.op == ">") {
    if (Constraint.value == std::numeric_limits<int64_t>::max())
      Domain.empty = true;
    else
      Domain.lower = Constraint.value + 1;
  } else if (Constraint.op == ">=") {
    Domain.lower = Constraint.value;
  } else if (Constraint.op == "<") {
    if (Constraint.value == std::numeric_limits<int64_t>::min())
      Domain.empty = true;
    else
      Domain.upper = Constraint.value - 1;
  } else if (Constraint.op == "<=") {
    Domain.upper = Constraint.value;
  } else {
    Domain.empty = true;
  }
  normalizeDomain(Domain);
  return Domain;
}

static IntegerDomain intersectDomains(IntegerDomain LHS, IntegerDomain RHS) {
  IntegerDomain Result;
  Result.empty = LHS.empty || RHS.empty;
  if (LHS.lower && RHS.lower)
    Result.lower = std::max(*LHS.lower, *RHS.lower);
  else
    Result.lower = LHS.lower ? LHS.lower : RHS.lower;
  if (LHS.upper && RHS.upper)
    Result.upper = std::min(*LHS.upper, *RHS.upper);
  else
    Result.upper = LHS.upper ? LHS.upper : RHS.upper;
  Result.excluded = std::move(LHS.excluded);
  Result.excluded.insert(RHS.excluded.begin(), RHS.excluded.end());
  normalizeDomain(Result);
  return Result;
}

static std::optional<ResultConstraint>
constraintForDomain(IntegerDomain Domain) {
  normalizeDomain(Domain);
  if (Domain.empty)
    return std::nullopt;
  if (Domain.lower && Domain.upper && *Domain.lower == *Domain.upper &&
      Domain.excluded.empty())
    return ResultConstraint{"==", *Domain.lower};
  if (!Domain.excluded.empty()) {
    if (!Domain.lower && !Domain.upper && Domain.excluded.size() == 1)
      return ResultConstraint{"!=", *Domain.excluded.begin()};
    return std::nullopt;
  }
  if (Domain.lower && !Domain.upper)
    return ResultConstraint{">=", *Domain.lower};
  if (!Domain.lower && Domain.upper)
    return ResultConstraint{"<=", *Domain.upper};
  if (Domain.lower && Domain.upper) {
    if (*Domain.lower == std::numeric_limits<int64_t>::min())
      return ResultConstraint{"<=", *Domain.upper};
    if (*Domain.upper == std::numeric_limits<int64_t>::max())
      return ResultConstraint{">=", *Domain.lower};
  }
  return std::nullopt;
}

static std::optional<ResultConstraint>
mergeConstraints(const ResultConstraint &LHS, const ResultConstraint &RHS) {
  if (LHS.op == RHS.op && LHS.value == RHS.value)
    return LHS;
  return constraintForDomain(
      intersectDomains(constraintDomain(LHS), constraintDomain(RHS)));
}

static bool modelableSyscall(const CallEvent &Call, CheckerContext &C) {
  if (!namedCall(Call, "syscall") || Call.getNumArgs() < 1 ||
      !ActiveCollector ||
      !ActiveCollector->wantsFunction(functionName(C.getLocationContext())))
    return false;
  const llvm::APSInt *Number = Call.getArgSVal(0).getAsInteger();
  return Number && Number->getBitWidth() <= 64;
}

class SyscallScenarioChecker
    : public Checker<eval::Call, check::PreCall, check::Bind,
                     check::PreStmt<ReturnStmt>, check::PostStmt<UnaryOperator>,
                     check::PostStmt<ImplicitCastExpr>,
                     check::PostStmt<BinaryOperator>, check::BeginFunction,
                     check::EndFunction, check::BranchCondition> {
  using CFGKey = std::pair<const Decl *, const CFG *>;
  mutable std::map<CFGKey, std::set<const CFGBlock *>> FailureBlocks;

  const std::set<const CFGBlock *> &failureBlocks(const CFG &Graph,
                                                  CheckerContext &C) const {
    CFGKey Key{C.getCurrentAnalysisDeclContext()->getDecl(), &Graph};
    auto [It, Inserted] = FailureBlocks.try_emplace(Key);
    if (!Inserted)
      return It->second;

    std::set<const CFGBlock *> &Result = It->second;
    for (const CFGBlock *Block : Graph) {
      for (const CFGElement &Element : *Block) {
        auto Statement = Element.getAs<CFGStmt>();
        if (Statement && knownFailureEvent(Statement->getStmt(), C)) {
          Result.insert(Block);
          break;
        }
      }
    }

    // Least fixed point: a block is definitely failing when it contains a
    // failure event, or every reachable successor is already definitely
    // failing. Cycles without a failure remain outside the set.
    bool Changed;
    do {
      Changed = false;
      for (const CFGBlock *Block : Graph) {
        if (Result.count(Block) || Block == &Graph.getExit())
          continue;
        bool HasSuccessor = false;
        bool AllFail = true;
        for (const CFGBlock::AdjacentBlock &Adjacent : Block->succs()) {
          const CFGBlock *Successor = Adjacent.getReachableBlock();
          if (!Successor)
            continue;
          HasSuccessor = true;
          AllFail &= Result.count(Successor) != 0;
        }
        if (HasSuccessor && AllFail) {
          Result.insert(Block);
          Changed = true;
        }
      }
    } while (Changed);
    return Result;
  }

  std::optional<bool> successfulCondition(const Stmt *Condition,
                                          CheckerContext &C) const {
    const auto *Expression = dyn_cast_or_null<Expr>(Condition);
    const CFGBlock *Block = C.getCFGElementRef().getParent();
    if (!Expression || !Block)
      return std::nullopt;

    if (const auto *If = dyn_cast_or_null<IfStmt>(Block->getTerminatorStmt())) {
      if (ignoreExpr(Expression) == ignoreExpr(If->getCond()) &&
          (assertionMacroAt(If->getIfLoc(), C) ||
           assertionMacroAt(Expression->getExprLoc(), C)))
        return false;
    }

    if (Block->succ_size() != 2)
      return std::nullopt;
    const CFG &Graph = *Block->getParent();
    const std::set<const CFGBlock *> &Failures = failureBlocks(Graph, C);
    auto Successor = Block->succ_begin();
    const CFGBlock *WhenTrue = Successor->getReachableBlock();
    ++Successor;
    const CFGBlock *WhenFalse = Successor->getReachableBlock();
    bool TrueFails = WhenTrue && Failures.count(WhenTrue);
    bool FalseFails = WhenFalse && Failures.count(WhenFalse);
    if (TrueFails == FalseFails)
      return std::nullopt;
    return !TrueFails;
  }

  static const Expr *bindingSource(const VarDecl *Variable,
                                   const Stmt *Statement) {
    if (const auto *Declaration = dyn_cast_or_null<DeclStmt>(Statement)) {
      for (const Decl *D : Declaration->decls()) {
        const auto *BoundVariable = dyn_cast<VarDecl>(D);
        if (BoundVariable == Variable)
          return BoundVariable->getInit();
      }
      return nullptr;
    }
    const auto *Assignment = dyn_cast_or_null<BinaryOperator>(Statement);
    if (Assignment && Assignment->getOpcode() == BO_Assign)
      return Assignment->getRHS();
    return nullptr;
  }

  static ProgramStateRef applyClause(ProgramStateRef State,
                                     const ConstraintClause &Clause) {
    for (const PendingConstraint &Pending : Clause) {
      ConstraintSet Updated;
      if (const ConstraintSet *const *Old =
              State->get<ConstraintsByCall>(Pending.subject.call))
        Updated = **Old;
      std::optional<ResultConstraint> &Slot =
          Pending.subject.error ? Updated.error : Updated.ret;
      if (Slot) {
        auto Merged = mergeConstraints(*Slot, Pending.result);
        if (!Merged)
          return nullptr;
        Slot = std::move(*Merged);
      } else {
        Slot = Pending.result;
      }
      const ConstraintSet *Stored =
          ActiveCollector->makeConstraints(std::move(Updated));
      State = State->set<ConstraintsByCall>(Pending.subject.call, Stored);
    }
    return State;
  }

  static bool applyPredicate(const Expr *Expression, bool Expected,
                             CheckerContext &C) {
    auto Extracted = extractPredicate(Expression, Expected, C);
    if (!Extracted)
      return false;
    if (Extracted->empty())
      return false;
    // If one successful alternative imposes no syscall constraint, emitting
    // only the narrower alternatives would invent an oracle the test does not
    // actually require (for example, `ret == 0 || true`).
    for (const ConstraintClause &Clause : *Extracted)
      if (Clause.empty())
        return false;

    ProgramStateRef Base = C.getState();
    if (auto Value = C.getSVal(Expression).getAs<DefinedOrUnknownSVal>()) {
      Base = Base->assume(*Value, Expected);
      if (!Base)
        return true;
    }
    bool Added = false;
    for (const ConstraintClause &Clause : *Extracted) {
      if (ProgramStateRef Next = applyClause(Base, Clause)) {
        C.addTransition(Next);
        Added = true;
      }
    }
    return Added;
  }

public:
  void checkBind(SVal Location, SVal Value, const Stmt *Statement,
                 CheckerContext &C) const {
    const auto *Region = dyn_cast_or_null<VarRegion>(Location.getAsRegion());
    const VarDecl *Variable = Region ? Region->getDecl() : nullptr;
    if (!Variable)
      return;

    ProgramStateRef State = C.getState();
    if (State->get<PredicateByRegion>(Region))
      State = State->remove<PredicateByRegion>(Region);

    const Expr *Source = bindingSource(Variable, Statement);
    if (Source && ActiveCollector) {
      std::optional<Predicate> WhenTrue = extractPredicate(Source, true, C);
      std::optional<Predicate> WhenFalse = extractPredicate(Source, false, C);
      if (containsConstraint(WhenTrue) || containsConstraint(WhenFalse)) {
        const PredicateBinding *Binding = ActiveCollector->makePredicateBinding(
            {Value, std::move(WhenTrue), std::move(WhenFalse)});
        State = State->set<PredicateByRegion>(Region, Binding);
      }
    }
    if (State != C.getState())
      C.addTransition(State);
  }

  bool evalCall(const CallEvent &Call, CheckerContext &C) const {
    if (knownFailureCall(
            dyn_cast_or_null<CallExpr>(ignoreExpr(Call.getOriginExpr())))) {
      C.addSink();
      return true;
    }
    if (!modelableSyscall(Call, C))
      return false;
    llvm::StringRef Function = functionName(C.getLocationContext());

    const llvm::APSInt *NumberValue = Call.getArgSVal(0).getAsInteger();
    if (!NumberValue || NumberValue->getBitWidth() > 64)
      return false;
    int64_t Number = NumberValue->getSExtValue();
    Invocation Value;
    Value.function = Function.str();
    Value.syscall = syscallName(Call, Number, C);
    Value.concrete = true;
    for (unsigned I = 1; I < Call.getNumArgs(); ++I) {
      auto Arg =
          snapshotValue(Call.getArgSVal(I), Call.getArgExpr(I)->getType(),
                        C.getState(), C.getLocationContext());
      if (!Arg) {
        Value.concrete = false;
        break;
      }
      Value.args.push_back(std::move(*Arg));
    }
    const Invocation *Stored =
        ActiveCollector->makeInvocation(std::move(Value));
    SVal Return = C.getSValBuilder().conjureSymbolVal(
        Call, Call.getResultType(), C.blockCount(), this);
    SymbolRef Symbol = Return.getAsSymbol();
    if (!Symbol)
      return false;
    ProgramStateRef State = C.getState()->BindExpr(
        Call.getOriginExpr(), C.getLocationContext(), Return);
    State = State->set<SyscallBySymbol>(Symbol, Stored);
    State = State->set<CurrentErrnoOwner>(Stored);
    C.addTransition(State);
    return true;
  }

  void checkPreStmt(const ReturnStmt *Return, CheckerContext &C) const {
    if (knownFailureReturn(Return, C))
      C.addSink();
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (namedCall(Call, "ksft_test_result") && Call.getNumArgs() > 0) {
      if (const Expr *Condition = Call.getArgExpr(0))
        if (applyPredicate(Condition, true, C))
          return;
    }
    if (namedCall(Call, "syscall")) {
      if (modelableSyscall(Call, C))
        return;
      if (C.getState()->get<CurrentErrnoOwner>())
        C.addTransition(C.getState()->remove<CurrentErrnoOwner>());
      return;
    }
    if (preservesSyscallContext(Call))
      return;
    if (!C.getState()->get<CurrentErrnoOwner>())
      return;
    C.addTransition(C.getState()->remove<CurrentErrnoOwner>());
  }

  void checkPostStmt(const BinaryOperator *Compare, CheckerContext &C) const {
    auto Pending = extractComparison(Compare, C);
    if (!Pending || !ActiveCollector)
      return;
    const PendingConstraint *Stored =
        ActiveCollector->makePendingConstraint(std::move(*Pending));
    C.addTransition(C.getState()->set<ConstraintByComparison>(Compare, Stored));
  }

  void checkPostStmt(const UnaryOperator *UO, CheckerContext &C) const {
    if (UO->getOpcode() != UO_Deref)
      return;
    const Expr *Operand = ignoreExpr(UO->getSubExpr());
    const auto *CE = dyn_cast_or_null<CallExpr>(Operand);
    const FunctionDecl *FD = CE ? CE->getDirectCallee() : nullptr;
    if (!FD || FD->getName() != "__errno_location")
      return;
    const Invocation *Owner = C.getState()->get<CurrentErrnoOwner>();
    if (!Owner)
      return;
    ProgramStateRef State = C.getState();
    bool Changed = false;
    for (SymbolRef Atom : C.getSVal(UO).symbols()) {
      State = State->set<ErrnoBySymbol>(Atom, Owner);
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkPostStmt(const ImplicitCastExpr *Cast, CheckerContext &C) const {
    if (Cast->getCastKind() != CK_LValueToRValue)
      return;
    const Expr *Source = ignoreExpr(Cast->getSubExpr());
    const auto *UO = dyn_cast_or_null<UnaryOperator>(Source);
    if (!UO || UO->getOpcode() != UO_Deref)
      return;
    const auto *CE = dyn_cast_or_null<CallExpr>(ignoreExpr(UO->getSubExpr()));
    const FunctionDecl *FD = CE ? CE->getDirectCallee() : nullptr;
    const Invocation *Owner = C.getState()->get<CurrentErrnoOwner>();
    if (!FD || FD->getName() != "__errno_location" || !Owner)
      return;
    ProgramStateRef State = C.getState();
    bool Changed = false;
    for (SymbolRef Atom : C.getSVal(Cast).symbols()) {
      State = State->set<ErrnoBySymbol>(Atom, Owner);
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkBeginFunction(CheckerContext &C) const {
    if (!C.inTopFrame() || !ActiveCollector)
      return;
    ActiveCollector->seeFunction(functionName(C.getLocationContext()));
  }

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
    const auto *Expression = dyn_cast<Expr>(Condition);
    std::optional<bool> Expected = successfulCondition(Condition, C);
    if (Expression && Expected)
      applyPredicate(Expression, *Expected, C);
  }

  void checkEndFunction(const ReturnStmt *, CheckerContext &C) const {
    if (!C.inTopFrame() || !ActiveCollector)
      return;
    for (const auto &Entry : C.getState()->get<ConstraintsByCall>())
      ActiveCollector->emit(Entry.first, Entry.second);
  }
};

class AnalyzerAction : public ASTFrontendAction {
protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 llvm::StringRef) override {
    AnalyzerOptions &Options = CI.getAnalyzerOpts();
    Options.AnalysisDiagOpt = PD_NONE;
    Options.maxBlockVisitOnPath = 128;
    if (!AllFunctions && Functions.size() == 1)
      Options.AnalyzeSpecificFunction = Functions.front();
    Options.CheckersAndPackages.emplace_back("extractor.SyscallScenario", true);
    auto Consumer = CreateAnalysisConsumer(CI);
    Consumer->AddCheckerRegistrationFn([](CheckerRegistry &Registry) {
      Registry.addChecker<SyscallScenarioChecker>(
          "extractor.SyscallScenario", "Extract concrete syscall expectations",
          "", false);
    });
    return Consumer;
  }
};

class AnalyzerActionFactory : public tooling::FrontendActionFactory {
public:
  std::unique_ptr<FrontendAction> create() override {
    return std::make_unique<AnalyzerAction>();
  }
};

class SingleCommandDatabase : public tooling::CompilationDatabase {
  tooling::CompileCommand Command;

public:
  explicit SingleCommandDatabase(tooling::CompileCommand Command)
      : Command(std::move(Command)) {}

  std::vector<tooling::CompileCommand>
  getCompileCommands(llvm::StringRef) const override {
    return {Command};
  }

  std::vector<std::string> getAllFiles() const override {
    return {Command.Filename};
  }
};

static std::string absoluteSource(const tooling::CompileCommand &Command) {
  std::filesystem::path Path(Command.Filename);
  if (Path.is_relative())
    Path = std::filesystem::path(Command.Directory) / Path;
  return std::filesystem::absolute(Path).lexically_normal().string();
}

int main(int argc, const char **argv) {
  llvm::cl::HideUnrelatedOptions(Category);
  llvm::cl::ParseCommandLineOptions(argc, argv);
  std::string Error;
  auto Database = tooling::JSONCompilationDatabase::loadFromFile(
      CompDB, Error, tooling::JSONCommandLineSyntax::AutoDetect);
  if (!Database) {
    llvm::errs() << "Unable to load compilation database: " << Error << "\n";
    return 2;
  }
  std::vector<tooling::CompileCommand> Commands =
      Database->getAllCompileCommands();
  if (UnitIndex >= Commands.size()) {
    llvm::errs() << "Compile-command index " << UnitIndex
                 << " is out of range (" << Commands.size() << " entries)\n";
    return 2;
  }
  tooling::CompileCommand Command = Commands[UnitIndex];
  std::string Source = absoluteSource(Command);
  SingleCommandDatabase Selected(Command);
  Collector Results;
  ActiveCollector = &Results;
  tooling::ClangTool Tool(Selected, {Source});
  Tool.clearArgumentsAdjusters();
  Tool.appendArgumentsAdjuster(tooling::getClangStripOutputAdjuster());
  Tool.appendArgumentsAdjuster(tooling::getClangStripDependencyFileAdjuster());
  Tool.appendArgumentsAdjuster(tooling::getStripPluginsAdjuster());
  AnalyzerActionFactory Factory;
  int Status = Tool.run(&Factory);
  ActiveCollector = nullptr;
  if (Status)
    return Status;

  json::Array CommandLine;
  for (const std::string &Arg : Command.CommandLine)
    CommandLine.push_back(Arg);
  json::Object Output{
      {"schema_version", 2},
      {"source", Source},
      {"compilation_unit", json::Object{{"index", UnitIndex.getValue()},
                                        {"directory", Command.Directory},
                                        {"file", Command.Filename},
                                        {"command", std::move(CommandLine)}}},
      {"functions", Results.functionJSON()},
      {"records", Results.recordJSON()},
  };
  llvm::outs() << json::Value(std::move(Output)) << "\n";
  return 0;
}
