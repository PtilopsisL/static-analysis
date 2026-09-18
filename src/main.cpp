// Extract concrete syscall expectations by analyzing original source with the
// exact command recorded in compile_commands.json. The analyzed program is
// never linked or executed.
#include <algorithm>
#include <cstdint>
#include <filesystem>
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
    std::sort(Records.begin(), Records.end(),
              [](const EmittedRecord &LHS, const EmittedRecord &RHS) {
                return LHS.fullKey < RHS.fullKey;
              });
    for (EmittedRecord &Record : Records)
      Result.push_back(std::move(Record.object));
    return Result;
  }
};

static Collector *ActiveCollector = nullptr;

REGISTER_MAP_WITH_PROGRAMSTATE(SyscallBySymbol, SymbolRef, const Invocation *)
REGISTER_MAP_WITH_PROGRAMSTATE(ErrnoBySymbol, SymbolRef, const Invocation *)
REGISTER_MAP_WITH_PROGRAMSTATE(ConstraintsByCall, const Invocation *,
                               const ConstraintSet *)
REGISTER_TRAIT_WITH_PROGRAMSTATE(LastSyscall, const Invocation *)

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

struct Subject {
  const Invocation *call = nullptr;
  bool error = false;
  int sign = 1;
};

static int signOf(const SymExpr *Expression, SymbolRef Atom) {
  if (Expression == Atom)
    return 1;
  if (const auto *Cast = dyn_cast<SymbolCast>(Expression))
    return signOf(Cast->getOperand(), Atom);
  if (const auto *Unary = dyn_cast<UnarySymExpr>(Expression)) {
    int Sign = signOf(Unary->getOperand(), Atom);
    return Unary->getOpcode() == UO_Minus ? -Sign : 0;
  }
  return 0;
}

static std::optional<Subject> findSubject(SVal Value, ProgramStateRef State) {
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
    int Sign = signOf(Expression, Atom);
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

static bool expectationVariable(const Expr *E) {
  E = ignoreExpr(E);
  const auto *Ref = dyn_cast_or_null<DeclRefExpr>(E);
  if (!Ref)
    return false;
  llvm::StringRef Name = Ref->getDecl()->getName();
  return Name == "__exp" || Name == "__seen";
}

static bool preservesSyscallContext(const CallEvent &Call) {
  const auto *ND = dyn_cast_or_null<NamedDecl>(Call.getDecl());
  if (!ND)
    return false;
  llvm::StringRef Name = ND->getName();
  return Name == "syscall" || Name == "__errno_location" || Name == "fprintf" ||
         Name == "printf" || Name == "snprintf" || Name == "puts" ||
         Name == "fputs";
}

class SyscallScenarioChecker
    : public Checker<eval::Call, check::PreCall, check::PostStmt<UnaryOperator>,
                     check::PostStmt<ImplicitCastExpr>, check::BeginFunction,
                     check::EndFunction, check::BranchCondition> {
public:
  bool evalCall(const CallEvent &Call, CheckerContext &C) const {
    if (!namedCall(Call, "syscall") || Call.getNumArgs() < 1)
      return false;
    llvm::StringRef Function = functionName(C.getLocationContext());
    if (!ActiveCollector || !ActiveCollector->wantsFunction(Function))
      return false;

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
    State = State->set<LastSyscall>(Stored);
    C.addTransition(State);
    return true;
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (preservesSyscallContext(Call))
      return;
    if (!C.getState()->get<LastSyscall>())
      return;
    C.addTransition(C.getState()->remove<LastSyscall>());
  }

  void checkPostStmt(const UnaryOperator *UO, CheckerContext &C) const {
    if (UO->getOpcode() != UO_Deref)
      return;
    const Expr *Operand = ignoreExpr(UO->getSubExpr());
    const auto *CE = dyn_cast_or_null<CallExpr>(Operand);
    const FunctionDecl *FD = CE ? CE->getDirectCallee() : nullptr;
    if (!FD || FD->getName() != "__errno_location")
      return;
    const Invocation *Last = C.getState()->get<LastSyscall>();
    if (!Last)
      return;
    ProgramStateRef State = C.getState();
    bool Changed = false;
    for (SymbolRef Atom : C.getSVal(UO).symbols()) {
      State = State->set<ErrnoBySymbol>(Atom, Last);
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
    const Invocation *Last = C.getState()->get<LastSyscall>();
    if (!FD || FD->getName() != "__errno_location" || !Last)
      return;
    ProgramStateRef State = C.getState();
    bool Changed = false;
    for (SymbolRef Atom : C.getSVal(Cast).symbols()) {
      State = State->set<ErrnoBySymbol>(Atom, Last);
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
    Expression = ignoreExpr(Expression);
    if (const auto *Not = dyn_cast_or_null<UnaryOperator>(Expression))
      if (Not->getOpcode() == UO_LNot)
        Expression = ignoreExpr(Not->getSubExpr());
    const auto *Compare = dyn_cast_or_null<BinaryOperator>(Expression);
    if (!Compare || !Compare->isComparisonOp() ||
        !expectationVariable(Compare->getLHS()) ||
        !expectationVariable(Compare->getRHS()))
      return;

    SVal LHS = C.getSVal(Compare->getLHS());
    SVal RHS = C.getSVal(Compare->getRHS());
    auto LeftSubject = findSubject(LHS, C.getState());
    auto RightSubject = findSubject(RHS, C.getState());
    const llvm::APSInt *LeftInteger = LHS.getAsInteger();
    const llvm::APSInt *RightInteger = RHS.getAsInteger();
    Subject S;
    const llvm::APSInt *Integer = nullptr;
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
      return;
    }
    if (Integer->getBitWidth() > 64 || Op.empty())
      return;
    int64_t Expected = Integer->getSExtValue();
    if (S.sign < 0) {
      if (Expected == INT64_MIN)
        return;
      Expected = -Expected;
      Op = negateComparison(std::move(Op));
    }
    ConstraintSet Updated;
    if (const ConstraintSet *const *Old =
            C.getState()->get<ConstraintsByCall>(S.call))
      Updated = **Old;
    ResultConstraint New{std::move(Op), Expected};
    if (S.error && !errnoConstraintHasPositiveSolution(New))
      return;
    if (auto ConditionValue = C.getSVal(Compare).getAs<DefinedOrUnknownSVal>())
      if (!C.getState()->assume(*ConditionValue, true))
        return;
    if (S.error)
      Updated.error = std::move(New);
    else
      Updated.ret = std::move(New);
    const ConstraintSet *Stored =
        ActiveCollector->makeConstraints(std::move(Updated));
    ProgramStateRef Next = C.getState()->set<ConstraintsByCall>(S.call, Stored);
    C.addTransition(Next);
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
