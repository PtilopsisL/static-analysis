// Extract syscall scenarios by analyzing original source with the exact
// command recorded in compile_commands.json. The analyzed program is never
// linked or executed.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ParentMapContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/Analysis/CFG.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Frontend/MultiplexConsumer.h>
#include <clang/Lex/Lexer.h>
#include <clang/StaticAnalyzer/Core/AnalyzerOptions.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/CheckerManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/RangedConstraintManager.h>
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
static llvm::cl::opt<std::string> LibcProfile(
    "libc-profile",
    llvm::cl::desc("Analysis-only libc wrapper profile (none or "
                   "glibc-linux-x86_64)"),
    llvm::cl::init("none"), llvm::cl::cat(Category));

/* Populated before the analyzer consumer runs for the current translation
 * unit. Keys are canonical .test callbacks and values are their .tcnt. */
static std::map<const FunctionDecl *, unsigned> LtpHarnessCaseCounts;

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

struct IntegerRange {
  int64_t lower;
  int64_t upper;

  bool operator==(const IntegerRange &Other) const {
    return lower == Other.lower && upper == Other.upper;
  }
};

struct IntegerDomain {
  std::vector<IntegerRange> ranges;

  bool empty() const { return ranges.empty(); }
};

static IntegerDomain fullDomain() {
  return {{{std::numeric_limits<int64_t>::min(),
            std::numeric_limits<int64_t>::max()}}};
}

static void normalizeDomain(IntegerDomain &Domain) {
  Domain.ranges.erase(
      std::remove_if(Domain.ranges.begin(), Domain.ranges.end(),
                     [](const IntegerRange &R) { return R.lower > R.upper; }),
      Domain.ranges.end());
  std::sort(Domain.ranges.begin(), Domain.ranges.end(),
            [](const IntegerRange &LHS, const IntegerRange &RHS) {
              return LHS.lower < RHS.lower ||
                     (LHS.lower == RHS.lower && LHS.upper < RHS.upper);
            });
  std::vector<IntegerRange> Merged;
  for (const IntegerRange &R : Domain.ranges) {
    if (Merged.empty() ||
        (Merged.back().upper != std::numeric_limits<int64_t>::max() &&
         R.lower > Merged.back().upper + 1)) {
      Merged.push_back(R);
      continue;
    }
    Merged.back().upper = std::max(Merged.back().upper, R.upper);
  }
  Domain.ranges = std::move(Merged);
}

static IntegerDomain negateDomain(IntegerDomain Domain) {
  constexpr int64_t Min = std::numeric_limits<int64_t>::min();
  constexpr int64_t Max = std::numeric_limits<int64_t>::max();
  for (IntegerRange &Range : Domain.ranges) {
    int64_t Lower = Range.upper == Max ? Min : -Range.upper;
    int64_t Upper = Range.lower == Min ? Max : -Range.lower;
    Range = {Lower, Upper};
  }
  normalizeDomain(Domain);
  return Domain;
}

static IntegerDomain intersectDomains(IntegerDomain LHS, IntegerDomain RHS) {
  normalizeDomain(LHS);
  normalizeDomain(RHS);
  IntegerDomain Result;
  size_t Left = 0;
  size_t Right = 0;
  while (Left < LHS.ranges.size() && Right < RHS.ranges.size()) {
    const IntegerRange &A = LHS.ranges[Left];
    const IntegerRange &B = RHS.ranges[Right];
    int64_t Lower = std::max(A.lower, B.lower);
    int64_t Upper = std::min(A.upper, B.upper);
    if (Lower <= Upper)
      Result.ranges.push_back({Lower, Upper});
    if (A.upper < B.upper)
      ++Left;
    else
      ++Right;
  }
  return Result;
}

static IntegerDomain unionDomains(IntegerDomain LHS, IntegerDomain RHS) {
  LHS.ranges.insert(LHS.ranges.end(), RHS.ranges.begin(), RHS.ranges.end());
  normalizeDomain(LHS);
  return LHS;
}

static bool equalDomains(IntegerDomain LHS, IntegerDomain RHS) {
  normalizeDomain(LHS);
  normalizeDomain(RHS);
  return LHS.ranges == RHS.ranges;
}

static bool isFullDomain(IntegerDomain Domain) {
  normalizeDomain(Domain);
  return Domain.ranges.size() == 1 &&
         Domain.ranges.front().lower == std::numeric_limits<int64_t>::min() &&
         Domain.ranges.front().upper == std::numeric_limits<int64_t>::max();
}

static bool domainHasPositiveSolution(IntegerDomain Domain) {
  normalizeDomain(Domain);
  return std::any_of(Domain.ranges.begin(), Domain.ranges.end(),
                     [](const IntegerRange &R) { return R.upper >= 1; });
}

static std::optional<ResultConstraint>
constraintForDomain(IntegerDomain Domain) {
  constexpr int64_t Min = std::numeric_limits<int64_t>::min();
  constexpr int64_t Max = std::numeric_limits<int64_t>::max();
  normalizeDomain(Domain);
  if (Domain.ranges.size() == 1) {
    const IntegerRange &R = Domain.ranges.front();
    if (R.lower == R.upper)
      return ResultConstraint{"==", R.lower};
    if (R.lower == Min && R.upper != Max)
      return ResultConstraint{"<=", R.upper};
    if (R.upper == Max && R.lower != Min)
      return ResultConstraint{">=", R.lower};
    return std::nullopt;
  }
  if (Domain.ranges.size() == 2) {
    const IntegerRange &Left = Domain.ranges[0];
    const IntegerRange &Right = Domain.ranges[1];
    if (Left.lower == Min && Right.upper == Max && Left.upper != Max &&
        Right.lower != Min &&
        static_cast<__int128>(Left.upper) + 2 == Right.lower)
      return ResultConstraint{"!=", Left.upper + 1};
  }
  return std::nullopt;
}

enum class ProjectionKind {
  Exact,
  Unconstrained,
  Unsatisfiable,
  Unrepresentable,
};

struct DomainProjection {
  ProjectionKind kind;
  std::optional<ResultConstraint> constraint;
};

static DomainProjection
projectDomain(const std::optional<IntegerDomain> &Stored) {
  if (!Stored)
    return {ProjectionKind::Unconstrained, std::nullopt};
  IntegerDomain Domain = *Stored;
  normalizeDomain(Domain);
  if (Domain.empty())
    return {ProjectionKind::Unsatisfiable, std::nullopt};
  if (isFullDomain(Domain))
    return {ProjectionKind::Unconstrained, std::nullopt};
  if (auto Constraint = constraintForDomain(Domain))
    return {ProjectionKind::Exact, std::move(Constraint)};
  return {ProjectionKind::Unrepresentable, std::nullopt};
}

static std::optional<int64_t> integerDomainValue(const llvm::APSInt &Value) {
  if (Value.getBitWidth() > 64 ||
      (Value.isUnsigned() &&
       Value.getZExtValue() >
           static_cast<uint64_t>(std::numeric_limits<int64_t>::max())))
    return std::nullopt;
  return Value.isUnsigned() ? static_cast<int64_t>(Value.getZExtValue())
                            : Value.getSExtValue();
}

static std::optional<IntegerDomain> domainForRangeSet(const RangeSet &Ranges) {
  constexpr int64_t Min = std::numeric_limits<int64_t>::min();
  constexpr int64_t Max = std::numeric_limits<int64_t>::max();
  IntegerDomain Domain;
  if (Ranges.isEmpty())
    return Domain;
  APSIntType Type = Ranges.getAPSIntType();
  if (Type.getBitWidth() > 64)
    return std::nullopt;
  llvm::APSInt TypeMin = Type.getMinValue();
  llvm::APSInt TypeMax = Type.getMaxValue();
  bool FullTypeDomain = false;
  unsigned RangeCount = 0;
  for (const Range &R : Ranges) {
    ++RangeCount;
    FullTypeDomain = R.From() == TypeMin && R.To() == TypeMax;
    std::optional<int64_t> Lower =
        R.From() == TypeMin
            ? std::optional<int64_t>(Type.isUnsigned() ? 0 : Min)
            : integerDomainValue(R.From());
    std::optional<int64_t> Upper = R.To() == TypeMax
                                       ? std::optional<int64_t>(Max)
                                       : integerDomainValue(R.To());
    if (!Lower || !Upper)
      return std::nullopt;
    Domain.ranges.push_back({*Lower, *Upper});
  }
  if (RangeCount == 1 && FullTypeDomain)
    return fullDomain();
  normalizeDomain(Domain);
  return Domain;
}

struct ConstraintDomains {
  std::optional<IntegerDomain> ret;
  std::optional<IntegerDomain> error;
};

struct ConstraintSet {
  std::optional<ResultConstraint> ret;
  std::optional<ResultConstraint> error;
};

struct CapturedArgument {
  enum Kind { Concrete, Symbolic, Reference, Output, Unsupported } kind =
      Unsupported;
  ConcreteValue concrete;
  SymbolRef symbol = nullptr;
  std::vector<SymbolRef> atoms;
  const struct Invocation *producer = nullptr;
  int producerOutputArgument = -1;
  const ValueDecl *sourceDecl = nullptr;
  std::optional<uint64_t> outputSize;

  static CapturedArgument concreteValue(ConcreteValue Value,
                                        const ValueDecl *SourceDecl) {
    CapturedArgument Result;
    Result.kind = Concrete;
    Result.concrete = std::move(Value);
    Result.sourceDecl = SourceDecl;
    return Result;
  }

  static CapturedArgument symbolicValue(SymbolRef Symbol,
                                        std::vector<SymbolRef> Atoms,
                                        const ValueDecl *SourceDecl) {
    CapturedArgument Result;
    Result.kind = Symbolic;
    Result.symbol = Symbol;
    Result.atoms = std::move(Atoms);
    Result.sourceDecl = SourceDecl;
    return Result;
  }

  static CapturedArgument reference(const struct Invocation *Producer,
                                    int OutputArgument = -1) {
    CapturedArgument Result;
    Result.kind = Reference;
    Result.producer = Producer;
    Result.producerOutputArgument = OutputArgument;
    return Result;
  }

  static CapturedArgument output(std::optional<uint64_t> Size) {
    CapturedArgument Result;
    Result.kind = Output;
    Result.outputSize = Size;
    return Result;
  }
};

struct Invocation {
  std::string function;
  std::string syscall;
  std::vector<CapturedArgument> args;
  const Expr *eventSite = nullptr;
  SymbolRef resultSymbol = nullptr;
  SymbolRef errnoSymbol = nullptr;
};

struct DependencyKey {
  const Invocation *call = nullptr;
  int outputArgument = -1;

  bool operator<(const DependencyKey &Other) const {
    if (call != Other.call)
      return std::less<const Invocation *>()(call, Other.call);
    return outputArgument < Other.outputArgument;
  }
};

enum class EventField : uint8_t {
  Result,
  Errno,
};

enum class ProjectionTransform : uint8_t {
  Identity,
  Negate,
};

struct SymbolOwner {
  const Invocation *call = nullptr;
  EventField field = EventField::Result;

  bool operator==(const SymbolOwner &Other) const {
    return call == Other.call && field == Other.field;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(call);
    ID.AddInteger(static_cast<unsigned>(field));
  }
};

struct OutputOwner {
  const Invocation *call = nullptr;
  unsigned argument = 0;

  bool operator==(const OutputOwner &Other) const {
    return call == Other.call && argument == Other.argument;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(call);
    ID.AddInteger(argument);
  }
};

struct EventOrigin {
  const Invocation *call = nullptr;
  EventField field = EventField::Result;
  SymbolRef atom = nullptr;
};

struct ProjectionSubject {
  EventOrigin origin;
  SymbolRef constrainedSymbol = nullptr;
  ProjectionTransform transform = ProjectionTransform::Identity;
};

struct Provenance {
  std::vector<EventOrigin> origins;
  std::vector<ProjectionSubject> projections;
};

struct EvaluationSite {
  const Expr *expression = nullptr;
  const LocationContext *context = nullptr;

  bool operator==(const EvaluationSite &Other) const {
    return expression == Other.expression && context == Other.context;
  }

  bool operator<(const EvaluationSite &Other) const {
    if (expression != Other.expression)
      return std::less<const Expr *>()(expression, Other.expression);
    return std::less<const LocationContext *>()(context, Other.context);
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(expression);
    ID.AddPointer(context);
  }
};

struct AssertionMarker {
  const Expr *site = nullptr;
  const Invocation *call = nullptr;
  std::vector<ProjectionSubject> projections;
  unsigned epoch = 0;
  unsigned sequence = 0;
  bool outcomeAttributed = false;
};

struct ComparisonHint {
  SymbolRef subject = nullptr;
  const ValueDecl *subjectDecl = nullptr;
  ResultConstraint spelling;
  SVal predicate;
};

struct MaterializedArgument {
  enum Kind { Concrete, Domain, Reference, Output } kind = Concrete;
  ConcreteValue concrete;
  IntegerDomain domain;
  std::vector<ResultConstraint> hints;
  std::string reference;
  std::optional<uint64_t> outputSize;
  std::string outputBinding;
};

struct MaterializedCall {
  std::string syscall;
  std::vector<MaterializedArgument> args;
  std::string bind;
  ConstraintSet result;
};

struct ScenarioObservation {
  std::string function;
  std::vector<MaterializedCall> setup;
  MaterializedCall target;
  ConstraintDomains result;
};

class Collector {
  struct EmittedRecord {
    std::string function;
    std::string baseKey;
    std::string fullKey;
    ConstraintSet result;
    json::Object object;
  };

  struct ObservationGroup {
    const Expr *assertionSite = nullptr;
    const Expr *eventSite = nullptr;
    unsigned epoch = 0;
    std::string function;
    std::string syscall;
    std::vector<ScenarioObservation> alternatives;
    bool outcomeAttributed = false;
    bool failureSeen = false;
    bool skipSeen = false;
  };

  std::set<std::string> SelectedFunctions;
  std::set<std::string> SelectedSyscalls;
  std::vector<std::unique_ptr<Invocation>> Invocations;
  std::vector<std::unique_ptr<Provenance>> Provenances;
  std::vector<std::unique_ptr<AssertionMarker>> AssertionMarkers;
  std::vector<std::unique_ptr<ComparisonHint>> ComparisonHints;
  std::map<DependencyKey, std::string> PreferredBindings;
  std::set<std::string> SeenFunctions;
  std::vector<ObservationGroup> ObservationGroups;
  std::vector<EmittedRecord> Records;
  bool Finalized = false;

  static json::Object constraintJSON(const ResultConstraint &C) {
    return json::Object{{"op", C.op}, {"value", C.value}};
  }

  static bool equal(const std::optional<ResultConstraint> &LHS,
                    const std::optional<ResultConstraint> &RHS) {
    if (LHS.has_value() != RHS.has_value())
      return false;
    return !LHS || (LHS->op == RHS->op && LHS->value == RHS->value);
  }

  static bool equal(const ConstraintSet &LHS, const ConstraintSet &RHS) {
    return equal(LHS.ret, RHS.ret) && equal(LHS.error, RHS.error);
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

  static IntegerDomain
  effectiveDomain(const std::optional<IntegerDomain> &Domain) {
    return Domain.value_or(fullDomain());
  }

  static bool equalDomainFields(const std::optional<IntegerDomain> &LHS,
                                const std::optional<IntegerDomain> &RHS) {
    return equalDomains(effectiveDomain(LHS), effectiveDomain(RHS));
  }

  static bool mergeDomainFields(const std::optional<IntegerDomain> &LHS,
                                const std::optional<IntegerDomain> &RHS,
                                std::optional<IntegerDomain> &Merged) {
    IntegerDomain Union =
        unionDomains(effectiveDomain(LHS), effectiveDomain(RHS));
    DomainProjection Projection = projectDomain(Union);
    if (Projection.kind == ProjectionKind::Unconstrained) {
      Merged.reset();
      return true;
    }
    if (Projection.kind != ProjectionKind::Exact)
      return false;
    Merged = std::move(Union);
    return true;
  }

  static void canonicalize(ConstraintDomains &Domains) {
    if (Domains.ret) {
      normalizeDomain(*Domains.ret);
      if (isFullDomain(*Domains.ret))
        Domains.ret.reset();
    }
    if (Domains.error) {
      normalizeDomain(*Domains.error);
      if (isFullDomain(*Domains.error))
        Domains.error.reset();
    }
  }

  static bool concreteEqual(const ConcreteValue &LHS,
                            const ConcreteValue &RHS) {
    return render(toJSON(LHS)) == render(toJSON(RHS));
  }

  static std::optional<IntegerDomain>
  numericDomain(const MaterializedArgument &Argument) {
    if (Argument.kind == MaterializedArgument::Domain)
      return Argument.domain;
    if (Argument.kind != MaterializedArgument::Concrete ||
        Argument.concrete.kind != ConcreteValue::Integer)
      return std::nullopt;
    if (Argument.concrete.isUnsigned &&
        Argument.concrete.bits >
            static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
      return std::nullopt;
    int64_t Value = static_cast<int64_t>(Argument.concrete.bits);
    return IntegerDomain{{{Value, Value}}};
  }

  static void appendHint(std::vector<ResultConstraint> &Hints,
                         const ResultConstraint &Hint) {
    if (std::none_of(Hints.begin(), Hints.end(), [&](const auto &Existing) {
          return Existing.op == Hint.op && Existing.value == Hint.value;
        }))
      Hints.push_back(Hint);
  }

  static void mergeHints(MaterializedArgument &Destination,
                         const MaterializedArgument &Source) {
    for (const ResultConstraint &Hint : Source.hints)
      appendHint(Destination.hints, Hint);
  }

  static bool argumentEqual(const MaterializedArgument &LHS,
                            const MaterializedArgument &RHS) {
    if (LHS.kind == MaterializedArgument::Output ||
        RHS.kind == MaterializedArgument::Output)
      return LHS.kind == MaterializedArgument::Output &&
             RHS.kind == MaterializedArgument::Output &&
             LHS.outputSize == RHS.outputSize &&
             LHS.outputBinding == RHS.outputBinding;
    if (LHS.kind == MaterializedArgument::Reference ||
        RHS.kind == MaterializedArgument::Reference)
      return LHS.kind == MaterializedArgument::Reference &&
             RHS.kind == MaterializedArgument::Reference &&
             LHS.reference == RHS.reference;
    auto LeftDomain = numericDomain(LHS);
    auto RightDomain = numericDomain(RHS);
    if (LeftDomain && RightDomain)
      return equalDomains(std::move(*LeftDomain), std::move(*RightDomain));
    return LHS.kind == MaterializedArgument::Concrete &&
           RHS.kind == MaterializedArgument::Concrete &&
           concreteEqual(LHS.concrete, RHS.concrete);
  }

  static bool mergeArgument(MaterializedArgument &Destination,
                            const MaterializedArgument &Source) {
    auto LeftDomain = numericDomain(Destination);
    auto RightDomain = numericDomain(Source);
    if (!LeftDomain || !RightDomain)
      return false;
    Destination.kind = MaterializedArgument::Domain;
    Destination.domain =
        unionDomains(std::move(*LeftDomain), std::move(*RightDomain));
    mergeHints(Destination, Source);
    return true;
  }

  static bool callsHaveSameShape(const MaterializedCall &LHS,
                                 const MaterializedCall &RHS) {
    return LHS.syscall == RHS.syscall && LHS.bind == RHS.bind &&
           equal(LHS.result, RHS.result) && LHS.args.size() == RHS.args.size();
  }

  static bool tryMerge(ScenarioObservation &Destination,
                       const ScenarioObservation &Source) {
    if (Destination.function != Source.function ||
        Destination.setup.size() != Source.setup.size() ||
        !callsHaveSameShape(Destination.target, Source.target))
      return false;
    for (size_t I = 0; I < Destination.setup.size(); ++I)
      if (!callsHaveSameShape(Destination.setup[I], Source.setup[I]))
        return false;

    for (size_t I = 0; I < Destination.setup.size(); ++I) {
      for (size_t J = 0; J < Destination.setup[I].args.size(); ++J) {
        MaterializedArgument &Left = Destination.setup[I].args[J];
        const MaterializedArgument &Right = Source.setup[I].args[J];
        if (!argumentEqual(Left, Right))
          return false;
        mergeHints(Left, Right);
      }
    }

    MaterializedArgument *Differing = nullptr;
    const MaterializedArgument *Other = nullptr;
    unsigned ArgumentDifferences = 0;
    auto CompareArguments = [&](MaterializedCall &Left,
                                const MaterializedCall &Right) {
      for (size_t I = 0; I < Left.args.size(); ++I) {
        if (argumentEqual(Left.args[I], Right.args[I])) {
          mergeHints(Left.args[I], Right.args[I]);
          continue;
        }
        ++ArgumentDifferences;
        Differing = &Left.args[I];
        Other = &Right.args[I];
      }
    };
    CompareArguments(Destination.target, Source.target);
    if (ArgumentDifferences > 1)
      return false;

    bool SameRet = equalDomainFields(Destination.result.ret, Source.result.ret);
    bool SameError =
        equalDomainFields(Destination.result.error, Source.result.error);
    unsigned ResultDifferences =
        static_cast<unsigned>(!SameRet) + static_cast<unsigned>(!SameError);

    if (ArgumentDifferences == 0 && ResultDifferences == 0)
      return true;
    if (ArgumentDifferences == 1 && ResultDifferences == 0)
      return mergeArgument(*Differing, *Other);
    if (ArgumentDifferences != 0 || ResultDifferences != 1)
      return false;

    std::optional<IntegerDomain> Merged;
    if (!SameRet) {
      if (!mergeDomainFields(Destination.result.ret, Source.result.ret, Merged))
        return false;
      Destination.result.ret = std::move(Merged);
    } else {
      if (!mergeDomainFields(Destination.result.error, Source.result.error,
                             Merged))
        return false;
      Destination.result.error = std::move(Merged);
    }
    canonicalize(Destination.result);
    return true;
  }

  static const ResultConstraint *findHint(
      const std::vector<ResultConstraint> &Hints,
      std::initializer_list<std::pair<llvm::StringRef, int64_t>> Candidates) {
    for (const auto &[Op, Value] : Candidates)
      for (const ResultConstraint &Hint : Hints)
        if (Hint.op == Op && Hint.value == Value)
          return &Hint;
    return nullptr;
  }

  static json::Object rangeJSON(const IntegerRange &Range,
                                const std::vector<ResultConstraint> &Hints) {
    constexpr int64_t Min = std::numeric_limits<int64_t>::min();
    constexpr int64_t Max = std::numeric_limits<int64_t>::max();
    json::Object Object;
    if (Range.lower != Min) {
      const ResultConstraint *Hint = nullptr;
      if (Range.lower != Min)
        Hint = findHint(Hints, {{">=", Range.lower}, {">", Range.lower - 1}});
      if (Hint)
        Object[Hint->op] = Hint->value;
      else
        Object[">="] = Range.lower;
    }
    if (Range.upper != Max) {
      const ResultConstraint *Hint =
          findHint(Hints, {{"<=", Range.upper}, {"<", Range.upper + 1}});
      if (Hint)
        Object[Hint->op] = Hint->value;
      else
        Object["<"] = Range.upper + 1;
    }
    return Object;
  }

  static json::Value argumentJSON(const MaterializedArgument &Argument) {
    if (Argument.kind == MaterializedArgument::Concrete)
      return toJSON(Argument.concrete);
    if (Argument.kind == MaterializedArgument::Reference)
      return json::Object{{"ref", Argument.reference}};
    if (Argument.kind == MaterializedArgument::Output) {
      json::Object Description;
      if (!Argument.outputBinding.empty())
        Description["bind"] = Argument.outputBinding;
      else if (Argument.outputSize)
        Description["size"] = *Argument.outputSize;
      return json::Object{{"out", std::move(Description)}};
    }

    IntegerDomain Domain = Argument.domain;
    normalizeDomain(Domain);
    if (Domain.ranges.size() == 1 &&
        Domain.ranges.front().lower == Domain.ranges.front().upper)
      return Domain.ranges.front().lower;

    json::Array Entries;
    constexpr int64_t Min = std::numeric_limits<int64_t>::min();
    constexpr int64_t Max = std::numeric_limits<int64_t>::max();
    if (Domain.ranges.size() == 2 && Domain.ranges[0].lower == Min &&
        Domain.ranges[1].upper == Max && Domain.ranges[0].upper != Max &&
        Domain.ranges[1].lower != Min &&
        static_cast<__int128>(Domain.ranges[0].upper) + 2 ==
            Domain.ranges[1].lower) {
      Entries.push_back(json::Object{{"!=", Domain.ranges[0].upper + 1}});
      return json::Object{{"domain", std::move(Entries)}};
    }
    for (const IntegerRange &Range : Domain.ranges) {
      bool ExplicitValues = false;
      if (Range.lower != Min && Range.upper != Max) {
        __int128 Count = static_cast<__int128>(Range.upper) - Range.lower + 1;
        if (Count > 0 &&
            Count <= static_cast<__int128>(Argument.hints.size())) {
          ExplicitValues = true;
          for (int64_t Value = Range.lower;; ++Value) {
            if (!findHint(Argument.hints, {{"==", Value}})) {
              ExplicitValues = false;
              break;
            }
            if (Value == Range.upper)
              break;
          }
        }
      }
      if (ExplicitValues) {
        for (int64_t Value = Range.lower;; ++Value) {
          Entries.push_back(Value);
          if (Value == Range.upper)
            break;
        }
      } else if (Range.lower == Range.upper) {
        Entries.push_back(Range.lower);
      } else {
        Entries.push_back(rangeJSON(Range, Argument.hints));
      }
    }
    return json::Object{{"domain", std::move(Entries)}};
  }

  static json::Object resultJSON(const ConstraintSet &Result) {
    json::Object Object;
    if (Result.ret)
      Object["ret"] = constraintJSON(*Result.ret);
    if (Result.error)
      Object["errno"] = constraintJSON(*Result.error);
    return Object;
  }

  static json::Object callJSON(const MaterializedCall &Call, bool IncludeBind) {
    json::Array Args;
    for (const MaterializedArgument &Argument : Call.args)
      Args.push_back(argumentJSON(Argument));
    json::Object Object{{"syscall", Call.syscall}, {"args", std::move(Args)}};
    if (IncludeBind && !Call.bind.empty())
      Object["bind"] = Call.bind;
    if (Call.result.ret || Call.result.error)
      Object["result"] = resultJSON(Call.result);
    return Object;
  }

  void appendRecord(const ScenarioObservation &Scenario) {
    DomainProjection Ret = projectDomain(Scenario.result.ret);
    DomainProjection Error = projectDomain(Scenario.result.error);
    auto CannotEmit = [](ProjectionKind Kind) {
      return Kind == ProjectionKind::Unsatisfiable ||
             Kind == ProjectionKind::Unrepresentable;
    };
    if (CannotEmit(Ret.kind) || CannotEmit(Error.kind))
      return;
    ConstraintSet Result{std::move(Ret.constraint),
                         std::move(Error.constraint)};
    if (!Result.ret && !Result.error)
      return;
    if (Result.error && !Result.ret)
      Result.ret = ResultConstraint{"==", -1};

    json::Object Record = callJSON(Scenario.target, false);
    if (!Scenario.setup.empty()) {
      json::Array Setup;
      for (const MaterializedCall &Call : Scenario.setup)
        Setup.push_back(callJSON(Call, true));
      Record["setup"] = std::move(Setup);
    }
    std::string BaseKey = render(json::Object(Record));
    Record["result"] = resultJSON(Result);
    std::string FullKey = render(json::Object(Record));

    for (auto It = Records.begin(); It != Records.end();) {
      if (It->function != Scenario.function || It->baseKey != BaseKey) {
        ++It;
        continue;
      }
      if (subset(Result, It->result))
        return;
      if (subset(It->result, Result)) {
        It = Records.erase(It);
        continue;
      }
      ++It;
    }
    Records.push_back({Scenario.function, std::move(BaseKey),
                       std::move(FullKey), std::move(Result),
                       std::move(Record)});
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

  const Provenance *makeProvenance(Provenance Value) {
    Provenances.push_back(std::make_unique<Provenance>(std::move(Value)));
    return Provenances.back().get();
  }

  const AssertionMarker *makeAssertionMarker(AssertionMarker Value) {
    AssertionMarkers.push_back(
        std::make_unique<AssertionMarker>(std::move(Value)));
    return AssertionMarkers.back().get();
  }

  const ComparisonHint *makeComparisonHint(ComparisonHint Value) {
    ComparisonHints.push_back(
        std::make_unique<ComparisonHint>(std::move(Value)));
    return ComparisonHints.back().get();
  }

  void noteBinding(const Invocation *Call, llvm::StringRef Name) {
    DependencyKey Key{Call, -1};
    if (Call && !Name.empty() && !PreferredBindings.count(Key))
      PreferredBindings.emplace(Key, Name.str());
  }

  void noteOutputBinding(const Invocation *Call, unsigned Argument,
                         llvm::StringRef Name) {
    DependencyKey Key{Call, static_cast<int>(Argument)};
    if (Call && !Name.empty() && !PreferredBindings.count(Key))
      PreferredBindings.emplace(Key, Name.str());
  }

  std::string preferredBinding(DependencyKey Key) const {
    auto It = PreferredBindings.find(Key);
    return It == PreferredBindings.end() ? std::string() : It->second;
  }

  ObservationGroup *groupFor(const AssertionMarker *Marker) {
    const Invocation *Call = Marker ? Marker->call : nullptr;
    if (!Call || !wantsFunction(Call->function) || !wantsSyscall(Call->syscall))
      return nullptr;
    Finalized = false;
    auto Group =
        std::find_if(ObservationGroups.begin(), ObservationGroups.end(),
                     [&](const ObservationGroup &Candidate) {
                       return Candidate.assertionSite == Marker->site &&
                              Candidate.eventSite == Call->eventSite &&
                              Candidate.epoch == Marker->epoch &&
                              Candidate.function == Call->function &&
                              Candidate.syscall == Call->syscall;
                     });
    if (Group == ObservationGroups.end()) {
      ObservationGroups.push_back({Marker->site,
                                   Call->eventSite,
                                   Marker->epoch,
                                   Call->function,
                                   Call->syscall,
                                   {},
                                   Marker->outcomeAttributed,
                                   false,
                                   false});
      return &ObservationGroups.back();
    }
    Group->outcomeAttributed |= Marker->outcomeAttributed;
    return &*Group;
  }

  void observe(const AssertionMarker *Marker, ScenarioObservation Scenario) {
    if (ObservationGroup *Group = groupFor(Marker)) {
      canonicalize(Scenario.result);
      Group->alternatives.push_back(std::move(Scenario));
    }
  }

  void markFailure(const AssertionMarker *Marker) {
    if (ObservationGroup *Group = groupFor(Marker))
      Group->failureSeen = true;
  }

  void markSkip(const AssertionMarker *Marker) {
    if (ObservationGroup *Group = groupFor(Marker))
      Group->skipSeen = true;
  }

  void finalize() {
    if (Finalized)
      return;
    Records.clear();
    std::vector<ScenarioObservation> Scenarios;
    for (ObservationGroup &Group : ObservationGroups) {
      if (Group.skipSeen ||
          (!Group.outcomeAttributed && !Group.failureSeen) ||
          Group.alternatives.empty())
        continue;
      std::vector<ScenarioObservation> Alternatives =
          std::move(Group.alternatives);
      bool Changed;
      do {
        Changed = false;
        for (size_t I = 0; I < Alternatives.size() && !Changed; ++I) {
          for (size_t J = I + 1; J < Alternatives.size(); ++J) {
            if (!tryMerge(Alternatives[I], Alternatives[J]))
              continue;
            Alternatives.erase(Alternatives.begin() +
                               static_cast<std::ptrdiff_t>(J));
            Changed = true;
            break;
          }
        }
      } while (Changed);
      Scenarios.insert(Scenarios.end(),
                       std::make_move_iterator(Alternatives.begin()),
                       std::make_move_iterator(Alternatives.end()));
    }
    for (const ScenarioObservation &Scenario : Scenarios)
      appendRecord(Scenario);
    Finalized = true;
  }

  json::Array functionJSON() const {
    json::Array Result;
    for (const std::string &Name : SeenFunctions) {
      size_t Count = static_cast<size_t>(std::count_if(
          Records.begin(), Records.end(), [&](const EmittedRecord &Record) {
            return Record.function == Name;
          }));
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
static int ErrnoSymbolTag;
static int OutputSymbolTag;

REGISTER_MAP_WITH_PROGRAMSTATE(SymbolOwners, SymbolRef, SymbolOwner)
REGISTER_MAP_WITH_PROGRAMSTATE(OutputOwners, SymbolRef, OutputOwner)
REGISTER_MAP_WITH_PROGRAMSTATE(ProvenanceBySymbol, SymbolRef,
                               const Provenance *)
REGISTER_MAP_WITH_PROGRAMSTATE(ProvenanceByEvaluationSite, EvaluationSite,
                               const Provenance *)
REGISTER_MAP_WITH_PROGRAMSTATE(SValByEvaluationSite, EvaluationSite, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(ComparisonHintByEvaluationSite, EvaluationSite,
                               const ComparisonHint *)
REGISTER_MAP_WITH_PROGRAMSTATE(ProvenanceByRegion, const MemRegion *,
                               const Provenance *)
REGISTER_SET_WITH_PROGRAMSTATE(TrackedArgumentSymbols, SymbolRef)
REGISTER_SET_WITH_PROGRAMSTATE(ActiveGuards, const AssertionMarker *)
REGISTER_TRAIT_WITH_PROGRAMSTATE(CurrentErrnoOwner, const Invocation *)
REGISTER_TRAIT_WITH_PROGRAMSTATE(CurrentOutcomeEpoch, unsigned)
REGISTER_TRAIT_WITH_PROGRAMSTATE(NextOutcomeCandidate, unsigned)
/* 0 means ordinary entry; harness case N is encoded as N + 1. */
REGISTER_TRAIT_WITH_PROGRAMSTATE(CurrentHarnessCase, unsigned)
/* 0 is unset/pass-by-default; other values are encoded PathOutcome + 1. */
REGISTER_TRAIT_WITH_PROGRAMSTATE(FrameworkStatus, unsigned)

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

enum class SemanticCallKind : uint8_t {
  Unknown,
  KsftResultCode,
  LtpReporter,
  LtpErrnoSet,
  Preserve,
};

enum class ContextEffect : uint8_t {
  Default,
  Preserve,
};

enum class PathOutcome : uint8_t {
  Pass,
  Fail,
  Broken,
  Skip,
  Neutral,
};

enum class OutcomeAction : uint8_t {
  ReportBoundary,
  CounterUpdate,
  StatusWrite,
  Terminate,
};

enum class OutcomeScope : uint8_t {
  ActiveCandidates,
  InnermostCandidates,
  Epoch,
};

struct OutcomeEffect {
  PathOutcome verdict = PathOutcome::Neutral;
  OutcomeAction action = OutcomeAction::ReportBoundary;
  OutcomeScope scope = OutcomeScope::Epoch;
};

struct CallSemantics {
  SemanticCallKind kind = SemanticCallKind::Unknown;
  ContextEffect contextEffect = ContextEffect::Default;
  std::optional<OutcomeEffect> outcome;
  struct OperationModel {
    struct Argument {
      enum Kind : uint8_t { CallArgument, SignedConstant, UnsignedConstant };
      Kind kind = CallArgument;
      unsigned index = 0;
      uint64_t value = 0;

      static Argument call(unsigned Index) {
        return {CallArgument, Index, 0};
      }
      static Argument signedConstant(int64_t Value) {
        return {SignedConstant, 0, static_cast<uint64_t>(Value)};
      }
      static Argument unsignedConstant(uint64_t Value) {
        return {UnsignedConstant, 0, Value};
      }
    };

    std::optional<unsigned> numberArgument;
    unsigned firstArgument = 0;
    std::string fixedName;
    bool modelsErrno = true;
    /* Wrappers such as LTP SAFE_* only return when this condition holds. */
    std::optional<ResultConstraint> acceptedResult;
    /* Empty means forward [firstArgument, getNumArgs()). */
    std::vector<Argument> arguments;
    /* Call arguments whose pointee state becomes unknown after the syscall. */
    std::vector<unsigned> invalidatedArguments;
  };
  std::optional<OperationModel> operation;
};

class SemanticDispatcher {
  using Adapter = std::optional<CallSemantics> (*)(llvm::StringRef);

  static CallSemantics action(SemanticCallKind Kind) {
    CallSemantics Result;
    Result.kind = Kind;
    Result.contextEffect = ContextEffect::Preserve;
    return Result;
  }

  static CallSemantics outcome(PathOutcome Verdict, OutcomeAction Action,
                               OutcomeScope Scope = OutcomeScope::Epoch) {
    CallSemantics Result;
    Result.contextEffect = ContextEffect::Preserve;
    Result.outcome = OutcomeEffect{Verdict, Action, Scope};
    return Result;
  }

  static std::optional<CallSemantics> operationAdapter(llvm::StringRef Name) {
    if (Name != "syscall")
      return std::nullopt;
    CallSemantics Result;
    Result.contextEffect = ContextEffect::Preserve;
    CallSemantics::OperationModel Operation;
    Operation.numberArgument = 0;
    Operation.firstArgument = 1;
    Result.operation = std::move(Operation);
    return Result;
  }

  static std::optional<CallSemantics> commonAdapter(llvm::StringRef Name) {
    if (Name == "abort" || Name == "__assert_fail")
      return outcome(PathOutcome::Fail, OutcomeAction::Terminate,
                     OutcomeScope::ActiveCandidates);
    if (Name == "test__fail")
      return outcome(PathOutcome::Fail, OutcomeAction::StatusWrite,
                     OutcomeScope::InnermostCandidates);
    if (Name == "test__report_pass")
      return outcome(PathOutcome::Pass, OutcomeAction::ReportBoundary);
    if (Name == "test__report_fail")
      return outcome(PathOutcome::Fail, OutcomeAction::ReportBoundary);
    if (Name == "__errno_location" || Name == "fprintf" || Name == "printf" ||
        Name == "snprintf" || Name == "puts" || Name == "fputs")
      return action(SemanticCallKind::Preserve);
    return std::nullopt;
  }

  static std::optional<CallSemantics> ksftAdapter(llvm::StringRef Name) {
    if (Name == "ksft_test_result_code")
      return action(SemanticCallKind::KsftResultCode);
    if (Name == "ksft_test_result_pass")
      return outcome(PathOutcome::Pass, OutcomeAction::ReportBoundary);
    if (Name == "ksft_test_result_fail" ||
        Name == "ksft_test_result_error")
      return outcome(PathOutcome::Fail, OutcomeAction::ReportBoundary);
    if (Name == "ksft_test_result_skip" ||
        Name == "ksft_test_result_xfail" || Name == "ksft_test_result_xpass")
      return outcome(PathOutcome::Skip, OutcomeAction::ReportBoundary);
    if (Name == "ksft_inc_pass_cnt")
      return outcome(PathOutcome::Pass, OutcomeAction::CounterUpdate);
    if (Name == "ksft_inc_fail_cnt" || Name == "ksft_inc_error_cnt")
      return outcome(PathOutcome::Fail, OutcomeAction::CounterUpdate);
    if (Name == "ksft_inc_xskip_cnt" || Name == "ksft_inc_xfail_cnt" ||
        Name == "ksft_inc_xpass_cnt")
      return outcome(PathOutcome::Skip, OutcomeAction::CounterUpdate);
    if (Name == "ksft_exit_pass")
      return outcome(PathOutcome::Pass, OutcomeAction::Terminate,
                     OutcomeScope::InnermostCandidates);
    if (Name == "ksft_exit_fail" || Name == "ksft_exit_fail_msg" ||
        Name == "ksft_exit_fail_perror")
      return outcome(PathOutcome::Fail, OutcomeAction::Terminate,
                     OutcomeScope::InnermostCandidates);
    if (Name == "ksft_exit_skip" || Name == "ksft_exit_xfail" ||
        Name == "ksft_exit_xpass")
      return outcome(PathOutcome::Skip, OutcomeAction::Terminate,
                     OutcomeScope::InnermostCandidates);
    return std::nullopt;
  }

  static std::optional<CallSemantics> bpfAdapter(llvm::StringRef Name) {
    if (Name == "bpf_test_failure")
      return outcome(PathOutcome::Fail, OutcomeAction::StatusWrite,
                     OutcomeScope::InnermostCandidates);
    return std::nullopt;
  }

  static std::optional<CallSemantics> nolibcAdapter(llvm::StringRef Name) {
    if (Name == "nolibc_test_failure")
      return outcome(PathOutcome::Fail, OutcomeAction::StatusWrite,
                     OutcomeScope::InnermostCandidates);
    return std::nullopt;
  }

  static std::optional<CallSemantics> ltpAdapter(llvm::StringRef Name) {
    if (Name == "tst_res_" || Name == "tst_brk_")
      return action(SemanticCallKind::LtpReporter);
    if (Name == "tst_errno_in_set")
      return action(SemanticCallKind::LtpErrnoSet);
    return std::nullopt;
  }

  static bool isUnresolvedExternalFunction(const CallEvent &Call) {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !Call.isGlobalCFunction() || !FD->isExternallyVisible())
      return false;
    const FunctionDecl *Definition = nullptr;
    return !FD->hasBody(Definition);
  }

  enum class ProfileType : uint8_t {
    Signed32,
    Unsigned32,
    Signed64,
    Unsigned64,
    Integral32,
    Pointer,
  };

  static bool matchesProfileType(QualType Type, ProfileType Expected,
                                 ASTContext &Context) {
    Type = Type.getCanonicalType();
    if (Expected == ProfileType::Pointer)
      return Type->isPointerType();
    if (Expected == ProfileType::Integral32) {
      if (const auto *Enumeration = Type->getAs<EnumType>()) {
        QualType Integer = Enumeration->getDecl()->getIntegerType();
        if (Integer.isNull())
          return false;
        Type = Integer.getCanonicalType();
      }
      return Type->isIntegerType() && Context.getIntWidth(Type) == 32;
    }
    bool Signed = Expected == ProfileType::Signed32 ||
                  Expected == ProfileType::Signed64;
    unsigned Width =
        Expected == ProfileType::Signed32 || Expected == ProfileType::Unsigned32
            ? 32
            : 64;
    return Type->isIntegerType() && Type->isSignedIntegerType() == Signed &&
           Context.getIntWidth(Type) == Width;
  }

  static bool matchesDeclaration(
      const FunctionDecl &FD, ProfileType Return,
      std::initializer_list<ProfileType> Parameters, bool Variadic,
      ASTContext &Context) {
    if (!matchesProfileType(FD.getReturnType(), Return, Context) ||
        FD.isVariadic() != Variadic || FD.getNumParams() != Parameters.size())
      return false;
    unsigned Index = 0;
    for (ProfileType Type : Parameters)
      if (!matchesProfileType(FD.getParamDecl(Index++)->getType(), Type,
                              Context))
        return false;
    return true;
  }

  static bool validGlibcDeclaration(llvm::StringRef Name,
                                    const FunctionDecl &FD,
                                    ASTContext &Context) {
    using T = ProfileType;
    if (Name == "close")
      return matchesDeclaration(FD, T::Signed32, {T::Signed32}, false,
                                Context);
    if (Name == "write")
      return matchesDeclaration(
          FD, T::Signed64, {T::Signed32, T::Pointer, T::Unsigned64}, false,
          Context);
    if (Name == "ioctl")
      return matchesDeclaration(FD, T::Signed32,
                                {T::Signed32, T::Unsigned64}, true, Context);
    if (Name == "eventfd")
      return matchesDeclaration(FD, T::Signed32,
                                {T::Unsigned32, T::Signed32}, false, Context);
    if (Name == "open")
      return matchesDeclaration(FD, T::Signed32,
                                {T::Pointer, T::Signed32}, true, Context);
    if (Name == "openat")
      return matchesDeclaration(
          FD, T::Signed32, {T::Signed32, T::Pointer, T::Signed32}, true,
          Context);
    if (Name == "fcntl")
      return matchesDeclaration(FD, T::Signed32,
                                {T::Signed32, T::Signed32}, true, Context);
    if (Name == "getpid")
      return matchesDeclaration(FD, T::Signed32, {}, false, Context);
    if (Name == "access")
      return matchesDeclaration(FD, T::Signed32,
                                {T::Pointer, T::Signed32}, false, Context);
    if (Name == "kill")
      return matchesDeclaration(FD, T::Signed32,
                                {T::Signed32, T::Signed32}, false, Context);
    if (Name == "safe_close")
      return matchesDeclaration(
          FD, T::Signed32,
          {T::Pointer, T::Signed32, T::Pointer, T::Signed32}, false, Context);
    if (Name == "safe_open")
      return matchesDeclaration(
          FD, T::Signed32,
          {T::Pointer, T::Signed32, T::Pointer, T::Pointer, T::Signed32},
          true, Context);
    if (Name == "safe_write")
      return matchesDeclaration(
          FD, T::Signed64,
          {T::Pointer, T::Signed32, T::Pointer, T::Integral32, T::Signed32,
           T::Pointer, T::Unsigned64},
          false, Context);
    return false;
  }

  static bool supportsGlibcX8664(const CallEvent &Call, CheckerContext &C) {
    if (LibcProfile != "glibc-linux-x86_64" ||
        !isUnresolvedExternalFunction(Call))
      return false;
    const llvm::Triple &Triple = C.getASTContext().getTargetInfo().getTriple();
    ASTContext &Context = C.getASTContext();
    return Triple.getArch() == llvm::Triple::x86_64 && Triple.isOSLinux() &&
           !Triple.isMusl() && Context.getTypeSize(Context.IntTy) == 32 &&
           Context.getTypeSize(Context.LongTy) == 64 &&
           Context.getTypeSize(Context.VoidPtrTy) == 64;
  }

  static CallSemantics fixedOperation(
      llvm::StringRef Name,
      std::vector<CallSemantics::OperationModel::Argument> Arguments = {},
      std::vector<unsigned> InvalidatedArguments = {},
      std::optional<ResultConstraint> AcceptedResult = std::nullopt) {
    CallSemantics Result;
    Result.contextEffect = ContextEffect::Preserve;
    CallSemantics::OperationModel Operation;
    Operation.fixedName = Name.str();
    Operation.arguments = std::move(Arguments);
    Operation.invalidatedArguments = std::move(InvalidatedArguments);
    Operation.acceptedResult = std::move(AcceptedResult);
    Result.operation = std::move(Operation);
    return Result;
  }

  static std::optional<CallSemantics>
  glibcX8664Adapter(const CallEvent &Call, CheckerContext &C) {
    if (!supportsGlibcX8664(Call, C))
      return std::nullopt;
    const auto *FD = dyn_cast<FunctionDecl>(Call.getDecl());
    llvm::StringRef Name = FD->getName();
    if (!validGlibcDeclaration(Name, *FD, C.getASTContext()))
      return std::nullopt;

    struct DirectModel {
      llvm::StringLiteral wrapper;
      llvm::StringLiteral syscall;
      unsigned argumentCount;
      int firstOutputArgument;
      int secondOutputArgument;
    };
    static constexpr DirectModel Direct[] = {
        {"close", "close", 1, -1, -1},
        {"write", "write", 3, -1, -1},
        {"ioctl", "ioctl", 3, 2, -1},
        {"fcntl", "fcntl", 3, -1, -1},
        {"fcntl", "fcntl", 2, -1, -1},
        {"getpid", "getpid", 0, -1, -1},
        {"access", "access", 2, -1, -1},
        {"kill", "kill", 2, -1, -1},
    };
    for (const DirectModel &Model : Direct) {
      if (Name != Model.wrapper || Call.getNumArgs() != Model.argumentCount)
        continue;
      std::vector<unsigned> Outputs;
      if (Model.firstOutputArgument >= 0)
        Outputs.push_back(static_cast<unsigned>(Model.firstOutputArgument));
      if (Model.secondOutputArgument >= 0)
        Outputs.push_back(static_cast<unsigned>(Model.secondOutputArgument));
      return fixedOperation(Model.syscall, {}, std::move(Outputs));
    }

    if (Name == "eventfd" && Call.getNumArgs() == 2)
      return fixedOperation("eventfd2");
    using Argument = CallSemantics::OperationModel::Argument;
    if (Name == "safe_close" && Call.getNumArgs() == 4)
      return fixedOperation("close", {Argument::call(3)}, {},
                            ResultConstraint{"==", 0});
    if (Name == "safe_write" && Call.getNumArgs() == 7) {
      const llvm::APSInt *Strict = Call.getArgSVal(3).getAsInteger();
      if (!Strict || Strict->getBitWidth() > 64)
        return std::nullopt;
      int64_t Policy = Strict->getExtValue();
      std::optional<ResultConstraint> Accepted;
      if (Policy == 0) {
        Accepted = ResultConstraint{">=", 0};
      } else if (Policy == 1) {
        const llvm::APSInt *Count = Call.getArgSVal(6).getAsInteger();
        if (!Count || Count->getBitWidth() > 64 ||
            (Count->isUnsigned() &&
             Count->getZExtValue() >
                 static_cast<uint64_t>(std::numeric_limits<int64_t>::max())))
          return std::nullopt;
        int64_t Bytes = Count->isUnsigned()
                            ? static_cast<int64_t>(Count->getZExtValue())
                            : Count->getSExtValue();
        Accepted = ResultConstraint{"==", Bytes};
      } else {
        /* SAFE_WRITE_RETRY can issue more than one write syscall. */
        return std::nullopt;
      }
      return fixedOperation(
          "write",
          {Argument::call(4), Argument::call(5), Argument::call(6)}, {},
          std::move(Accepted));
    }

    unsigned FlagsIndex;
    unsigned RequiredArguments;
    std::vector<Argument> Arguments;
    if (Name == "open" && Call.getNumArgs() >= 2) {
      FlagsIndex = 1;
      RequiredArguments = 2;
      Arguments = {Argument::signedConstant(-100), Argument::call(0),
                   Argument::call(1)};
    } else if (Name == "openat" && Call.getNumArgs() >= 3) {
      FlagsIndex = 2;
      RequiredArguments = 3;
      Arguments = {Argument::call(0), Argument::call(1), Argument::call(2)};
    } else if (Name == "safe_open" && Call.getNumArgs() >= 5) {
      FlagsIndex = 4;
      RequiredArguments = 5;
      Arguments = {Argument::signedConstant(-100), Argument::call(3),
                   Argument::call(4)};
    } else {
      return std::nullopt;
    }

    const llvm::APSInt *Flags = Call.getArgSVal(FlagsIndex).getAsInteger();
    if (!Flags || Flags->getBitWidth() > 64)
      return std::nullopt;
    uint64_t Bits = Flags->getZExtValue();
    constexpr uint64_t OCreat = 0100;
    constexpr uint64_t OTmpfile = 020200000;
    bool NeedsMode = (Bits & OCreat) != 0 || (Bits & OTmpfile) == OTmpfile;
    if (NeedsMode) {
      if (Call.getNumArgs() != RequiredArguments + 1)
        return std::nullopt;
      Arguments.push_back(Argument::call(RequiredArguments));
    } else {
      /* On Linux x86-64 O_LARGEFILE is zero. Extra variadic arguments are
       * ignored exactly as in the glibc wrapper. */
      Arguments.push_back(Argument::unsignedConstant(0));
    }
    std::optional<ResultConstraint> Accepted;
    if (Name == "safe_open")
      Accepted = ResultConstraint{">=", 0};
    return fixedOperation("openat", std::move(Arguments), {},
                          std::move(Accepted));
  }

public:
  static CallSemantics classify(const CallEvent &Call, CheckerContext &C) {
    const auto *ND = dyn_cast_or_null<NamedDecl>(Call.getDecl());
    if (!ND)
      return {};
    llvm::StringRef Name = ND->getName();
    const Adapter Adapters[] = {operationAdapter, commonAdapter, ksftAdapter,
                                bpfAdapter,       nolibcAdapter, ltpAdapter};
    for (Adapter Match : Adapters)
      if (auto Result = Match(Name))
        return std::move(*Result);
    if (auto Result = glibcX8664Adapter(Call, C))
      return std::move(*Result);
    return {};
  }
};

static std::optional<PathOutcome> ltpOutcome(int64_t Flags) {
  constexpr int64_t ResultMask = 0x3f;
  switch (Flags & ResultMask) {
  case 0:
    return PathOutcome::Pass;
  case 1:
    return PathOutcome::Fail;
  case 2:
    return PathOutcome::Broken;
  case 4:
  case 8:
  case 16:
    return PathOutcome::Neutral;
  case 32:
    return PathOutcome::Skip;
  default:
    return std::nullopt;
  }
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

static std::optional<bool> relationToAtom(SymbolRef Expression, SymbolRef Atom,
                                          ASTContext &Context) {
  if (Expression == Atom)
    return false;
  if (const auto *Cast = dyn_cast<SymbolCast>(Expression)) {
    if (!valuePreservingIntegerConversion(Cast->getOperand()->getType(),
                                          Cast->getType(), Context))
      return std::nullopt;
    return relationToAtom(Cast->getOperand(), Atom, Context);
  }
  const auto *Unary = dyn_cast<UnarySymExpr>(Expression);
  if (!Unary || Unary->getOpcode() != UO_Minus)
    return std::nullopt;
  QualType OperandType = Unary->getOperand()->getType();
  QualType ResultType = Unary->getType();
  if (!OperandType->isSignedIntegerType() ||
      !ResultType->isSignedIntegerType() ||
      Context.getIntWidth(OperandType) != Context.getIntWidth(ResultType))
    return std::nullopt;
  auto Inner = relationToAtom(Unary->getOperand(), Atom, Context);
  return Inner ? std::optional<bool>(!*Inner) : std::nullopt;
}

static std::optional<ProjectionSubject>
findProjectionSubject(SVal Value, ProgramStateRef State, QualType ObservedType,
                      ASTContext &Context) {
  SymbolRef ConstrainedSymbol = Value.getAsSymbol(true);
  if (!ConstrainedSymbol)
    return std::nullopt;
  std::optional<ProjectionSubject> Found;
  for (SymbolRef Atom : Value.symbols()) {
    const SymbolOwner *Owner = State->get<SymbolOwners>(Atom);
    if (!Owner)
      continue;
    // The analyzer may represent a same-width signedness cast with the
    // original symbol. Check the AST operand type as well as SymbolCast nodes
    // so such a conversion cannot inherit the syscall's integer semantics.
    if (!valuePreservingIntegerConversion(Atom->getType(), ObservedType,
                                          Context))
      return std::nullopt;
    auto Negated = relationToAtom(ConstrainedSymbol, Atom, Context);
    if (!Negated)
      return std::nullopt;
    EventOrigin Origin{Owner->call, Owner->field, Atom};
    if (Found && (Found->origin.call != Origin.call ||
                  Found->origin.field != Origin.field ||
                  Found->origin.atom != Origin.atom))
      return std::nullopt;
    Found = ProjectionSubject{Origin, ConstrainedSymbol,
                              *Negated ? ProjectionTransform::Negate
                                       : ProjectionTransform::Identity};
  }
  return Found;
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

static bool sameOrigin(const EventOrigin &LHS, const EventOrigin &RHS) {
  return LHS.call == RHS.call && LHS.field == RHS.field && LHS.atom == RHS.atom;
}

static void appendOrigin(std::vector<EventOrigin> &Origins, EventOrigin Value) {
  if (std::none_of(Origins.begin(), Origins.end(),
                   [&](const EventOrigin &Existing) {
                     return sameOrigin(Existing, Value);
                   }))
    Origins.push_back(Value);
}

static void appendProjection(Provenance &EventProvenance,
                             ProjectionSubject Value) {
  appendOrigin(EventProvenance.origins, Value.origin);
  auto Same = [&](const ProjectionSubject &Existing) {
    return sameOrigin(Existing.origin, Value.origin) &&
           Existing.constrainedSymbol == Value.constrainedSymbol &&
           Existing.transform == Value.transform;
  };
  if (std::none_of(EventProvenance.projections.begin(),
                   EventProvenance.projections.end(), Same))
    EventProvenance.projections.push_back(Value);
}

static void mergeProvenance(Provenance &Destination, const Provenance &Source) {
  for (const EventOrigin &Origin : Source.origins)
    appendOrigin(Destination.origins, Origin);
  for (const ProjectionSubject &Projection : Source.projections)
    appendProjection(Destination, Projection);
}

static Provenance provenanceFromSVal(SVal Value, ProgramStateRef State,
                                     QualType ObservedType,
                                     ASTContext &Context) {
  Provenance Result;
  for (SymbolRef Atom : Value.symbols()) {
    if (const SymbolOwner *Owner = State->get<SymbolOwners>(Atom))
      appendOrigin(Result.origins, {Owner->call, Owner->field, Atom});
  }
  if (SymbolRef Symbol = Value.getAsSymbol(true)) {
    if (const Provenance *const *Stored =
            State->get<ProvenanceBySymbol>(Symbol))
      mergeProvenance(Result, **Stored);
  }
  if (auto Projection =
          findProjectionSubject(Value, State, ObservedType, Context))
    appendProjection(Result, *Projection);
  return Result;
}

static Provenance provenanceFromValue(SVal Value, ProgramStateRef State,
                                      QualType ObservedType,
                                      ASTContext &Context) {
  Provenance Result = provenanceFromSVal(Value, State, ObservedType, Context);
  if (!ObservedType->isIntegerType())
    return Result;
  const MemRegion *Region = Value.getAsRegion();
  if (!Region)
    return Result;
  if (const Provenance *const *Stored = State->get<ProvenanceByRegion>(Region))
    mergeProvenance(Result, **Stored);
  const auto *Typed = dyn_cast<TypedValueRegion>(Region);
  if (!Typed)
    return Result;
  SVal StoredValue = State->getSVal(Region, Typed->getValueType());
  if (StoredValue != Value)
    mergeProvenance(Result, provenanceFromSVal(StoredValue, State,
                                               Typed->getValueType(), Context));
  return Result;
}

static bool regionsOverlap(const MemRegion *LHS, const MemRegion *RHS) {
  return LHS && RHS && (LHS->isSubRegionOf(RHS) || RHS->isSubRegionOf(LHS));
}

static ProgramStateRef
removeOverlappingRegionProvenance(ProgramStateRef State,
                                  const MemRegion *Changed) {
  std::vector<const MemRegion *> ToRemove;
  for (const auto &Entry : State->get<ProvenanceByRegion>())
    if (regionsOverlap(Entry.first, Changed))
      ToRemove.push_back(Entry.first);
  for (const MemRegion *Region : ToRemove)
    State = State->remove<ProvenanceByRegion>(Region);
  return State;
}

static EvaluationSite evaluationSite(const Expr *Expression,
                                     CheckerContext &C) {
  return {Expression, C.getLocationContext()};
}

static std::optional<bool> knownTruth(SVal Value, ProgramStateRef State) {
  // This only asks Clang whether the current path proves the predicate. It
  // does not derive a constraint from the expression's AST shape.
  auto Condition = Value.getAs<DefinedOrUnknownSVal>();
  if (!Condition)
    return std::nullopt;
  auto [TrueState, FalseState] = State->assume(*Condition);
  if (TrueState && !FalseState)
    return true;
  if (FalseState && !TrueState)
    return false;
  return std::nullopt;
}

static std::optional<bool> knownTruth(const Expr *Expression, CheckerContext &C,
                                      unsigned Depth = 0) {
  if (!Expression || Depth > 32)
    return std::nullopt;
  const Expr *ValueExpression = Expression;
  Expression = ignoreExpr(Expression);
  if (!Expression)
    return std::nullopt;

  if (const auto *Binary = dyn_cast<BinaryOperator>(Expression)) {
    if (Binary->getOpcode() == BO_LAnd || Binary->getOpcode() == BO_LOr) {
      auto LHS = knownTruth(Binary->getLHS(), C, Depth + 1);
      if (!LHS)
        return std::nullopt;
      if (Binary->getOpcode() == BO_LAnd)
        return *LHS ? knownTruth(Binary->getRHS(), C, Depth + 1)
                    : std::optional<bool>(false);
      return *LHS ? std::optional<bool>(true)
                  : knownTruth(Binary->getRHS(), C, Depth + 1);
    }
  }

  if (const auto *Unary = dyn_cast<UnaryOperator>(Expression)) {
    if (Unary->getOpcode() == UO_LNot) {
      auto Inner = knownTruth(Unary->getSubExpr(), C, Depth + 1);
      return Inner ? std::optional<bool>(!*Inner) : std::nullopt;
    }
  }

  if (const SVal *Stored = C.getState()->get<SValByEvaluationSite>(
          evaluationSite(Expression, C)))
    if (auto Truth = knownTruth(*Stored, C.getState()))
      return Truth;
  return knownTruth(currentValue(ValueExpression, C), C.getState());
}

static void collectDirectProvenance(const Expr *Expression, CheckerContext &C,
                                    Provenance &EventProvenance) {
  if (!Expression)
    return;
  Provenance Direct =
      provenanceFromValue(currentValue(Expression, C), C.getState(),
                          Expression->getType(), C.getASTContext());
  mergeProvenance(EventProvenance, Direct);
}

static void collectProvenance(const Expr *Expression, CheckerContext &C,
                              Provenance &EventProvenance, unsigned Depth = 0) {
  if (!Expression || Depth > 32)
    return;
  const Expr *ValueExpression = Expression;
  Expression = ignoreExpr(Expression);
  if (!Expression)
    return;

  collectDirectProvenance(ValueExpression, C, EventProvenance);
  if (Expression != ValueExpression)
    collectDirectProvenance(Expression, C, EventProvenance);

  if (const Provenance *const *Stored =
          C.getState()->get<ProvenanceByEvaluationSite>(
              evaluationSite(Expression, C)))
    mergeProvenance(EventProvenance, **Stored);

  if (const auto *Ref = dyn_cast<DeclRefExpr>(Expression)) {
    const auto *Variable = dyn_cast<VarDecl>(Ref->getDecl());
    if (!Variable)
      return;
    Loc Location = C.getState()->getLValue(Variable, C.getLocationContext());
    const MemRegion *Region = Location.getAsRegion();
    const Provenance *const *Stored =
        Region ? C.getState()->get<ProvenanceByRegion>(Region) : nullptr;
    if (Stored)
      mergeProvenance(EventProvenance, **Stored);
    return;
  }

  if (const auto *Binary = dyn_cast<BinaryOperator>(Expression)) {
    if (Binary->isComparisonOp())
      return;
    if (Binary->getOpcode() == BO_LAnd || Binary->getOpcode() == BO_LOr) {
      collectProvenance(Binary->getLHS(), C, EventProvenance, Depth + 1);
      auto LHS = knownTruth(Binary->getLHS(), C);
      bool RHSEvaluated =
          LHS && (Binary->getOpcode() == BO_LAnd ? *LHS : !*LHS);
      if (RHSEvaluated)
        collectProvenance(Binary->getRHS(), C, EventProvenance, Depth + 1);
      return;
    }
  }

  if (const auto *Unary = dyn_cast<UnaryOperator>(Expression)) {
    if (Unary->getOpcode() == UO_LNot) {
      collectProvenance(Unary->getSubExpr(), C, EventProvenance, Depth + 1);
      return;
    }
  }
}

static bool resourceCastChain(SymbolRef Expression, SymbolRef Atom) {
  if (Expression == Atom)
    return true;
  const auto *Cast = dyn_cast_or_null<SymbolCast>(Expression);
  return Cast && resourceCastChain(Cast->getOperand(), Atom);
}

struct DependencySource {
  const Invocation *call = nullptr;
  int outputArgument = -1;
};

static std::optional<DependencySource>
dependencyProducer(SVal Value, QualType Type, ProgramStateRef State,
                   ASTContext &Context) {
  SymbolRef Expression = Value.getAsSymbol(true);
  if (!Expression)
    return std::nullopt;
  if (const OutputOwner *Owner = State->get<OutputOwners>(Expression))
    return DependencySource{Owner->call, static_cast<int>(Owner->argument)};
  for (SymbolRef Atom : Value.symbols())
    if (const OutputOwner *Owner = State->get<OutputOwners>(Atom))
      return DependencySource{Owner->call, static_cast<int>(Owner->argument)};
  Provenance ValueProvenance = provenanceFromValue(Value, State, Type, Context);
  const Invocation *Producer = nullptr;
  bool Found = false;
  for (const EventOrigin &Origin : ValueProvenance.origins) {
    if (Origin.field != EventField::Result ||
        !resourceCastChain(Expression, Origin.atom))
      return std::nullopt;
    if (Found && Producer != Origin.call)
      return std::nullopt;
    Producer = Origin.call;
    Found = true;
  }
  if (!Found)
    return std::nullopt;
  return DependencySource{Producer, -1};
}

static std::string comparisonOperator(BinaryOperatorKind Opcode) {
  switch (Opcode) {
  case BO_LT:
    return "<";
  case BO_LE:
    return "<=";
  case BO_GT:
    return ">";
  case BO_GE:
    return ">=";
  case BO_EQ:
    return "==";
  case BO_NE:
    return "!=";
  default:
    return {};
  }
}

static BinaryOperatorKind reverseComparison(BinaryOperatorKind Opcode) {
  switch (Opcode) {
  case BO_LT:
    return BO_GT;
  case BO_LE:
    return BO_GE;
  case BO_GT:
    return BO_LT;
  case BO_GE:
    return BO_LE;
  default:
    return Opcode;
  }
}

static std::string negateComparison(llvm::StringRef Opcode) {
  if (Opcode == "<")
    return ">=";
  if (Opcode == "<=")
    return ">";
  if (Opcode == ">")
    return "<=";
  if (Opcode == ">=")
    return "<";
  if (Opcode == "==")
    return "!=";
  if (Opcode == "!=")
    return "==";
  return {};
}

static std::optional<int64_t> comparisonConstant(SVal Value) {
  const llvm::APSInt *Integer = Value.getAsInteger();
  if (!Integer || Integer->getBitWidth() > 64 ||
      (Integer->isUnsigned() &&
       Integer->getZExtValue() >
           static_cast<uint64_t>(std::numeric_limits<int64_t>::max())))
    return std::nullopt;
  return Integer->isUnsigned() ? static_cast<int64_t>(Integer->getZExtValue())
                               : Integer->getSExtValue();
}

static std::optional<ComparisonHint>
comparisonHintFor(const BinaryOperator *Compare, CheckerContext &C) {
  if (!Compare || !Compare->isComparisonOp())
    return std::nullopt;
  SVal Left = currentValue(Compare->getLHS(), C);
  SVal Right = currentValue(Compare->getRHS(), C);
  auto LeftConstant = comparisonConstant(Left);
  auto RightConstant = comparisonConstant(Right);
  SymbolRef Subject = nullptr;
  const Expr *SubjectExpression = nullptr;
  int64_t Constant = 0;
  BinaryOperatorKind Opcode = Compare->getOpcode();
  if (RightConstant && !LeftConstant) {
    Subject = Left.getAsSymbol(true);
    SubjectExpression = Compare->getLHS();
    Constant = *RightConstant;
  } else if (LeftConstant && !RightConstant) {
    Subject = Right.getAsSymbol(true);
    SubjectExpression = Compare->getRHS();
    Constant = *LeftConstant;
    Opcode = reverseComparison(Opcode);
  }
  std::string Spelling = comparisonOperator(Opcode);
  if (!Subject || Spelling.empty())
    return std::nullopt;
  const auto *Ref =
      dyn_cast_or_null<DeclRefExpr>(ignoreExpr(SubjectExpression));
  const ValueDecl *SubjectDecl = Ref ? Ref->getDecl() : nullptr;
  return ComparisonHint{Subject,
                        SubjectDecl,
                        {std::move(Spelling), Constant},
                        C.getSVal(Compare)};
}

static bool symbolMatches(SymbolRef Subject, const CapturedArgument &Argument) {
  if (Subject == Argument.symbol)
    return true;
  return std::find(Argument.atoms.begin(), Argument.atoms.end(), Subject) !=
         Argument.atoms.end();
}

static std::vector<ResultConstraint>
comparisonHintsFor(const CapturedArgument &Argument, ProgramStateRef State) {
  std::vector<ResultConstraint> Result;
  for (const auto &Entry : State->get<ComparisonHintByEvaluationSite>()) {
    const ComparisonHint *Hint = Entry.second;
    if (!Hint)
      continue;
    auto Truth = knownTruth(Hint->predicate, State);
    if (!Truth)
      continue;
    ResultConstraint Effective = Hint->spelling;
    if (!*Truth)
      Effective.op = negateComparison(Effective.op);
    if (Effective.op.empty())
      continue;
    bool Matches =
        symbolMatches(Hint->subject, Argument) ||
        (Argument.sourceDecl && Hint->subjectDecl == Argument.sourceDecl);
    if (!Matches && Argument.kind == CapturedArgument::Concrete &&
        Argument.concrete.kind == ConcreteValue::Integer &&
        !Argument.concrete.isUnsigned && Effective.op == "==" &&
        static_cast<int64_t>(Argument.concrete.bits) == Effective.value)
      Matches = true;
    if (!Matches)
      continue;
    if (std::none_of(Result.begin(), Result.end(), [&](const auto &Existing) {
          return Existing.op == Effective.op &&
                 Existing.value == Effective.value;
        }))
      Result.push_back(std::move(Effective));
  }
  return Result;
}

static std::optional<IntegerDomain>
domainForSymbols(SymbolRef Symbol, llvm::ArrayRef<SymbolRef> Atoms,
                 ProgramStateRef State) {
  ConstraintMap Constraints = getConstraintMap(State);
  IntegerDomain Result = fullDomain();
  std::set<SymbolRef> Seen;
  auto Intersect = [&](SymbolRef Candidate) -> bool {
    if (!Candidate || !Seen.insert(Candidate).second)
      return true;
    const RangeSet *Ranges = Constraints.lookup(Candidate);
    if (!Ranges)
      return true;
    auto Domain = domainForRangeSet(*Ranges);
    if (!Domain)
      return false;
    Result = intersectDomains(std::move(Result), std::move(*Domain));
    return true;
  };
  if (!Intersect(Symbol))
    return std::nullopt;
  for (SymbolRef Atom : Atoms)
    if (!Intersect(Atom))
      return std::nullopt;
  normalizeDomain(Result);
  return Result;
}

static ConstraintSet constraintsForInvocation(const Invocation *Call,
                                              ProgramStateRef State) {
  ConstraintSet Result;
  auto Project = [&](SymbolRef Symbol) -> std::optional<ResultConstraint> {
    auto Domain = domainForSymbols(Symbol, {}, State);
    if (!Domain || isFullDomain(*Domain))
      return std::nullopt;
    DomainProjection Projection = projectDomain(*Domain);
    return Projection.kind == ProjectionKind::Exact
               ? std::move(Projection.constraint)
               : std::nullopt;
  };
  Result.ret = Project(Call->resultSymbol);
  Result.error = Project(Call->errnoSymbol);
  if (Result.error && !Result.ret)
    Result.ret = ResultConstraint{"==", -1};
  return Result;
}

static bool collectDependencies(const Invocation *Call,
                                std::vector<const Invocation *> &Ordered,
                                std::set<const Invocation *> &Visiting,
                                std::set<const Invocation *> &Done) {
  if (!Call)
    return false;
  if (Done.count(Call))
    return true;
  if (!Visiting.insert(Call).second)
    return false;
  for (const CapturedArgument &Argument : Call->args) {
    if (Argument.kind != CapturedArgument::Reference)
      continue;
    if (!collectDependencies(Argument.producer, Ordered, Visiting, Done))
      return false;
  }
  Visiting.erase(Call);
  Done.insert(Call);
  Ordered.push_back(Call);
  return true;
}

static std::optional<MaterializedArgument>
materializeArgument(const CapturedArgument &Argument, ProgramStateRef State,
                    const std::map<DependencyKey, std::string> &Names,
                    const Invocation *Owner = nullptr,
                    unsigned ArgumentIndex = 0) {
  MaterializedArgument Result;
  if (Argument.kind == CapturedArgument::Concrete) {
    Result.kind = MaterializedArgument::Concrete;
    Result.concrete = Argument.concrete;
    Result.hints = comparisonHintsFor(Argument, State);
    return Result;
  }
  if (Argument.kind == CapturedArgument::Reference) {
    auto Name = Names.find(
        DependencyKey{Argument.producer, Argument.producerOutputArgument});
    if (Name == Names.end())
      return std::nullopt;
    Result.kind = MaterializedArgument::Reference;
    Result.reference = Name->second;
    return Result;
  }
  if (Argument.kind == CapturedArgument::Output) {
    Result.kind = MaterializedArgument::Output;
    Result.outputSize = Argument.outputSize;
    auto Name = Names.find(
        DependencyKey{Owner, static_cast<int>(ArgumentIndex)});
    if (Name != Names.end())
      Result.outputBinding = Name->second;
    if (!Result.outputSize && Result.outputBinding.empty())
      return std::nullopt;
    return Result;
  }
  if (Argument.kind != CapturedArgument::Symbolic)
    return std::nullopt;
  auto Domain = domainForSymbols(Argument.symbol, Argument.atoms, State);
  if (!Domain || Domain->empty() || isFullDomain(*Domain))
    return std::nullopt;
  Result.kind = MaterializedArgument::Domain;
  Result.domain = std::move(*Domain);
  Result.hints = comparisonHintsFor(Argument, State);
  return Result;
}

static std::optional<MaterializedCall>
materializeCall(const Invocation *Call, ProgramStateRef State,
                const std::map<DependencyKey, std::string> &Names,
                bool Setup) {
  MaterializedCall Result;
  Result.syscall = Call->syscall;
  if (Setup) {
    auto Name = Names.find(DependencyKey{Call, -1});
    if (Name != Names.end())
      Result.bind = Name->second;
    Result.result = constraintsForInvocation(Call, State);
  }
  for (unsigned Index = 0; Index < Call->args.size(); ++Index) {
    const CapturedArgument &Argument = Call->args[Index];
    auto Materialized =
        materializeArgument(Argument, State, Names, Call, Index);
    if (!Materialized)
      return std::nullopt;
    Result.args.push_back(std::move(*Materialized));
  }
  return Result;
}

static std::optional<ScenarioObservation>
materializeScenario(const AssertionMarker *Marker, ConstraintDomains Domains,
                    ProgramStateRef State) {
  const Invocation *Target = Marker ? Marker->call : nullptr;
  if (!Target || !ActiveCollector)
    return std::nullopt;

  std::vector<const Invocation *> Ordered;
  std::set<const Invocation *> Visiting;
  std::set<const Invocation *> Done;
  if (!collectDependencies(Target, Ordered, Visiting, Done) || Ordered.empty())
    return std::nullopt;
  Ordered.pop_back();

  std::map<DependencyKey, std::string> Names;
  std::set<std::string> UsedNames;
  unsigned Generated = 0;
  auto NameReferences = [&](const Invocation *Call) {
    for (const CapturedArgument &Argument : Call->args) {
      if (Argument.kind != CapturedArgument::Reference)
        continue;
      DependencyKey Key{Argument.producer, Argument.producerOutputArgument};
      if (Names.count(Key))
        continue;
      std::string Base = ActiveCollector->preferredBinding(Key);
      if (Base.empty())
        Base = "dep" + std::to_string(Generated++);
      std::string Name = Base;
      for (unsigned Suffix = 2; !UsedNames.insert(Name).second; ++Suffix)
        Name = Base + "_" + std::to_string(Suffix);
      Names.emplace(Key, std::move(Name));
    }
  };
  for (const Invocation *Call : Ordered)
    NameReferences(Call);
  NameReferences(Target);

  ScenarioObservation Result;
  Result.function = Target->function;
  Result.result = std::move(Domains);
  for (const Invocation *Call : Ordered) {
    auto Setup = materializeCall(Call, State, Names, true);
    if (!Setup)
      return std::nullopt;
    Result.setup.push_back(std::move(*Setup));
  }
  auto MaterializedTarget = materializeCall(Target, State, Names, false);
  if (!MaterializedTarget)
    return std::nullopt;
  Result.target = std::move(*MaterializedTarget);
  return Result;
}

static bool modelableOperation(const CallEvent &Call,
                               const CallSemantics &Semantics,
                               CheckerContext &C) {
  if (!Semantics.operation || !ActiveCollector ||
      !ActiveCollector->wantsFunction(functionName(C.getLocationContext())))
    return false;
  const CallSemantics::OperationModel &Operation = *Semantics.operation;
  for (const auto &Argument : Operation.arguments)
    if (Argument.kind == CallSemantics::OperationModel::Argument::CallArgument &&
        Argument.index >= Call.getNumArgs())
      return false;
  for (unsigned Index : Operation.invalidatedArguments)
    if (Index >= Call.getNumArgs())
      return false;
  if (Operation.firstArgument > Call.getNumArgs())
    return false;
  if (!Operation.numberArgument)
    return !Operation.fixedName.empty();
  if (*Operation.numberArgument >= Call.getNumArgs())
    return false;
  const llvm::APSInt *Number =
      Call.getArgSVal(*Operation.numberArgument).getAsInteger();
  return Number && Number->getBitWidth() <= 64;
}

struct OutputArgumentModel {
  bool storesScalar = false;
};

static std::optional<OutputArgumentModel>
outputArgumentModel(llvm::StringRef Syscall, const CallEvent &Call,
                    unsigned Index) {
  struct Rule {
    llvm::StringLiteral syscall;
    unsigned argument;
    int selectorArgument;
    int64_t selectorValue;
    bool storesScalar;
  };
  /* Indices are call-expression indices, including syscall(2)'s number at 0.
   * A selector of -1 makes the direction unconditional. */
  static constexpr Rule Rules[] = {
      {"timer_create", 3, -1, 0, true},
      {"sysfs", 3, 1, 2, false},
  };
  for (const Rule &Candidate : Rules) {
    if (Syscall != Candidate.syscall || Index != Candidate.argument)
      continue;
    if (Candidate.selectorArgument >= 0) {
      unsigned Selector = static_cast<unsigned>(Candidate.selectorArgument);
      if (Selector >= Call.getNumArgs())
        continue;
      const llvm::APSInt *Value = Call.getArgSVal(Selector).getAsInteger();
      if (!Value || Value->getBitWidth() > 64 ||
          Value->getExtValue() != Candidate.selectorValue)
        continue;
    }
    return OutputArgumentModel{Candidate.storesScalar};
  }
  return std::nullopt;
}

static std::optional<uint64_t> outputObjectSize(const Expr *Expression,
                                                ASTContext &Context) {
  Expression = ignoreExpr(Expression);
  if (!Expression)
    return std::nullopt;
  QualType Type = Expression->getType();
  if (!Context.getAsConstantArrayType(Type))
    return std::nullopt;
  CharUnits Size = Context.getTypeSizeInChars(Type);
  if (Size.isNegative())
    return std::nullopt;
  return static_cast<uint64_t>(Size.getQuantity());
}

static const InitListExpr *semanticInitializers(const Expr *Expression) {
  auto *Initializers =
      dyn_cast_or_null<InitListExpr>(ignoreExpr(Expression));
  if (!Initializers)
    return nullptr;
  if (!Initializers->isSemanticForm())
    Initializers = Initializers->getSemanticForm();
  return Initializers;
}

static std::optional<ConcreteValue>
constantInitializerValue(const Expr *Expression, ASTContext &Context) {
  Expression = ignoreExpr(Expression);
  if (!Expression)
    return std::nullopt;
  if (const auto *Literal = dyn_cast<StringLiteral>(Expression))
    return ConcreteValue::string(Literal->getString().str());
  Expr::EvalResult Evaluated;
  if (!Expression->EvaluateAsInt(Evaluated, Context))
    return std::nullopt;
  const llvm::APSInt &Integer = Evaluated.Val.getInt();
  if (Integer.getBitWidth() > 64)
    return std::nullopt;
  uint64_t Bits = Integer.isUnsigned()
                      ? Integer.getZExtValue()
                      : static_cast<uint64_t>(Integer.getSExtValue());
  return ConcreteValue::integer(Bits, Integer.isUnsigned());
}

static std::optional<ConcreteValue>
snapshotHarnessArgument(const Expr *Expression, unsigned Case,
                        const ParmVarDecl *HarnessIndex,
                        ASTContext &Context) {
  Expression = ignoreExpr(Expression);
  const FieldDecl *Field = nullptr;
  if (const auto *Member = dyn_cast_or_null<MemberExpr>(Expression)) {
    Field = dyn_cast<FieldDecl>(Member->getMemberDecl());
    Expression = ignoreExpr(Member->getBase());
  }
  const auto *Subscript = dyn_cast_or_null<ArraySubscriptExpr>(Expression);
  const auto *IndexReference = Subscript ? dyn_cast_or_null<DeclRefExpr>(
                                               ignoreExpr(Subscript->getIdx()))
                                         : nullptr;
  if (!Subscript || !IndexReference || !HarnessIndex ||
      IndexReference->getDecl()->getCanonicalDecl() !=
          HarnessIndex->getCanonicalDecl())
    return std::nullopt;
  const auto *ArrayReference =
      dyn_cast_or_null<DeclRefExpr>(ignoreExpr(Subscript->getBase()));
  const auto *Array =
      ArrayReference ? dyn_cast<VarDecl>(ArrayReference->getDecl()) : nullptr;
  if (!Array || !Array->hasGlobalStorage() || !Array->hasInit())
    return std::nullopt;
  const InitListExpr *ArrayValues = semanticInitializers(Array->getInit());
  if (!ArrayValues || Case >= ArrayValues->getNumInits())
    return std::nullopt;
  const Expr *Value = ArrayValues->getInit(Case);
  if (Field) {
    const InitListExpr *Fields = semanticInitializers(Value);
    if (!Fields)
      return std::nullopt;
    unsigned Index = 0;
    bool Found = false;
    for (const FieldDecl *Candidate : Field->getParent()->fields()) {
      if (Candidate->getCanonicalDecl() == Field->getCanonicalDecl()) {
        Found = true;
        break;
      }
      ++Index;
    }
    if (!Found || Index >= Fields->getNumInits())
      return std::nullopt;
    Value = Fields->getInit(Index);
  }
  return constantInitializerValue(Value, Context);
}

static std::optional<IntegerDomain>
domainForAcceptedResult(const ResultConstraint &Constraint) {
  constexpr int64_t Min = std::numeric_limits<int64_t>::min();
  constexpr int64_t Max = std::numeric_limits<int64_t>::max();
  int64_t Value = Constraint.value;
  if (Constraint.op == "==")
    return IntegerDomain{{{Value, Value}}};
  if (Constraint.op == ">=")
    return IntegerDomain{{{Value, Max}}};
  if (Constraint.op == ">" && Value != Max)
    return IntegerDomain{{{Value + 1, Max}}};
  if (Constraint.op == "<=")
    return IntegerDomain{{{Min, Value}}};
  if (Constraint.op == "<" && Value != Min)
    return IntegerDomain{{{Min, Value - 1}}};
  if (Constraint.op == "!=" && Value != Min && Value != Max)
    return IntegerDomain{{{Min, Value - 1}, {Value + 1, Max}}};
  return std::nullopt;
}

static ProgramStateRef
assumeAcceptedResult(ProgramStateRef State, SVal Result, QualType Type,
                     const ResultConstraint &Constraint, CheckerContext &C) {
  BinaryOperatorKind Opcode;
  if (Constraint.op == "==")
    Opcode = BO_EQ;
  else if (Constraint.op == "!=")
    Opcode = BO_NE;
  else if (Constraint.op == ">=")
    Opcode = BO_GE;
  else if (Constraint.op == ">")
    Opcode = BO_GT;
  else if (Constraint.op == "<=")
    Opcode = BO_LE;
  else if (Constraint.op == "<")
    Opcode = BO_LT;
  else
    return State;
  DefinedSVal Constant = C.getSValBuilder().makeIntVal(
      static_cast<uint64_t>(Constraint.value), Type);
  SVal Predicate = C.getSValBuilder().evalBinOp(
      State, Opcode, Result, Constant, C.getASTContext().BoolTy);
  auto Condition = Predicate.getAs<DefinedOrUnknownSVal>();
  return Condition ? State->assume(*Condition, true) : State;
}

class SyscallScenarioChecker
    : public Checker<
          eval::Call, check::PreCall, check::Bind, check::LiveSymbols,
          check::RegionChanges, check::PostStmt<ImplicitCastExpr>,
          check::PostStmt<BinaryOperator>,
          check::BeginFunction, check::EndFunction, check::BranchCondition> {
  static const Expr *fallbackBindingSource(const MemRegion *Region,
                                           const Stmt *Statement) {
    const auto *VariableRegion = dyn_cast_or_null<VarRegion>(Region);
    const VarDecl *Variable =
        VariableRegion ? VariableRegion->getDecl() : nullptr;
    if (const auto *Declaration = dyn_cast_or_null<DeclStmt>(Statement)) {
      if (!Variable)
        return nullptr;
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

  static ProgramStateRef addMarkers(ProgramStateRef State, const Expr *Site,
                                    const Provenance &EventProvenance,
                                    unsigned Sequence) {
    std::map<const Invocation *, Provenance> ByCall;
    for (const ProjectionSubject &Projection : EventProvenance.projections)
      appendProjection(ByCall[Projection.origin.call], Projection);
    for (auto &[Call, CallProvenance] : ByCall) {
      const AssertionMarker *Marker = ActiveCollector->makeAssertionMarker(
          {Site, Call, std::move(CallProvenance.projections),
           State->get<CurrentOutcomeEpoch>(), Sequence, false});
      State = State->add<ActiveGuards>(Marker);
    }
    return State;
  }

  static const Expr *branchExpressionRoot(const Expr *Expression,
                                          ASTContext &Context) {
    const Expr *Current = Expression;
    for (unsigned Depth = 0; Current && Depth < 32; ++Depth) {
      auto Parents = Context.getParents(*Current);
      if (Parents.size() != 1)
        break;
      const auto *Parent = Parents[0].get<Expr>();
      if (!Parent)
        break;
      bool PredicateWrapper = isa<ParenExpr>(Parent) || isa<CastExpr>(Parent);
      if (const auto *Unary = dyn_cast<UnaryOperator>(Parent))
        PredicateWrapper |= Unary->getOpcode() == UO_LNot;
      if (const auto *Binary = dyn_cast<BinaryOperator>(Parent))
        PredicateWrapper |= Binary->getOpcode() == BO_LAnd ||
                            Binary->getOpcode() == BO_LOr;
      if (!PredicateWrapper)
        break;
      Current = Parent;
    }
    return Current ? Current : Expression;
  }

  static void registerGuard(const Expr *Expression, CheckerContext &C) {
    Expression = branchExpressionRoot(Expression, C.getASTContext());
    Provenance EventProvenance;
    collectProvenance(Expression, C, EventProvenance);
    if (EventProvenance.projections.empty())
      return;
    ProgramStateRef State = C.getState();
    unsigned Sequence = State->get<NextOutcomeCandidate>() + 1;
    State = State->set<NextOutcomeCandidate>(Sequence);
    C.addTransition(addMarkers(State, Expression, EventProvenance, Sequence));
  }

  static void observeMarker(const AssertionMarker *Marker,
                            ProgramStateRef State) {
    if (!ActiveCollector)
      return;
    if (auto Domains = domainsForMarker(Marker, State))
      if (auto Scenario =
              materializeScenario(Marker, std::move(*Domains), State))
        ActiveCollector->observe(Marker, std::move(*Scenario));
  }

  /* Complete every currently attributed candidate on this path.  This is used
   * by effects whose adapter policy covers the active control context; epoch
   * boundaries use completeOutcomeEpoch() below instead. */
  static ProgramStateRef completeActiveGuards(ProgramStateRef State,
                                              PathOutcome Outcome) {
    ProgramStateRef Result = State;
    for (const AssertionMarker *Marker : State->get<ActiveGuards>()) {
      switch (Outcome) {
      case PathOutcome::Pass:
        observeMarker(Marker, State);
        break;
      case PathOutcome::Fail:
      case PathOutcome::Broken:
        if (ActiveCollector)
          ActiveCollector->markFailure(Marker);
        break;
      case PathOutcome::Skip:
        if (ActiveCollector)
          ActiveCollector->markSkip(Marker);
        break;
      case PathOutcome::Neutral:
        break;
      }
      Result = Result->remove<ActiveGuards>(Marker);
    }
    return Result;
  }

  static ProgramStateRef completeInnermostGuards(ProgramStateRef State,
                                                 PathOutcome Outcome) {
    unsigned Latest = 0;
    for (const AssertionMarker *Marker : State->get<ActiveGuards>())
      Latest = std::max(Latest, Marker->sequence);
    if (!Latest)
      return State;

    ProgramStateRef Result = State;
    for (const AssertionMarker *Marker : State->get<ActiveGuards>()) {
      if (Marker->sequence != Latest)
        continue;
      switch (Outcome) {
      case PathOutcome::Pass:
        observeMarker(Marker, State);
        break;
      case PathOutcome::Fail:
      case PathOutcome::Broken:
        ActiveCollector->markFailure(Marker);
        break;
      case PathOutcome::Skip:
        ActiveCollector->markSkip(Marker);
        break;
      case PathOutcome::Neutral:
        break;
      }
      Result = Result->remove<ActiveGuards>(Marker);
    }
    return Result;
  }

  /* A report/counter boundary describes one framework result.  Aggregate all
   * event projections accumulated in the epoch into one observation per
   * syscall event, instead of treating each CFG component as an assertion. */
  static ProgramStateRef completeOutcomeEpoch(ProgramStateRef State,
                                              PathOutcome Outcome) {
    std::map<const Invocation *, Provenance> ByCall;
    for (const AssertionMarker *Marker : State->get<ActiveGuards>())
      for (const ProjectionSubject &Projection : Marker->projections)
        appendProjection(ByCall[Projection.origin.call], Projection);

    for (auto &[Call, EventProvenance] : ByCall) {
      const AssertionMarker *Marker = ActiveCollector->makeAssertionMarker(
          {nullptr, Call, std::move(EventProvenance.projections),
           State->get<CurrentOutcomeEpoch>(), 0, true});
      switch (Outcome) {
      case PathOutcome::Pass:
        observeMarker(Marker, State);
        break;
      case PathOutcome::Fail:
      case PathOutcome::Broken:
        ActiveCollector->markFailure(Marker);
        break;
      case PathOutcome::Skip:
        ActiveCollector->markSkip(Marker);
        break;
      case PathOutcome::Neutral:
        break;
      }
    }

    ProgramStateRef Result = State;
    for (const AssertionMarker *Marker : State->get<ActiveGuards>())
      Result = Result->remove<ActiveGuards>(Marker);
    return Result;
  }

  static ProgramStateRef completeForScope(ProgramStateRef State,
                                          PathOutcome Outcome,
                                          OutcomeScope Scope) {
    switch (Scope) {
    case OutcomeScope::ActiveCandidates:
      return completeActiveGuards(State, Outcome);
    case OutcomeScope::InnermostCandidates:
      return completeInnermostGuards(State, Outcome);
    case OutcomeScope::Epoch:
      return completeOutcomeEpoch(State, Outcome);
    }
    return State;
  }

  static void observeActiveGuards(ProgramStateRef State) {
    for (const AssertionMarker *Marker : State->get<ActiveGuards>())
      observeMarker(Marker, State);
  }

  static ProgramStateRef advanceOutcomeEpoch(ProgramStateRef State) {
    return State->set<CurrentOutcomeEpoch>(
        State->get<CurrentOutcomeEpoch>() + 1);
  }

  static unsigned encodeFrameworkStatus(PathOutcome Outcome) {
    return static_cast<unsigned>(Outcome) + 1;
  }

  static std::optional<PathOutcome>
  frameworkStatus(ProgramStateRef State) {
    unsigned Encoded = State->get<FrameworkStatus>();
    if (!Encoded)
      return std::nullopt;
    unsigned Raw = Encoded - 1;
    if (Raw > static_cast<unsigned>(PathOutcome::Neutral))
      return std::nullopt;
    return static_cast<PathOutcome>(Raw);
  }

  static bool acceptsAtTestEnd(ProgramStateRef State) {
    auto Status = frameworkStatus(State);
    return !Status || *Status == PathOutcome::Pass ||
           *Status == PathOutcome::Neutral;
  }

  static ProgramStateRef applyStatusWrite(
      ProgramStateRef State, PathOutcome Outcome,
      OutcomeScope Scope = OutcomeScope::InnermostCandidates) {
    if (Outcome == PathOutcome::Fail || Outcome == PathOutcome::Broken ||
        Outcome == PathOutcome::Skip)
      State = completeForScope(State, Outcome, Scope);
    return State->set<FrameworkStatus>(encodeFrameworkStatus(Outcome));
  }

  static ProgramStateRef applyNonTerminalEffect(ProgramStateRef State,
                                                const OutcomeEffect &Effect) {
    switch (Effect.action) {
    case OutcomeAction::ReportBoundary:
    case OutcomeAction::CounterUpdate:
      State = completeForScope(State, Effect.verdict, Effect.scope);
      return advanceOutcomeEpoch(State);
    case OutcomeAction::StatusWrite:
      return applyStatusWrite(State, Effect.verdict, Effect.scope);
    case OutcomeAction::Terminate:
      return State;
    }
    return State;
  }

  static std::optional<PathOutcome> ksftOutcomeForCode(int64_t Code) {
    switch (Code) {
    case 0:
      return PathOutcome::Pass;
    case 1:
      return PathOutcome::Fail;
    case 2:
    case 3:
    case 4:
      return PathOutcome::Skip;
    default:
      return PathOutcome::Fail;
    }
  }

  static bool modelLtpReporter(const CallEvent &Call, CheckerContext &C) {
    if (Call.getNumArgs() < 3)
      return false;
    const llvm::APSInt *Flags = Call.getArgSVal(2).getAsInteger();
    if (!Flags || Flags->getBitWidth() > 64)
      return false;
    int64_t Value = Flags->isUnsigned()
                        ? static_cast<int64_t>(Flags->getZExtValue())
                        : Flags->getSExtValue();
    auto Outcome = ltpOutcome(Value);
    if (!Outcome)
      return false;
    if (namedCall(Call, "tst_brk_")) {
      // A passing/neutral tst_brk_ terminates without establishing an
      // assertion. Rejected outcomes still classify the active candidates.
      ProgramStateRef State = C.getState();
      if (*Outcome == PathOutcome::Fail || *Outcome == PathOutcome::Broken)
        State = completeOutcomeEpoch(State, *Outcome);
      else if (*Outcome == PathOutcome::Skip)
        State = completeActiveGuards(State, *Outcome);
      C.addSink(State);
      return true;
    }
    OutcomeEffect Effect{*Outcome, OutcomeAction::ReportBoundary};
    C.addTransition(applyNonTerminalEffect(C.getState(), Effect));
    return true;
  }

  static const Expr *singlePointeeExpression(const Expr *Pointer) {
    Pointer = ignoreExpr(Pointer);
    const auto *Address = dyn_cast_or_null<UnaryOperator>(Pointer);
    return Address && Address->getOpcode() == UO_AddrOf
               ? Address->getSubExpr()
               : nullptr;
  }

  static bool modelLtpErrnoSet(const CallEvent &Call, CheckerContext &C) {
    if (Call.getNumArgs() < 3 || !Call.getOriginExpr())
      return false;
    const llvm::APSInt *Count = Call.getArgSVal(2).getAsInteger();
    if (!Count || Count->getBitWidth() > 64 || Count->getExtValue() != 1)
      return false;
    const Expr *ExpectedExpression =
        singlePointeeExpression(Call.getArgExpr(1));
    if (!ExpectedExpression)
      return false;

    auto Error = currentValue(Call.getArgExpr(0), C)
                     .getAs<DefinedOrUnknownSVal>();
    auto Expected = currentValue(ExpectedExpression, C)
                        .getAs<DefinedOrUnknownSVal>();
    if (!Error || !Expected)
      return false;
    DefinedOrUnknownSVal Equal =
        C.getSValBuilder().evalEQ(C.getState(), *Error, *Expected);
    const Expr *Site = Call.getOriginExpr();
    ProgramStateRef State = C.getState()->BindExpr(
        Site, C.getLocationContext(), Equal);

    Provenance EventProvenance;
    collectProvenance(Call.getArgExpr(0), C, EventProvenance);
    if (ActiveCollector && !EventProvenance.origins.empty()) {
      const Provenance *Stored =
          ActiveCollector->makeProvenance(std::move(EventProvenance));
      State = State->set<ProvenanceByEvaluationSite>(evaluationSite(Site, C),
                                                     Stored);
      if (SymbolRef Symbol = Equal.getAsSymbol(true))
        State = State->set<ProvenanceBySymbol>(Symbol, Stored);
    }
    C.addTransition(State);
    return true;
  }

  static std::optional<ConstraintDomains>
  domainsForMarker(const AssertionMarker *Marker, ProgramStateRef State) {
    ConstraintDomains Domains;
    ConstraintMap ClangConstraints = getConstraintMap(State);
    for (const ProjectionSubject &Projection : Marker->projections) {
      IntegerDomain Incoming = fullDomain();
      if (const RangeSet *Ranges =
              ClangConstraints.lookup(Projection.constrainedSymbol)) {
        auto FromClang = domainForRangeSet(*Ranges);
        if (!FromClang)
          return std::nullopt;
        Incoming = Projection.transform == ProjectionTransform::Negate
                       ? negateDomain(std::move(*FromClang))
                       : std::move(*FromClang);
      }
      if (Projection.constrainedSymbol != Projection.origin.atom) {
        if (const RangeSet *Ranges =
                ClangConstraints.lookup(Projection.origin.atom)) {
          auto FromClang = domainForRangeSet(*Ranges);
          if (!FromClang)
            return std::nullopt;
          Incoming =
              intersectDomains(std::move(Incoming), std::move(*FromClang));
        }
      }
      std::optional<IntegerDomain> &Slot =
          Projection.origin.field == EventField::Errno ? Domains.error
                                                       : Domains.ret;
      Slot = Slot ? intersectDomains(std::move(*Slot), std::move(Incoming))
                  : std::move(Incoming);
      if (Slot->empty())
        return std::nullopt;
    }
    if (Domains.error && !domainHasPositiveSolution(*Domains.error))
      return std::nullopt;
    return Domains;
  }

  static bool isKselftestExitCodeField(const FieldDecl *Field) {
    if (!Field || Field->getCanonicalDecl()->getName() != "exit_code" ||
        !Field->getType()->isIntegerType())
      return false;
    const RecordDecl *Record = Field->getParent();
    if (!Record || Record->getCanonicalDecl()->getName() != "__test_metadata")
      return false;
    bool HasTrigger = false;
    for (const FieldDecl *Sibling : Record->fields())
      HasTrigger |= Sibling->getName() == "trigger" &&
                    Sibling->getType()->isIntegerType();
    return HasTrigger;
  }

  static std::optional<PathOutcome> kselftestStatusWrite(SVal Location,
                                                         SVal Value) {
    const auto *Field =
        dyn_cast_or_null<FieldRegion>(Location.getAsRegion());
    if (!Field || !isKselftestExitCodeField(Field->getDecl()))
      return std::nullopt;
    const llvm::APSInt *Integer = Value.getAsInteger();
    if (!Integer || Integer->getBitWidth() > 64)
      return std::nullopt;
    int64_t Code = Integer->isUnsigned()
                       ? static_cast<int64_t>(Integer->getZExtValue())
                       : Integer->getSExtValue();
    return ksftOutcomeForCode(Code);
  }

public:
  ProgramStateRef
  checkRegionChanges(ProgramStateRef State,
                     const InvalidatedSymbols *Invalidated,
                     llvm::ArrayRef<const MemRegion *> ExplicitRegions,
                     llvm::ArrayRef<const MemRegion *> Regions,
                     const LocationContext *, const CallEvent *Call) const {
    // ExprEngine reports an ordinary bind after checkBind() as one identical
    // explicit/changed region with no call or invalidated-symbol set.
    // checkBind() already replaced the overlapping provenance, so processing
    // that notification here would immediately erase the new binding.
    bool OrdinaryBind = !Call && !Invalidated && ExplicitRegions.size() == 1 &&
                        Regions.size() == 1 &&
                        ExplicitRegions.front() == Regions.front();
    if (OrdinaryBind)
      return State;
    for (const MemRegion *Region : ExplicitRegions)
      State = removeOverlappingRegionProvenance(State, Region);
    for (const MemRegion *Region : Regions)
      State = removeOverlappingRegionProvenance(State, Region);
    return State;
  }

  void checkLiveSymbols(ProgramStateRef State, SymbolReaper &Reaper) const {
    auto MarkProvenance = [&](const Provenance *Value) {
      for (const EventOrigin &Origin : Value->origins)
        Reaper.markLive(Origin.atom);
      for (const ProjectionSubject &Projection : Value->projections) {
        Reaper.markLive(Projection.origin.atom);
        Reaper.markLive(Projection.constrainedSymbol);
      }
    };
    for (const auto &Entry : State->get<SymbolOwners>())
      Reaper.markLive(Entry.first);
    for (const auto &Entry : State->get<OutputOwners>())
      Reaper.markLive(Entry.first);
    for (const auto &Entry : State->get<ProvenanceBySymbol>()) {
      Reaper.markLive(Entry.first);
      MarkProvenance(Entry.second);
    }
    for (const auto &Entry : State->get<ProvenanceByEvaluationSite>())
      MarkProvenance(Entry.second);
    for (const auto &Entry : State->get<ProvenanceByRegion>())
      MarkProvenance(Entry.second);
    for (const auto &Entry : State->get<SValByEvaluationSite>())
      if (SymbolRef Symbol = Entry.second.getAsSymbol(true))
        Reaper.markLive(Symbol);
    for (SymbolRef Symbol : State->get<TrackedArgumentSymbols>())
      Reaper.markLive(Symbol);
    for (const auto &Entry : State->get<ComparisonHintByEvaluationSite>()) {
      const ComparisonHint *Hint = Entry.second;
      if (!Hint)
        continue;
      if (Hint->subject)
        Reaper.markLive(Hint->subject);
      if (SymbolRef Symbol = Hint->predicate.getAsSymbol(true))
        Reaper.markLive(Symbol);
    }
  }

  void checkBind(SVal Location, SVal Value, const Stmt *Statement,
                 CheckerContext &C) const {
    const auto *Region =
        dyn_cast_or_null<TypedValueRegion>(Location.getAsRegion());
    if (!Region)
      return;

    ProgramStateRef State =
        removeOverlappingRegionProvenance(C.getState(), Region);
    if (auto Outcome = kselftestStatusWrite(Location, Value))
      State = applyStatusWrite(State, *Outcome);

    if (ActiveCollector) {
      Provenance EventProvenance = provenanceFromValue(
          Value, C.getState(), Region->getValueType(), C.getASTContext());
      if (EventProvenance.projections.empty()) {
        const Expr *Source = fallbackBindingSource(Region, Statement);
        if (Source)
          collectProvenance(Source, C, EventProvenance);
      }
      if (!EventProvenance.origins.empty()) {
        const auto *VariableRegion = dyn_cast<VarRegion>(Region);
        const Invocation *BoundCall = nullptr;
        bool Ambiguous = false;
        for (const EventOrigin &Origin : EventProvenance.origins) {
          if (Origin.field != EventField::Result)
            continue;
          if (BoundCall && BoundCall != Origin.call) {
            Ambiguous = true;
            break;
          }
          BoundCall = Origin.call;
        }
        if (!Ambiguous && BoundCall && VariableRegion)
          ActiveCollector->noteBinding(BoundCall,
                                       VariableRegion->getDecl()->getName());
        const Provenance *Binding =
            ActiveCollector->makeProvenance(std::move(EventProvenance));
        State = State->set<ProvenanceByRegion>(Region, Binding);
        if (SymbolRef Symbol = Value.getAsSymbol(true))
          State = State->set<ProvenanceBySymbol>(Symbol, Binding);
      }
    }
    if (State != C.getState())
      C.addTransition(State);
  }

  bool evalCall(const CallEvent &Call, CheckerContext &C) const {
    CallSemantics Semantics = SemanticDispatcher::classify(Call, C);
    if (Semantics.outcome &&
        Semantics.outcome->action == OutcomeAction::Terminate) {
      ProgramStateRef State = completeForScope(
          C.getState(), Semantics.outcome->verdict, Semantics.outcome->scope);
      C.addSink(State);
      return true;
    }
    if (Semantics.kind == SemanticCallKind::KsftResultCode)
      return false;
    if (Semantics.kind == SemanticCallKind::LtpReporter)
      return modelLtpReporter(Call, C);
    if (Semantics.kind == SemanticCallKind::LtpErrnoSet)
      return modelLtpErrnoSet(Call, C);
    if (!modelableOperation(Call, Semantics, C))
      return false;
    llvm::StringRef Function = functionName(C.getLocationContext());
    const CallSemantics::OperationModel &Operation = *Semantics.operation;
    Invocation Value;
    Value.function = Function.str();
    if (Operation.numberArgument) {
      const llvm::APSInt *NumberValue =
          Call.getArgSVal(*Operation.numberArgument).getAsInteger();
      if (!NumberValue || NumberValue->getBitWidth() > 64)
        return false;
      Value.syscall =
          syscallName(Call, NumberValue->getSExtValue(), C);
    } else {
      Value.syscall = Operation.fixedName;
    }
    Value.eventSite = Call.getOriginExpr();
    struct CapturedOutput {
      unsigned callIndex;
      unsigned capturedIndex;
      bool storesScalar;
    };
    std::vector<CapturedOutput> OutputArguments;
    auto CaptureArgument = [&](unsigned I) {
      SVal ArgumentValue = Call.getArgSVal(I);
      QualType ArgumentType = Call.getArgExpr(I)->getType();
      const auto *ArgumentRef =
          dyn_cast_or_null<DeclRefExpr>(ignoreExpr(Call.getArgExpr(I)));
      const ValueDecl *SourceDecl =
          ArgumentRef ? ArgumentRef->getDecl() : nullptr;
      if (auto Producer = dependencyProducer(
              ArgumentValue, ArgumentType, C.getState(), C.getASTContext())) {
        if (Producer->outputArgument >= 0 && SourceDecl)
          ActiveCollector->noteOutputBinding(
              Producer->call, static_cast<unsigned>(Producer->outputArgument),
              SourceDecl->getName());
        return CapturedArgument::reference(Producer->call,
                                           Producer->outputArgument);
      }
      if (outputArgumentModel(Value.syscall, Call, I))
        return CapturedArgument::output(
            outputObjectSize(Call.getArgExpr(I), C.getASTContext()));
      unsigned HarnessCase = C.getState()->get<CurrentHarnessCase>();
      const FunctionDecl *HarnessFunction =
          topFunction(C.getLocationContext());
      const ParmVarDecl *HarnessIndex =
          HarnessFunction && HarnessFunction->getNumParams() == 1
              ? HarnessFunction->getParamDecl(0)
              : nullptr;
      if (HarnessCase && HarnessIndex)
        if (auto Concrete = snapshotHarnessArgument(
                Call.getArgExpr(I), HarnessCase - 1, HarnessIndex,
                C.getASTContext()))
          return CapturedArgument::concreteValue(std::move(*Concrete),
                                                 SourceDecl);
      if (auto Concrete = snapshotValue(ArgumentValue, ArgumentType,
                                        C.getState(), C.getLocationContext())) {
        return CapturedArgument::concreteValue(std::move(*Concrete),
                                               SourceDecl);
      }
      SymbolRef Symbol = ArgumentValue.getAsSymbol(true);
      if (Symbol && ArgumentType->isIntegerType()) {
        std::vector<SymbolRef> Atoms;
        for (SymbolRef Atom : ArgumentValue.symbols())
          Atoms.push_back(Atom);
        return CapturedArgument::symbolicValue(Symbol, std::move(Atoms),
                                               SourceDecl);
      }
      return CapturedArgument{};
    };
    if (Operation.arguments.empty()) {
      for (unsigned I = Operation.firstArgument; I < Call.getNumArgs(); ++I) {
        unsigned CapturedIndex = Value.args.size();
        Value.args.push_back(CaptureArgument(I));
        if (Value.args.back().kind == CapturedArgument::Output) {
          auto Model = outputArgumentModel(Value.syscall, Call, I);
          OutputArguments.push_back({I, CapturedIndex,
                                     Model && Model->storesScalar});
        }
      }
    } else {
      using Argument = CallSemantics::OperationModel::Argument;
      for (const Argument &Model : Operation.arguments) {
        if (Model.kind == Argument::CallArgument) {
          unsigned CapturedIndex = Value.args.size();
          Value.args.push_back(CaptureArgument(Model.index));
          if (Value.args.back().kind == CapturedArgument::Output) {
            auto Output =
                outputArgumentModel(Value.syscall, Call, Model.index);
            OutputArguments.push_back(
                {Model.index, CapturedIndex,
                 Output && Output->storesScalar});
          }
        } else {
          Value.args.push_back(CapturedArgument::concreteValue(
              ConcreteValue::integer(Model.value,
                                     Model.kind == Argument::UnsignedConstant),
              nullptr));
        }
      }
    }
    SVal Return = C.getSValBuilder().conjureSymbolVal(
        Call, Call.getResultType(), C.blockCount(), this);
    Value.resultSymbol = Return.getAsSymbol();
    if (Operation.modelsErrno) {
      SVal Error = C.getSValBuilder().conjureSymbolVal(
          Call, C.getASTContext().IntTy, C.blockCount(), &ErrnoSymbolTag);
      Value.errnoSymbol = Error.getAsSymbol();
    }
    if (!Value.resultSymbol || (Operation.modelsErrno && !Value.errnoSymbol))
      return false;
    const Invocation *Stored =
        ActiveCollector->makeInvocation(std::move(Value));
    ProgramStateRef State = C.getState();
    if (Operation.acceptedResult) {
      State = assumeAcceptedResult(State, Return, Call.getResultType(),
                                   *Operation.acceptedResult, C);
      if (!State)
        return true;
    }
    std::vector<unsigned> InvalidatedArguments =
        Operation.invalidatedArguments;
    for (const CapturedOutput &Output : OutputArguments)
      if (std::find(InvalidatedArguments.begin(), InvalidatedArguments.end(),
                    Output.callIndex) == InvalidatedArguments.end())
        InvalidatedArguments.push_back(Output.callIndex);
    if (!InvalidatedArguments.empty()) {
      std::vector<SVal> Values;
      Values.reserve(InvalidatedArguments.size());
      for (unsigned Index : InvalidatedArguments) {
        SVal Argument = Call.getArgSVal(Index);
        Values.push_back(Argument);
        if (const MemRegion *Region = Argument.getAsRegion())
          State = removeOverlappingRegionProvenance(State, Region);
      }
      State = State->invalidateRegions(
          Values, C.getCFGElementRef(), C.blockCount(), C.getLocationContext(),
          false, nullptr, &Call);
    }
    for (const CapturedOutput &Captured : OutputArguments) {
      if (!Captured.storesScalar)
        continue;
      SVal Location = Call.getArgSVal(Captured.callIndex);
      QualType PointerType = Call.getArgExpr(Captured.callIndex)->getType();
      if (!PointerType->isPointerType() ||
          !PointerType->getPointeeType()->isIntegerType())
        continue;
      SVal Output = C.getSValBuilder().conjureSymbolVal(
          Call, PointerType->getPointeeType(), C.blockCount(),
          &OutputSymbolTag);
      SymbolRef Symbol = Output.getAsSymbol();
      if (!Symbol)
        continue;
      State = State->bindLoc(Location, Output, C.getLocationContext());
      State = State->set<OutputOwners>(
          Symbol, OutputOwner{Stored, Captured.capturedIndex});
    }
    State = State->BindExpr(Call.getOriginExpr(), C.getLocationContext(),
                            Return);
    State = State->set<SymbolOwners>(Stored->resultSymbol,
                                     SymbolOwner{Stored, EventField::Result});
    if (Stored->errnoSymbol)
      State = State->set<SymbolOwners>(Stored->errnoSymbol,
                                       SymbolOwner{Stored, EventField::Errno});
    for (const CapturedArgument &Argument : Stored->args) {
      if (Argument.kind != CapturedArgument::Symbolic)
        continue;
      if (Argument.symbol)
        State = State->add<TrackedArgumentSymbols>(Argument.symbol);
      for (SymbolRef Atom : Argument.atoms)
        State = State->add<TrackedArgumentSymbols>(Atom);
    }
    if (Stored->errnoSymbol)
      State = State->set<CurrentErrnoOwner>(Stored);
    if (Operation.acceptedResult) {
      if (auto Domain = domainForAcceptedResult(*Operation.acceptedResult)) {
        const AssertionMarker *Marker = ActiveCollector->makeAssertionMarker(
            {Call.getOriginExpr(), Stored, {},
             State->get<CurrentOutcomeEpoch>(), 0, true});
        ConstraintDomains Domains;
        Domains.ret = std::move(*Domain);
        if (auto Scenario =
                materializeScenario(Marker, std::move(Domains), State))
          ActiveCollector->observe(Marker, std::move(*Scenario));
      }
    }
    C.addTransition(State);
    return true;
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    CallSemantics Semantics = SemanticDispatcher::classify(Call, C);
    if (Semantics.outcome &&
        Semantics.outcome->action != OutcomeAction::Terminate) {
      C.addTransition(
          applyNonTerminalEffect(C.getState(), *Semantics.outcome));
      return;
    }
    if (Semantics.kind == SemanticCallKind::KsftResultCode) {
      if (Call.getNumArgs() > 0) {
        if (const llvm::APSInt *Code = Call.getArgSVal(0).getAsInteger()) {
          if (Code->getBitWidth() <= 64) {
            int64_t Value = Code->isUnsigned()
                                ? static_cast<int64_t>(Code->getZExtValue())
                                : Code->getSExtValue();
            if (auto Outcome = ksftOutcomeForCode(Value)) {
              OutcomeEffect Effect{*Outcome, OutcomeAction::ReportBoundary,
                                   OutcomeScope::Epoch};
              C.addTransition(applyNonTerminalEffect(C.getState(), Effect));
            }
          }
        }
      }
      return;
    }
    if (Semantics.operation) {
      if (modelableOperation(Call, Semantics, C))
        return;
      if (C.getState()->get<CurrentErrnoOwner>())
        C.addTransition(C.getState()->remove<CurrentErrnoOwner>());
      return;
    }
    if (Semantics.contextEffect == ContextEffect::Preserve)
      return;
    if (const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl())) {
      const FunctionDecl *Definition = nullptr;
      if (FD->hasBody(Definition))
        return;
    }
    if (!C.getState()->get<CurrentErrnoOwner>())
      return;
    C.addTransition(C.getState()->remove<CurrentErrnoOwner>());
  }

  void checkPostStmt(const BinaryOperator *Compare, CheckerContext &C) const {
    if (!Compare->isComparisonOp())
      return;
    ProgramStateRef State = C.getState();
    EvaluationSite Site = evaluationSite(Compare, C);
    State = State->set<SValByEvaluationSite>(Site, C.getSVal(Compare));
    if (State->get<ComparisonHintByEvaluationSite>(Site))
      State = State->remove<ComparisonHintByEvaluationSite>(Site);
    if (ActiveCollector)
      if (auto Hint = comparisonHintFor(Compare, C))
        State = State->set<ComparisonHintByEvaluationSite>(
            Site, ActiveCollector->makeComparisonHint(std::move(*Hint)));
    if (State->get<ProvenanceByEvaluationSite>(Site))
      State = State->remove<ProvenanceByEvaluationSite>(Site);
    SymbolRef ResultSymbol = C.getSVal(Compare).getAsSymbol(true);
    if (ResultSymbol && State->get<ProvenanceBySymbol>(ResultSymbol))
      State = State->remove<ProvenanceBySymbol>(ResultSymbol);
    if (!ActiveCollector) {
      if (State != C.getState())
        C.addTransition(State);
      return;
    }
    Provenance EventProvenance;
    collectProvenance(Compare->getLHS(), C, EventProvenance);
    collectProvenance(Compare->getRHS(), C, EventProvenance);
    if (EventProvenance.origins.empty()) {
      if (State != C.getState())
        C.addTransition(State);
      return;
    }
    const Provenance *Stored =
        ActiveCollector->makeProvenance(std::move(EventProvenance));
    State = State->set<ProvenanceByEvaluationSite>(Site, Stored);
    if (ResultSymbol)
      State = State->set<ProvenanceBySymbol>(ResultSymbol, Stored);
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
      State =
          State->set<SymbolOwners>(Atom, SymbolOwner{Owner, EventField::Errno});
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkBeginFunction(CheckerContext &C) const {
    if (!C.inTopFrame() || !ActiveCollector)
      return;
    ActiveCollector->seeFunction(functionName(C.getLocationContext()));
    const FunctionDecl *Function = topFunction(C.getLocationContext());
    if (!Function)
      return;
    auto Harness =
        LtpHarnessCaseCounts.find(Function->getCanonicalDecl());
    if (Harness == LtpHarnessCaseCounts.end() || Function->getNumParams() != 1)
      return;
    const ParmVarDecl *Index = Function->getParamDecl(0);
    if (!Index->getType()->isIntegerType())
      return;
    ProgramStateRef State = C.getState();
    Loc Location = State->getLValue(Index, C.getLocationContext());
    for (unsigned Case = 0; Case < Harness->second; ++Case) {
      DefinedSVal Constant =
          C.getSValBuilder().makeIntVal(Case, Index->getType());
      C.addTransition(
          State->bindLoc(Location, Constant, C.getLocationContext())
              ->set<CurrentHarnessCase>(Case + 1));
    }
  }

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
    const auto *Expression = dyn_cast<Expr>(Condition);
    const CFGBlock *Block = C.getCFGElementRef().getParent();
    if (!Expression || !Block)
      return;
    registerGuard(Expression, C);
  }

  void checkEndFunction(const ReturnStmt *, CheckerContext &C) const {
    if (!C.inTopFrame() || !ActiveCollector)
      return;
    if (acceptsAtTestEnd(C.getState()))
      observeActiveGuards(C.getState());
  }
};

class LtpHarnessVisitor : public RecursiveASTVisitor<LtpHarnessVisitor> {
  ASTContext &Context;

  static const FunctionDecl *functionInitializer(const Expr *Expression) {
    Expression = ignoreExpr(Expression);
    if (const auto *Address = dyn_cast_or_null<UnaryOperator>(Expression))
      if (Address->getOpcode() == UO_AddrOf)
        Expression = ignoreExpr(Address->getSubExpr());
    const auto *Reference = dyn_cast_or_null<DeclRefExpr>(Expression);
    return Reference ? dyn_cast<FunctionDecl>(Reference->getDecl()) : nullptr;
  }

public:
  explicit LtpHarnessVisitor(ASTContext &Context) : Context(Context) {}

  bool VisitVarDecl(VarDecl *Variable) {
    if (!Variable->hasGlobalStorage() || !Variable->hasInit())
      return true;
    const auto *RT = Variable->getType()->getAs<RecordType>();
    const RecordDecl *Record = RT ? RT->getDecl() : nullptr;
    if (!Record || Record->getName() != "tst_test")
      return true;
    auto *Initializers =
        dyn_cast_or_null<InitListExpr>(ignoreExpr(Variable->getInit()));
    if (!Initializers)
      return true;
    if (!Initializers->isSemanticForm())
      Initializers = Initializers->getSemanticForm();
    if (!Initializers)
      return true;

    const Expr *CountExpression = nullptr;
    const Expr *FunctionExpression = nullptr;
    unsigned FieldIndex = 0;
    for (const FieldDecl *Field : Record->fields()) {
      const Expr *Initializer = FieldIndex < Initializers->getNumInits()
                                    ? Initializers->getInit(FieldIndex)
                                    : nullptr;
      if (Field->getName() == "tcnt")
        CountExpression = Initializer;
      else if (Field->getName() == "test")
        FunctionExpression = Initializer;
      ++FieldIndex;
    }
    if (!CountExpression || !FunctionExpression)
      return true;
    Expr::EvalResult Evaluated;
    if (!CountExpression->EvaluateAsInt(Evaluated, Context))
      return true;
    const llvm::APSInt &Count = Evaluated.Val.getInt();
    if (Count.isNegative() || Count.getActiveBits() > 32)
      return true;
    uint64_t Cases = Count.getZExtValue();
    /* Keep accidental or malformed descriptors from causing path explosion. */
    if (Cases == 0 || Cases > 256)
      return true;
    const FunctionDecl *Function = functionInitializer(FunctionExpression);
    if (!Function || Function->getNumParams() != 1)
      return true;
    LtpHarnessCaseCounts[Function->getCanonicalDecl()] =
        static_cast<unsigned>(Cases);
    return true;
  }
};

class LtpHarnessConsumer : public ASTConsumer {
public:
  bool HandleTopLevelDecl(DeclGroupRef Declarations) override {
    if (Declarations.isNull())
      return true;
    ASTContext &Context = (*Declarations.begin())->getASTContext();
    LtpHarnessVisitor Visitor(Context);
    for (Decl *Declaration : Declarations)
      Visitor.TraverseDecl(Declaration);
    return true;
  }

  void HandleTranslationUnit(ASTContext &Context) override {
    LtpHarnessVisitor Visitor(Context);
    Visitor.TraverseDecl(Context.getTranslationUnitDecl());
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
    auto Analysis = CreateAnalysisConsumer(CI);
    Analysis->AddCheckerRegistrationFn([](CheckerRegistry &Registry) {
      Registry.addChecker<SyscallScenarioChecker>(
          "extractor.SyscallScenario", "Extract syscall scenarios", "", false);
    });
    LtpHarnessCaseCounts.clear();
    std::vector<std::unique_ptr<ASTConsumer>> Consumers;
    Consumers.push_back(std::make_unique<LtpHarnessConsumer>());
    Consumers.push_back(std::move(Analysis));
    return std::make_unique<MultiplexConsumer>(std::move(Consumers));
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
  if (LibcProfile != "none" && LibcProfile != "glibc-linux-x86_64") {
    llvm::errs() << "Unsupported libc profile: " << LibcProfile << "\n";
    return 2;
  }
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
  Results.finalize();

  json::Array CommandLine;
  for (const std::string &Arg : Command.CommandLine)
    CommandLine.push_back(Arg);
  json::Object Output{
      {"schema_version", 2},
      {"source", Source},
      {"libc_profile", LibcProfile.getValue()},
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
