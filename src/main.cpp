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

static std::optional<int64_t> signedDomainValue(const llvm::APSInt &Value) {
  if (Value.getBitWidth() > 64 || Value.isUnsigned())
    return std::nullopt;
  return Value.getSExtValue();
}

static std::optional<IntegerDomain> domainForRangeSet(const RangeSet &Ranges) {
  constexpr int64_t Min = std::numeric_limits<int64_t>::min();
  constexpr int64_t Max = std::numeric_limits<int64_t>::max();
  IntegerDomain Domain;
  if (Ranges.isEmpty())
    return Domain;
  APSIntType Type = Ranges.getAPSIntType();
  if (Type.getBitWidth() > 64 || Type.isUnsigned())
    return std::nullopt;
  auto TypeMin = signedDomainValue(Type.getMinValue());
  auto TypeMax = signedDomainValue(Type.getMaxValue());
  if (!TypeMin || !TypeMax)
    return std::nullopt;
  for (const Range &R : Ranges) {
    auto Lower = signedDomainValue(R.From());
    auto Upper = signedDomainValue(R.To());
    if (!Lower || !Upper)
      return std::nullopt;
    Domain.ranges.push_back(
        {*Lower == *TypeMin ? Min : *Lower, *Upper == *TypeMax ? Max : *Upper});
  }
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

struct Invocation {
  std::string function;
  std::string syscall;
  std::vector<ConcreteValue> args;
  const Expr *eventSite = nullptr;
  SymbolRef resultSymbol = nullptr;
  SymbolRef errnoSymbol = nullptr;
  bool concrete = false;
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

struct AssertionMarker {
  const Expr *site = nullptr;
  const Invocation *call = nullptr;
  std::vector<ProjectionSubject> projections;
  bool explicitAssertion = false;
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
    const Expr *assertionSite;
    const Expr *eventSite;
    const Invocation *call;
    std::string baseKey;
    std::vector<ConstraintDomains> alternatives;
    bool explicitAssertion = false;
    bool failureSeen = false;
  };

  std::set<std::string> SelectedFunctions;
  std::set<std::string> SelectedSyscalls;
  std::vector<std::unique_ptr<Invocation>> Invocations;
  std::vector<std::unique_ptr<Provenance>> Provenances;
  std::vector<std::unique_ptr<AssertionMarker>> AssertionMarkers;
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

  static std::string baseKey(const Invocation &Call) {
    json::Array Args;
    for (const ConcreteValue &Arg : Call.args)
      Args.push_back(toJSON(Arg));
    return render(
        json::Object{{"syscall", Call.syscall}, {"args", std::move(Args)}});
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

  static void mergeAlternatives(std::vector<ConstraintDomains> &Alternatives) {
    for (ConstraintDomains &Domains : Alternatives)
      canonicalize(Domains);
    bool Changed;
    do {
      Changed = false;
      for (size_t I = 0; I < Alternatives.size() && !Changed; ++I) {
        for (size_t J = I + 1; J < Alternatives.size(); ++J) {
          ConstraintDomains Merged;
          if (equalDomainFields(Alternatives[I].error, Alternatives[J].error) &&
              mergeDomainFields(Alternatives[I].ret, Alternatives[J].ret,
                                Merged.ret)) {
            Merged.error = Alternatives[I].error;
          } else if (equalDomainFields(Alternatives[I].ret,
                                       Alternatives[J].ret) &&
                     mergeDomainFields(Alternatives[I].error,
                                       Alternatives[J].error, Merged.error)) {
            Merged.ret = Alternatives[I].ret;
          } else {
            continue;
          }
          canonicalize(Merged);
          Alternatives[I] = std::move(Merged);
          Alternatives.erase(Alternatives.begin() + J);
          Changed = true;
          break;
        }
      }
    } while (Changed);
  }

  void appendRecord(const Invocation *Call, const std::string &BaseKey,
                    const ConstraintDomains &Domains) {
    DomainProjection Ret = projectDomain(Domains.ret);
    DomainProjection Error = projectDomain(Domains.error);
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

    for (auto It = Records.begin(); It != Records.end();) {
      if (It->function != Call->function || It->baseKey != BaseKey) {
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

    json::Array Args;
    for (const ConcreteValue &Arg : Call->args)
      Args.push_back(toJSON(Arg));
    json::Object ResultObject;
    if (Result.ret)
      ResultObject["ret"] = constraintJSON(*Result.ret);
    if (Result.error)
      ResultObject["errno"] = constraintJSON(*Result.error);
    json::Object Record{{"syscall", Call->syscall},
                        {"args", std::move(Args)},
                        {"result", std::move(ResultObject)}};
    std::string FullKey = render(json::Object(Record));
    Records.push_back({Call->function, BaseKey, std::move(FullKey),
                       std::move(Result), std::move(Record)});
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

  ObservationGroup *groupFor(const AssertionMarker *Marker) {
    const Invocation *Call = Marker ? Marker->call : nullptr;
    if (!Call || !Call->concrete || !wantsFunction(Call->function) ||
        !wantsSyscall(Call->syscall))
      return nullptr;
    Finalized = false;
    std::string Key = baseKey(*Call);
    auto Group =
        std::find_if(ObservationGroups.begin(), ObservationGroups.end(),
                     [&](const ObservationGroup &Candidate) {
                       return Candidate.assertionSite == Marker->site &&
                              Candidate.eventSite == Call->eventSite &&
                              Candidate.call->function == Call->function &&
                              Candidate.baseKey == Key;
                     });
    if (Group == ObservationGroups.end()) {
      ObservationGroups.push_back({Marker->site,
                                   Call->eventSite,
                                   Call,
                                   std::move(Key),
                                   {},
                                   Marker->explicitAssertion,
                                   false});
      return &ObservationGroups.back();
    }
    Group->explicitAssertion |= Marker->explicitAssertion;
    return &*Group;
  }

  void observe(const AssertionMarker *Marker, ConstraintDomains Domains) {
    ObservationGroup *Group = groupFor(Marker);
    if (!Group)
      return;
    canonicalize(Domains);
    Group->alternatives.push_back(std::move(Domains));
  }

  void markFailure(const AssertionMarker *Marker) {
    if (ObservationGroup *Group = groupFor(Marker))
      Group->failureSeen = true;
  }

  void finalize() {
    if (Finalized)
      return;
    Records.clear();
    for (ObservationGroup &Group : ObservationGroups) {
      if ((!Group.explicitAssertion && !Group.failureSeen) ||
          Group.alternatives.empty())
        continue;
      std::vector<ConstraintDomains> Alternatives = Group.alternatives;
      mergeAlternatives(Alternatives);
      for (const ConstraintDomains &Domains : Alternatives)
        appendRecord(Group.call, Group.baseKey, Domains);
    }
    Finalized = true;
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
static int ErrnoSymbolTag;

REGISTER_MAP_WITH_PROGRAMSTATE(SymbolOwners, SymbolRef, SymbolOwner)
REGISTER_MAP_WITH_PROGRAMSTATE(ProvenanceBySymbol, SymbolRef,
                               const Provenance *)
REGISTER_MAP_WITH_PROGRAMSTATE(ProvenanceByComparison, const BinaryOperator *,
                               const Provenance *)
REGISTER_MAP_WITH_PROGRAMSTATE(ProvenanceByRegion, const MemRegion *,
                               const Provenance *)
REGISTER_SET_WITH_PROGRAMSTATE(PendingAssertions, const AssertionMarker *)
REGISTER_SET_WITH_PROGRAMSTATE(ActiveGuards, const AssertionMarker *)
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

static void collectDirectProvenance(const Expr *Expression, CheckerContext &C,
                                    Provenance &EventProvenance) {
  if (!Expression)
    return;
  Provenance Direct =
      provenanceFromSVal(currentValue(Expression, C), C.getState(),
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
    if (Binary->isComparisonOp()) {
      const Provenance *const *Stored =
          C.getState()->get<ProvenanceByComparison>(Binary);
      if (Stored)
        mergeProvenance(EventProvenance, **Stored);
      return;
    }
    if (Binary->getOpcode() == BO_LAnd || Binary->getOpcode() == BO_LOr) {
      collectProvenance(Binary->getLHS(), C, EventProvenance, Depth + 1);
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

static bool assertionMacroAt(SourceLocation Location, CheckerContext &C) {
  const SourceManager &SM = C.getSourceManager();
  for (unsigned Depth = 0; Location.isMacroID() && Depth < 16; ++Depth) {
    llvm::StringRef Name =
        Lexer::getImmediateMacroName(Location, SM, C.getLangOpts());
    if (Name == "EXPECT_SYSEQ" || Name == "EXPECT_SYSZR" ||
        Name == "EXPECT_SYSER")
      return false;
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
                     check::LiveSymbols, check::PreStmt<ReturnStmt>,
                     check::PostStmt<ImplicitCastExpr>,
                     check::PostStmt<BinaryOperator>, check::BeginFunction,
                     check::EndFunction, check::BranchCondition> {
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

  static ProgramStateRef addMarkers(ProgramStateRef State, const Expr *Site,
                                    const Provenance &EventProvenance,
                                    bool ExplicitAssertion) {
    std::map<const Invocation *, Provenance> ByCall;
    for (const ProjectionSubject &Projection : EventProvenance.projections)
      appendProjection(ByCall[Projection.origin.call], Projection);
    for (auto &[Call, CallProvenance] : ByCall) {
      const AssertionMarker *Marker = ActiveCollector->makeAssertionMarker(
          {Site, Call, std::move(CallProvenance.projections),
           ExplicitAssertion});
      State = ExplicitAssertion ? State->add<PendingAssertions>(Marker)
                                : State->add<ActiveGuards>(Marker);
    }
    return State;
  }

  static void applyAssertion(const Expr *Expression, bool Expected,
                             CheckerContext &C) {
    Provenance EventProvenance;
    collectProvenance(Expression, C, EventProvenance);
    if (EventProvenance.projections.empty())
      return;
    ProgramStateRef Base = C.getState();
    if (auto Value = C.getSVal(Expression).getAs<DefinedOrUnknownSVal>()) {
      Base = Base->assume(*Value, Expected);
      if (!Base) {
        C.addSink();
        return;
      }
    }
    Base = addMarkers(Base, Expression, EventProvenance, true);
    C.addTransition(Base);
  }

  static ProgramStateRef assumeEqual(ProgramStateRef State, SVal LHS, SVal RHS,
                                     CheckerContext &C) {
    auto Left = LHS.getAs<DefinedOrUnknownSVal>();
    auto Right = RHS.getAs<DefinedOrUnknownSVal>();
    if (!Left || !Right)
      return State;
    DefinedOrUnknownSVal Equal =
        C.getSValBuilder().evalEQ(State, *Left, *Right);
    return State->assume(Equal, true);
  }

  static bool applyAssertionCall(const CallEvent &Call, CheckerContext &C) {
    bool SysEq = namedCall(Call, "expect_syseq") && Call.getNumArgs() >= 2;
    bool SysZero = namedCall(Call, "expect_syszr") && Call.getNumArgs() >= 1;
    bool SysError = namedCall(Call, "expect_syserr") && Call.getNumArgs() >= 3;
    if (!SysEq && !SysZero && !SysError)
      return false;

    Provenance EventProvenance;
    if (const Expr *Argument = Call.getArgExpr(0))
      collectProvenance(Argument, C, EventProvenance);
    if (EventProvenance.projections.empty())
      return true;
    ProgramStateRef State = C.getState();
    SVal Expected =
        SysZero
            ? C.getSValBuilder().makeIntVal(0, Call.getArgExpr(0)->getType())
            : Call.getArgSVal(1);
    State = assumeEqual(State, Call.getArgSVal(0), Expected, C);
    if (!State) {
      C.addSink();
      return true;
    }

    if (SysError) {
      std::vector<const Invocation *> Calls;
      for (const ProjectionSubject &Projection : EventProvenance.projections)
        if (Projection.origin.field == EventField::Result &&
            std::find(Calls.begin(), Calls.end(), Projection.origin.call) ==
                Calls.end())
          Calls.push_back(Projection.origin.call);
      for (const Invocation *Invocation : Calls) {
        if (!Invocation->errnoSymbol)
          continue;
        State = assumeEqual(State, nonloc::SymbolVal(Invocation->errnoSymbol),
                            Call.getArgSVal(2), C);
        if (!State) {
          C.addSink();
          return true;
        }
        appendProjection(EventProvenance, {{Invocation, EventField::Errno,
                                            Invocation->errnoSymbol},
                                           Invocation->errnoSymbol,
                                           ProjectionTransform::Identity});
      }
    }

    const Expr *Site = Call.getOriginExpr();
    State = addMarkers(State, Site, EventProvenance, true);
    C.addTransition(State);
    return true;
  }

  static void registerGuard(const Expr *Expression, CheckerContext &C) {
    Provenance EventProvenance;
    collectProvenance(Expression, C, EventProvenance);
    if (!EventProvenance.projections.empty())
      C.addTransition(
          addMarkers(C.getState(), Expression, EventProvenance, false));
  }

  static void markFailureGuards(ProgramStateRef State) {
    if (!ActiveCollector)
      return;
    for (const AssertionMarker *Marker : State->get<ActiveGuards>())
      ActiveCollector->markFailure(Marker);
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

public:
  void checkLiveSymbols(ProgramStateRef State, SymbolReaper &Reaper) const {
    for (const auto &Entry : State->get<SymbolOwners>())
      Reaper.markLive(Entry.first);
    for (const auto &Entry : State->get<ProvenanceBySymbol>()) {
      Reaper.markLive(Entry.first);
      for (const EventOrigin &Origin : Entry.second->origins)
        Reaper.markLive(Origin.atom);
      for (const ProjectionSubject &Projection : Entry.second->projections) {
        Reaper.markLive(Projection.origin.atom);
        Reaper.markLive(Projection.constrainedSymbol);
      }
    }
  }

  void checkBind(SVal Location, SVal Value, const Stmt *Statement,
                 CheckerContext &C) const {
    const auto *Region = dyn_cast_or_null<VarRegion>(Location.getAsRegion());
    const VarDecl *Variable = Region ? Region->getDecl() : nullptr;
    if (!Variable)
      return;

    ProgramStateRef State = C.getState();
    if (State->get<ProvenanceByRegion>(Region))
      State = State->remove<ProvenanceByRegion>(Region);

    if (ActiveCollector) {
      Provenance EventProvenance = provenanceFromSVal(
          Value, C.getState(), Variable->getType(), C.getASTContext());
      const Expr *Source = bindingSource(Variable, Statement);
      if (Source)
        collectProvenance(Source, C, EventProvenance);
      if (!EventProvenance.origins.empty()) {
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
    if (knownFailureCall(
            dyn_cast_or_null<CallExpr>(ignoreExpr(Call.getOriginExpr())))) {
      markFailureGuards(C.getState());
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
    Value.eventSite = Call.getOriginExpr();
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
    SVal Return = C.getSValBuilder().conjureSymbolVal(
        Call, Call.getResultType(), C.blockCount(), this);
    SVal Error = C.getSValBuilder().conjureSymbolVal(
        Call, C.getASTContext().IntTy, C.blockCount(), &ErrnoSymbolTag);
    Value.resultSymbol = Return.getAsSymbol();
    Value.errnoSymbol = Error.getAsSymbol();
    if (!Value.resultSymbol || !Value.errnoSymbol)
      return false;
    const Invocation *Stored =
        ActiveCollector->makeInvocation(std::move(Value));
    ProgramStateRef State = C.getState()->BindExpr(
        Call.getOriginExpr(), C.getLocationContext(), Return);
    State = State->set<SymbolOwners>(Stored->resultSymbol,
                                     SymbolOwner{Stored, EventField::Result});
    State = State->set<SymbolOwners>(Stored->errnoSymbol,
                                     SymbolOwner{Stored, EventField::Errno});
    State = State->set<CurrentErrnoOwner>(Stored);
    C.addTransition(State);
    return true;
  }

  void checkPreStmt(const ReturnStmt *Return, CheckerContext &C) const {
    if (knownFailureReturn(Return, C)) {
      markFailureGuards(C.getState());
      C.addSink();
    }
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (namedCall(Call, "ksft_test_result") && Call.getNumArgs() > 0) {
      if (const Expr *Condition = Call.getArgExpr(0))
        applyAssertion(Condition, true, C);
      return;
    }
    if (applyAssertionCall(Call, C))
      return;
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
    if (!Compare->isComparisonOp() || !ActiveCollector)
      return;
    ProgramStateRef State = C.getState();
    if (State->get<ProvenanceByComparison>(Compare))
      State = State->remove<ProvenanceByComparison>(Compare);
    SymbolRef ResultSymbol = C.getSVal(Compare).getAsSymbol(true);
    if (ResultSymbol && State->get<ProvenanceBySymbol>(ResultSymbol))
      State = State->remove<ProvenanceBySymbol>(ResultSymbol);
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
    State = State->set<ProvenanceByComparison>(Compare, Stored);
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
  }

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
    const auto *Expression = dyn_cast<Expr>(Condition);
    const CFGBlock *Block = C.getCFGElementRef().getParent();
    if (!Expression || !Block)
      return;
    if (const auto *If = dyn_cast_or_null<IfStmt>(Block->getTerminatorStmt())) {
      if (ignoreExpr(Expression) == ignoreExpr(If->getCond()) &&
          (assertionMacroAt(If->getIfLoc(), C) ||
           assertionMacroAt(Expression->getExprLoc(), C))) {
        applyAssertion(Expression, false, C);
        return;
      }
    }
    registerGuard(Expression, C);
  }

  void checkEndFunction(const ReturnStmt *, CheckerContext &C) const {
    if (!C.inTopFrame() || !ActiveCollector)
      return;
    for (const AssertionMarker *Marker :
         C.getState()->get<PendingAssertions>()) {
      if (auto Domains = domainsForMarker(Marker, C.getState())) {
        ActiveCollector->observe(Marker, std::move(*Domains));
      }
    }
    for (const AssertionMarker *Marker : C.getState()->get<ActiveGuards>())
      if (auto Domains = domainsForMarker(Marker, C.getState()))
        ActiveCollector->observe(Marker, std::move(*Domains));
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
  Results.finalize();

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
