--------------------------- MODULE AgentVaultSync ---------------------------
(***************************************************************************)
(* The sync protocol of agent-vault (src/agent_vault/sync.py): runs on      *)
(* several machines keep one login file per machine in step with one vault *)
(* secret, while the programs they wrap refresh credentials in the file    *)
(* and people edit the secret by hand.                                     *)
(*                                                                         *)
(* Each action is one phase of a Syncer and is atomic for the reason given *)
(* next to it. The flags switch on each of doppler-nix's behaviours, so    *)
(* TLC can show what each one breaks (spec/README.md):                     *)
(*                                                                         *)
(*   Guarded     writes are compare-and-set (Doppler's originalValue).     *)
(*               FALSE: blind writes, as `doppler secrets set`.            *)
(*   SharedBase  one base per machine and a sync mutex, so the runs on a   *)
(*               machine sync one at a time. FALSE: one base per run, no   *)
(*               mutex.                                                    *)
(*   Rebase      after a write that failed, a credential the merge took    *)
(*               from the vault joins the base. FALSE: the whole old base  *)
(*               stays, and a pull or a sync that wrote nothing makes the  *)
(*               merge the base.                                           *)
(*                                                                         *)
(* A credential value is a number; 0 is "absent". Every new value is the   *)
(* next number, so for a credential with a time key (Timed) a larger       *)
(* value is a later time. Bases hold values here; the code holds digests   *)
(* of them, which are equal exactly when the values are.                   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Machines,       \* machines, each with its own copy of the file
    Runs,           \* runs of the wrapped command
    Host,           \* Host[r]: the machine run r runs on
    Timed,          \* credentials with a time key (OAuth logins)
    Untimed,        \* credentials without one (API keys)
    MaxValue,       \* bound on new credential values
    MaxFaults,      \* bound on vault failures (a read or write that errs)
    MaxAttempts,    \* compare-and-set attempts per operation (sync.MAX_ATTEMPTS)
    Guarded, SharedBase, Rebase,
    Ephemeral,      \* remove the file at the end (pi's preset)
    AllowLogout,    \* programs may remove a credential from the file
    AllowHandEdit   \* people may edit the secret in the vault

Creds == Timed \cup Untimed
NoRun == "none"
Zero == [c \in Creds |-> 0]
Max(a, b) == IF a > b THEN a ELSE b

(* The owner of a base: the machine, or the run (doppler-nix). *)
Owner(r) == IF SharedBase THEN Host[r] ELSE r
Owners == IF SharedBase THEN Machines ELSE Runs

VARIABLES
    vault,      \* the vault's copy: [Creds -> value]
    file,       \* file[m]: the file on machine m
    base,       \* base[o]: the value each credential had when file and vault last agreed
    hasBase,    \* hasBase[o]: a base is recorded (none before the first sync, or after removal)
    mutex,      \* mutex[m]: the run holding machine m's sync mutex
    sessions,   \* sessions[m]: runs holding the shared session lock on m's directory
    excl,       \* excl[m]: the run holding it exclusively (removing the file)
    pc,         \* the phase of each run
    prog,       \* prog[r]: run r's command is running
    snap,       \* snap[r]: the vault as last read by run r
    merged,     \* merged[r]: run r's merge, waiting to be written
    fileNow,    \* fileNow[r]: what the file held after run r's merge
    cur,        \* cur[r]: the file as read for the write-back
    attempts,   \* attempts[r]: compare-and-set attempts in the current operation
    synced,     \* synced[r]: the write-back succeeded
    clock,      \* the last value made
    faults,     \* vault failures so far
    \* History, for the properties only:
    newest,     \* newest[c]: the latest value a program made for c
    replaced,   \* replaced[c]: values the vault held and replaced
    loggedOut,  \* a program removed a credential from its file
    gaveUp,     \* a run ended without writing back
    badRemoval, \* a file was removed while the vault lacked part of it
    lostLocal   \* a sync replaced in a file a value the vault never had

vars == <<vault, file, base, hasBase, mutex, sessions, excl, pc, prog, snap, merged,
          fileNow, cur, attempts, synced, clock, faults, newest, replaced, loggedOut,
          gaveUp, badRemoval, lostLocal>>

Phases == {"start", "pullBegin", "pullRead", "pullMerge", "running", "syncRead",
           "syncMerge", "syncWrite", "exitBegin", "exitRead", "exitMerge", "exitWrite",
           "remove", "release", "done"}

(* --- The merge (src/agent_vault/merge.py) ------------------------------ *)

(* merge.newer: a later time wins; otherwise the local copy wins if it     *)
(* changed since the base; a credential missing on one side is kept.       *)
Newer(c, l, r, b) ==
    IF r = 0 THEN l
    ELSE IF l = 0 THEN r
    ELSE IF c \in Timed /\ l # r THEN Max(l, r)
    ELSE IF l # b THEN l
    ELSE r

Merge(L, R, B) == [c \in Creds |-> Newer(c, L[c], R[c], B[c])]

(* merge.push's `kept`: what the command removed since the base stays out. *)
Kept(L, M, B) == [c \in Creds |-> IF B[c] # 0 /\ L[c] = 0 THEN 0 ELSE M[c]]

(* merge.rebase: a credential whose copies in file and vault are equal is  *)
(* in step; any other keeps its base.                                      *)
RebaseTo(B, F, V) == [c \in Creds |-> IF F[c] # 0 /\ F[c] = V[c] THEN F[c] ELSE B[c]]

InVault(c) == replaced[c] \cup {vault[c]}

(* A sync that changes the file only replaces values the vault had. *)
LosesLocal(old, new) == \E c \in Untimed : old[c] # new[c] /\ old[c] # 0 /\ old[c] \notin InVault(c)

(* --- Initial state ------------------------------------------------------ *)

Init ==
    /\ vault = [c \in Creds |-> IF c \in Timed THEN 1 ELSE 2]
    /\ file = [m \in Machines |-> Zero]
    /\ base = [o \in Owners |-> Zero]
    /\ hasBase = [o \in Owners |-> FALSE]
    /\ mutex = [m \in Machines |-> NoRun]
    /\ sessions = [m \in Machines |-> {}]
    /\ excl = [m \in Machines |-> NoRun]
    /\ pc = [r \in Runs |-> "start"]
    /\ prog = [r \in Runs |-> FALSE]
    /\ snap = [r \in Runs |-> Zero]
    /\ merged = [r \in Runs |-> Zero]
    /\ fileNow = [r \in Runs |-> Zero]
    /\ cur = [r \in Runs |-> Zero]
    /\ attempts = [r \in Runs |-> 0]
    /\ synced = [r \in Runs |-> FALSE]
    /\ clock = 2
    /\ faults = 0
    /\ newest = [c \in Creds |-> IF c \in Timed THEN 1 ELSE 0]
    /\ replaced = [c \in Creds |-> {}]
    /\ loggedOut = FALSE
    /\ gaveUp = FALSE
    /\ badRemoval = FALSE
    /\ lostLocal = FALSE

(* --- Helpers ------------------------------------------------------------ *)

B(r) == base[Owner(r)]
SetBase(r, value) ==
    /\ base' = [base EXCEPT ![Owner(r)] = value]
    /\ hasBase' = [hasBase EXCEPT ![Owner(r)] = TRUE]

(* The sync mutex: taken at the start of an operation, released at its end. *)
MutexFree(r) == ~SharedBase \/ mutex[Host[r]] = NoRun
TakeMutex(r) == mutex' = IF SharedBase THEN [mutex EXCEPT ![Host[r]] = r] ELSE mutex
FreeMutex(r) == mutex' = IF SharedBase THEN [mutex EXCEPT ![Host[r]] = NoRun] ELSE mutex

Goto(r, p) == pc' = [pc EXCEPT ![r] = p]

(* Sync.\_assume\_base: no sync happened, so the file as it is stands for  *)
(* the last one.                                                           *)
AssumeBase(r) ==
    IF hasBase[Owner(r)] THEN UNCHANGED <<base, hasBase>>
    ELSE SetBase(r, file[Host[r]])

CanFail == faults < MaxFaults
Fail == faults' = faults + 1

(* Writing the vault: replaced values are recorded. *)
WriteVault(value) ==
    /\ vault' = value
    /\ replaced' = [c \in Creds |-> IF value[c] # vault[c] /\ vault[c] # 0
                                    THEN replaced[c] \cup {vault[c]} ELSE replaced[c]]

History == <<newest, loggedOut>>

(* --- Step 1: the pull (Syncer.pull, merge_pulled) ----------------------- *)

(* The session lock is shared by every run of the file on the machine, and *)
(* waits while the last one removes the file.                              *)
Start(r) ==
    /\ pc[r] = "start"
    /\ excl[Host[r]] = NoRun
    /\ sessions' = [sessions EXCEPT ![Host[r]] = @ \cup {r}]
    /\ Goto(r, "pullBegin")
    /\ UNCHANGED <<vault, file, base, hasBase, mutex, excl, prog, snap, merged, fileNow,
                   cur, attempts, synced, clock, faults, replaced, gaveUp, badRemoval,
                   lostLocal, History>>

Begin(r, from, to) ==
    /\ pc[r] = from
    /\ MutexFree(r)
    /\ TakeMutex(r)
    /\ attempts' = [attempts EXCEPT ![r] = 0]
    /\ Goto(r, to)
    /\ UNCHANGED <<vault, file, base, hasBase, sessions, excl, prog, snap, merged, fileNow,
                   cur, synced, clock, faults, replaced, gaveUp, badRemoval, lostLocal,
                   History>>

(* Reading the vault is atomic: one HTTPS request. *)
PullRead(r) ==
    /\ pc[r] = "pullRead"
    /\ \/ /\ snap' = [snap EXCEPT ![r] = vault]
          /\ Goto(r, "pullMerge")
          /\ UNCHANGED <<base, hasBase, mutex, prog, faults>>
       \/ /\ CanFail /\ Fail            \* unreadable: the command starts with the file as it is
          /\ AssumeBase(r)
          /\ FreeMutex(r)
          /\ prog' = [prog EXCEPT ![r] = TRUE]
          /\ Goto(r, "running")
          /\ UNCHANGED snap
    /\ UNCHANGED <<vault, file, sessions, excl, merged, fileNow, cur, attempts, synced,
                   clock, replaced, gaveUp, badRemoval, lostLocal, History>>

(* Under the tool lock, which the program also takes: atomic for the file. *)
PullMerge(r) ==
    LET m == Host[r]
        b == IF hasBase[Owner(r)] THEN B(r) ELSE file[m]   \* none: the vault wins
        new == Merge(file[m], snap[r], b)
    IN
    /\ pc[r] = "pullMerge"
    /\ file' = [file EXCEPT ![m] = new]
    /\ SetBase(r, IF Rebase
                  THEN RebaseTo(IF hasBase[Owner(r)] THEN B(r) ELSE Zero, new, snap[r])
                  ELSE new)
    /\ lostLocal' = (lostLocal \/ LosesLocal(file[m], new))
    /\ FreeMutex(r)
    /\ prog' = [prog EXCEPT ![r] = TRUE]
    /\ snap' = [snap EXCEPT ![r] = Zero]
    /\ Goto(r, "running")
    /\ UNCHANGED <<vault, sessions, excl, merged, fileNow, cur, attempts, synced,
                   clock, faults, replaced, gaveUp, badRemoval, History>>

(* --- The programs, and people editing the vault ------------------------- *)

Running(m) == \E r \in Runs : Host[r] = m /\ prog[r]

ProgramWrite(m, c) ==
    /\ Running(m)
    /\ clock < MaxValue
    /\ clock' = clock + 1
    /\ file' = [file EXCEPT ![m][c] = clock + 1]
    /\ newest' = IF c \in Timed THEN [newest EXCEPT ![c] = clock + 1] ELSE newest
    /\ UNCHANGED <<vault, base, hasBase, mutex, sessions, excl, pc, prog, snap, merged,
                   fileNow, cur, attempts, synced, faults, replaced, loggedOut, gaveUp,
                   badRemoval, lostLocal>>

Logout(m, c) ==
    /\ AllowLogout
    /\ Running(m)
    /\ file[m][c] # 0
    /\ file' = [file EXCEPT ![m][c] = 0]
    /\ loggedOut' = TRUE
    /\ UNCHANGED <<vault, base, hasBase, mutex, sessions, excl, pc, prog, snap, merged,
                   fileNow, cur, attempts, synced, clock, faults, newest, replaced, gaveUp,
                   badRemoval, lostLocal>>

HandEdit(c) ==
    /\ AllowHandEdit
    /\ clock < MaxValue
    /\ clock' = clock + 1
    /\ WriteVault([vault EXCEPT ![c] = clock + 1])
    /\ UNCHANGED <<file, base, hasBase, mutex, sessions, excl, pc, prog, snap, merged,
                   fileNow, cur, attempts, synced, faults, gaveUp, badRemoval, lostLocal,
                   History>>

(* --- Step 2: syncing while the command runs (Syncer.step) --------------- *)

SyncRead(r) ==
    /\ pc[r] = "syncRead"
    /\ \/ /\ snap' = [snap EXCEPT ![r] = vault]
          /\ Goto(r, "syncMerge")
          /\ UNCHANGED <<mutex, faults>>
       \/ /\ CanFail /\ Fail
          /\ FreeMutex(r)
          /\ Goto(r, "running")
          /\ UNCHANGED snap
    /\ UNCHANGED <<vault, file, base, hasBase, sessions, excl, prog, merged, fileNow, cur,
                   attempts, synced, clock, replaced, gaveUp, badRemoval, lostLocal, History>>

(* Syncer.reconcile with write_file: under the tool lock. *)
SyncMerge(r) ==
    LET m == Host[r]
        M == Merge(file[m], snap[r], B(r))
        K == Kept(file[m], M, B(r))
    IN
    /\ pc[r] = "syncMerge"
    /\ file' = [file EXCEPT ![m] = K]
    /\ merged' = [merged EXCEPT ![r] = M]
    /\ fileNow' = [fileNow EXCEPT ![r] = K]
    /\ lostLocal' = (lostLocal \/ LosesLocal(file[m], K))
    /\ Goto(r, "syncWrite")
    /\ UNCHANGED <<vault, base, hasBase, mutex, sessions, excl, prog, snap, cur, attempts,
                   synced, clock, faults, replaced, gaveUp, badRemoval, History>>

(* Syncer.publish. The compare-and-set is atomic in the vault (Doppler     *)
(* applies a change only if originalValue matches).                        *)
NoWrite(r) == merged[r] = snap[r]

BaseAfterWrite(r) == IF Rebase THEN RebaseTo(B(r), fileNow[r], merged[r]) ELSE merged[r]
BaseAfterNoWrite(r) == IF Rebase THEN RebaseTo(B(r), fileNow[r], snap[r]) ELSE merged[r]
BaseAfterFailure(r) == IF Rebase THEN RebaseTo(B(r), fileNow[r], snap[r]) ELSE B(r)

(* The outcome of writing run r's merge: "none" (nothing to write), "ok",  *)
(* "conflict" or "fault".                                                  *)
Publish(r, outcome) ==
    /\ \/ /\ outcome = "none" /\ NoWrite(r)
          /\ SetBase(r, BaseAfterNoWrite(r))
          /\ UNCHANGED <<vault, replaced, faults>>
       \/ /\ outcome = "ok" /\ ~NoWrite(r)
          /\ (~Guarded \/ vault = snap[r])
          /\ WriteVault(merged[r])
          /\ SetBase(r, BaseAfterWrite(r))
          /\ UNCHANGED faults
       \/ /\ outcome = "conflict" /\ ~NoWrite(r)
          /\ Guarded /\ vault # snap[r]
          /\ SetBase(r, BaseAfterFailure(r))
          /\ UNCHANGED <<vault, replaced, faults>>
       \/ /\ outcome = "fault" /\ ~NoWrite(r)
          /\ CanFail /\ Fail
          /\ SetBase(r, BaseAfterFailure(r))
          /\ UNCHANGED <<vault, replaced>>

Retry(r) == attempts' = [attempts EXCEPT ![r] = @ + 1]
Done(r) == attempts' = [attempts EXCEPT ![r] = 0]

(* What a run read and merged is dead once it is written or given up: TLC  *)
(* counts states that differ only there as one.                            *)
ClearScratch(r) ==
    /\ snap' = [snap EXCEPT ![r] = Zero]
    /\ merged' = [merged EXCEPT ![r] = Zero]
    /\ fileNow' = [fileNow EXCEPT ![r] = Zero]

SyncWrite(r) ==
    /\ pc[r] = "syncWrite"
    /\ \E outcome \in {"none", "ok", "conflict", "fault"} :
        /\ Publish(r, outcome)
        /\ IF outcome = "conflict" /\ attempts[r] + 1 < MaxAttempts
           THEN Goto(r, "syncRead") /\ Retry(r) /\ UNCHANGED mutex
           ELSE Goto(r, "running") /\ Done(r) /\ FreeMutex(r)
    /\ ClearScratch(r)
    /\ UNCHANGED <<file, sessions, excl, prog, cur, synced, clock,
                   gaveUp, badRemoval, lostLocal, History>>

(* --- Steps 3 and 4: write-back and removal (Syncer.finish) -------------- *)

(* The command exits; the background sync has finished its step (joined). *)
Exit(r) ==
    /\ pc[r] = "running"
    /\ prog' = [prog EXCEPT ![r] = FALSE]
    /\ Goto(r, "exitBegin")
    /\ UNCHANGED <<vault, file, base, hasBase, mutex, sessions, excl, snap, merged, fileNow,
                   cur, attempts, synced, clock, faults, replaced, gaveUp, badRemoval,
                   lostLocal, History>>

ExitRead(r) ==
    /\ pc[r] = "exitRead"
    /\ \/ /\ snap' = [snap EXCEPT ![r] = vault]
          /\ Goto(r, "exitMerge")
          /\ UNCHANGED <<mutex, faults, gaveUp>>
       \/ /\ CanFail /\ Fail            \* newer credentials stay in the file
          /\ gaveUp' = TRUE
          /\ FreeMutex(r)
          /\ Goto(r, "release")
          /\ UNCHANGED snap
    /\ UNCHANGED <<vault, file, base, hasBase, sessions, excl, prog, merged, fileNow, cur,
                   attempts, synced, clock, replaced, badRemoval, lostLocal, History>>

(* Syncer.reconcile without write_file: the file is only read. *)
ExitMerge(r) ==
    LET m == Host[r] IN
    /\ pc[r] = "exitMerge"
    /\ cur' = [cur EXCEPT ![r] = file[m]]
    /\ merged' = [merged EXCEPT ![r] = Merge(file[m], snap[r], B(r))]
    /\ fileNow' = [fileNow EXCEPT ![r] = file[m]]
    /\ Goto(r, "exitWrite")
    /\ UNCHANGED <<vault, file, base, hasBase, mutex, sessions, excl, prog, snap, attempts,
                   synced, clock, faults, replaced, gaveUp, badRemoval, lostLocal, History>>

ExitWrite(r) ==
    /\ pc[r] = "exitWrite"
    /\ \E outcome \in {"none", "ok", "conflict", "fault"} :
        /\ Publish(r, outcome)
        /\ CASE outcome \in {"none", "ok"} ->
                    synced' = [synced EXCEPT ![r] = TRUE] /\ Goto(r, "remove") /\ Done(r)
                    /\ UNCHANGED <<mutex, gaveUp>>
             [] outcome = "conflict" /\ attempts[r] + 1 < MaxAttempts ->
                    Goto(r, "exitRead") /\ Retry(r) /\ UNCHANGED <<mutex, gaveUp, synced>>
             [] OTHER ->
                    gaveUp' = TRUE /\ FreeMutex(r) /\ Goto(r, "release") /\ Done(r)
                    /\ UNCHANGED synced
    /\ ClearScratch(r)
    /\ UNCHANGED <<file, sessions, excl, prog, cur, clock,
                   badRemoval, lostLocal, History>>

(* Syncer.remove_if_last. Linux drops a shared flock before it tries the   *)
(* exclusive one, so a run that is refused no longer holds either.         *)
Remove(r) ==
    LET m == Host[r]
        last == sessions[m] = {r}
        gone == Ephemeral /\ last /\ file[m] = cur[r]
    IN
    /\ pc[r] = "remove"
    /\ excl' = IF Ephemeral /\ last THEN [excl EXCEPT ![m] = r] ELSE excl
    /\ sessions' = IF Ephemeral THEN [sessions EXCEPT ![m] = @ \ {r}] ELSE sessions
    /\ file' = IF gone THEN [file EXCEPT ![m] = Zero] ELSE file
    /\ IF gone
       THEN /\ hasBase' = [hasBase EXCEPT ![Owner(r)] = FALSE]
            /\ base' = [base EXCEPT ![Owner(r)] = Zero]
       ELSE UNCHANGED <<base, hasBase>>
    /\ badRemoval' = (badRemoval \/ (gone /\ \E c \in Creds :
                        \/ c \in Timed /\ file[m][c] > vault[c]
                        \/ c \in Untimed /\ file[m][c] # 0 /\ file[m][c] \notin InVault(c)))
    /\ FreeMutex(r)
    /\ Goto(r, "release")
    /\ cur' = [cur EXCEPT ![r] = Zero]
    /\ synced' = [synced EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<vault, prog, snap, merged, fileNow, attempts, clock, faults,
                   replaced, gaveUp, lostLocal, History>>

Release(r) ==
    LET m == Host[r] IN
    /\ pc[r] = "release"
    /\ sessions' = [sessions EXCEPT ![m] = @ \ {r}]
    /\ excl' = IF excl[m] = r THEN [excl EXCEPT ![m] = NoRun] ELSE excl
    \* Forget the run's own copies, so finished runs do not multiply states.
    /\ snap' = [snap EXCEPT ![r] = Zero]
    /\ merged' = [merged EXCEPT ![r] = Zero]
    /\ fileNow' = [fileNow EXCEPT ![r] = Zero]
    /\ cur' = [cur EXCEPT ![r] = Zero]
    /\ attempts' = [attempts EXCEPT ![r] = 0]
    /\ synced' = [synced EXCEPT ![r] = FALSE]
    /\ Goto(r, "done")
    /\ UNCHANGED <<vault, file, base, hasBase, mutex, prog, clock, faults,
                   replaced, gaveUp, badRemoval, lostLocal, History>>

(* --- The system --------------------------------------------------------- *)

Next ==
    \/ \E r \in Runs :
        \/ Start(r)
        \/ Begin(r, "pullBegin", "pullRead") \/ PullRead(r) \/ PullMerge(r)
        \/ Begin(r, "running", "syncRead") \/ SyncRead(r) \/ SyncMerge(r) \/ SyncWrite(r)
        \/ Exit(r)
        \/ Begin(r, "exitBegin", "exitRead") \/ ExitRead(r) \/ ExitMerge(r) \/ ExitWrite(r)
        \/ Remove(r) \/ Release(r)
    \/ \E m \in Machines, c \in Creds : ProgramWrite(m, c) \/ Logout(m, c)
    \/ \E c \in Untimed : HandEdit(c)

Spec == Init /\ [][Next]_vars

(* --- Properties ---------------------------------------------------------- *)

TypeOK ==
    /\ vault \in [Creds -> 0..MaxValue]
    /\ file \in [Machines -> [Creds -> 0..MaxValue]]
    /\ pc \in [Runs -> Phases]
    /\ mutex \in [Machines -> Runs \cup {NoRun}]
    /\ faults \in 0..MaxFaults

(* No refresh is lost: the newest value of each credential with a time key *)
(* is in the vault or in a machine's file. (A logout loses a value on      *)
(* purpose, so this is checked without logouts.)                           *)
NoLostRefresh ==
    loggedOut \/ \A c \in Timed :
        \/ newest[c] <= vault[c]
        \/ \E m \in Machines : newest[c] <= file[m][c]

(* A value the vault replaced never comes back to it. *)
NoResurrection == \A c \in Creds : vault[c] \notin replaced[c]

(* A file is removed only when the vault holds all of it. *)
SafeRemoval == ~badRemoval

(* A sync never replaces, in a file, a value the vault never had: what a   *)
(* program changed reaches the vault or stays.                             *)
NoLostLocalChange == ~lostLocal

(* Once every run has ended without giving up, the vault holds the newest  *)
(* value of each credential with a time key.                               *)
Converged ==
    (\A r \in Runs : pc[r] = "done") /\ ~gaveUp /\ ~loggedOut =>
        \A c \in Timed : vault[c] = newest[c]

(* At most one run of a machine is inside a sync operation. *)
OneSyncPerMachine ==
    SharedBase => \A m \in Machines :
        Cardinality({r \in Runs : Host[r] = m /\ pc[r] \in
            {"pullRead", "pullMerge", "syncRead", "syncMerge", "syncWrite",
             "exitRead", "exitMerge", "exitWrite", "remove"}}) <= 1
=============================================================================
