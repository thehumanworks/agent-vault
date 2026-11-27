------------------------------ MODULE LockSteal ------------------------------
(***************************************************************************)
(* The tool lock as a lock directory (proper-lockfile's, which pi takes on *)
(* auth.json), and the removal of one left behind by a process that died   *)
(* (src/agent_vault/localfile.py, ToolLock).                               *)
(*                                                                         *)
(* mkdir and rmdir are atomic. "Stale" (untouched for 10 seconds) is       *)
(* modelled as "made by a process that has died": a live holder touches    *)
(* its directory every 5 seconds (proper-lockfile) or holds it for         *)
(* milliseconds (agent-vault), and is never suspended for 10 seconds while *)
(* it holds it. That is assumption L1 in spec/README.md.                   *)
(*                                                                         *)
(* UseMutex: agent-vault checks and removes a stale directory under its    *)
(* own flock (the steal mutex). FALSE: doppler-nix checks, then removes,   *)
(* with nothing in between.                                                *)
(* ToolSteals: the tool removes stale directories too, without the steal   *)
(* mutex (proper-lockfile does). agent-vault cannot make it take the       *)
(* mutex; assumption L2 is that the tool and agent-vault do not both find  *)
(* the same stale directory at once.                                       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Avlt, Tool, UseMutex, ToolSteals, MaxCrashes

Procs == Avlt \cup {Tool}
None == "none"

VARIABLES
    exists,     \* the lock directory exists
    owner,      \* the process whose mkdir made it
    holders,    \* live processes that believe they hold the lock
    pc,
    mutex,      \* the steal mutex (an flock: released when its holder dies)
    dead,       \* processes that have died
    crashes

vars == <<exists, owner, holders, pc, mutex, dead, crashes>>

Stale == exists /\ owner \in dead
Steals(p) == p \in Avlt \/ ToolSteals
Mutexed(p) == UseMutex /\ p \in Avlt

Init ==
    /\ exists = FALSE
    /\ owner = None
    /\ holders = {}
    /\ pc = [p \in Procs |-> "try"]
    /\ mutex = None
    /\ dead = {}
    /\ crashes = 0

Goto(p, s) == pc' = [pc EXCEPT ![p] = s]

(* mkdir: success makes the process a holder. *)
Try(p) ==
    /\ pc[p] = "try"
    /\ IF ~exists
       THEN /\ exists' = TRUE /\ owner' = p /\ holders' = holders \cup {p}
            /\ Goto(p, "held")
            /\ UNCHANGED mutex
       ELSE /\ Goto(p, IF ~Steals(p) THEN "try" ELSE IF Mutexed(p) THEN "mutex" ELSE "check")
            /\ UNCHANGED <<exists, owner, holders, mutex>>
    /\ UNCHANGED <<dead, crashes>>

TakeMutex(p) ==
    /\ pc[p] = "mutex"
    /\ mutex = None
    /\ mutex' = p
    /\ Goto(p, "check")
    /\ UNCHANGED <<exists, owner, holders, dead, crashes>>

FreeMutex(p) == mutex' = IF mutex = p THEN None ELSE mutex

(* stat: is the directory stale? *)
Check(p) ==
    /\ pc[p] = "check"
    /\ IF Stale
       THEN Goto(p, "rmdir") /\ UNCHANGED mutex
       ELSE Goto(p, "try") /\ FreeMutex(p)
    /\ UNCHANGED <<exists, owner, holders, dead, crashes>>

(* rmdir by path: it removes whatever directory is there now. *)
Rmdir(p) ==
    /\ pc[p] = "rmdir"
    /\ exists' = FALSE
    /\ owner' = None
    /\ FreeMutex(p)
    /\ Goto(p, "try")
    /\ UNCHANGED <<holders, dead, crashes>>

Release(p) ==
    /\ pc[p] = "held"
    /\ holders' = holders \ {p}
    /\ exists' = FALSE
    /\ owner' = None
    /\ Goto(p, "try")
    /\ UNCHANGED <<mutex, dead, crashes>>

(* A process dies anywhere; the kernel releases its flock, not its directory. *)
Crash(p) ==
    /\ p \notin dead
    /\ crashes < MaxCrashes
    /\ dead' = dead \cup {p}
    /\ crashes' = crashes + 1
    /\ holders' = holders \ {p}
    /\ FreeMutex(p)
    /\ Goto(p, "dead")
    /\ UNCHANGED <<exists, owner>>

Next == \E p \in Procs \ dead :
    Try(p) \/ TakeMutex(p) \/ Check(p) \/ Rmdir(p) \/ Release(p) \/ Crash(p)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ holders \subseteq Procs
    /\ mutex \in Procs \cup {None}
    /\ owner \in Procs \cup {None}

(* No two live processes hold the lock at once. *)
MutualExclusion == Cardinality(holders) <= 1
=============================================================================
