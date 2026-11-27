---------------------------- MODULE MCAgentVaultSync ----------------------------
(* The model TLC checks: two machines, two runs on the first and one on the   *)
(* second. The two runs on m1 are interchangeable, so TLC checks one of each  *)
(* pair of states that differ only by swapping them.                          *)
EXTENDS AgentVaultSync, TLC

CONSTANTS m1, m2, r1, r2, r3

MCHost == (r1 :> m1) @@ (r2 :> m1) @@ (r3 :> m2)
MCSymmetry == Permutations({r1, r2})
=================================================================================
