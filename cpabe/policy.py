"""
Attribute encoding and the RequestGen / PolicyGen / DataGen pipeline.

This module is the concrete counterpart of the deterministic pipeline that
appears in the report's Tamarin abstraction::

    S  --RequestGen-->  req  --PolicyGen-->  AP        (access policy)
                             --DataGen--->   data      (the medicine)

and of Section 3.1's description of a prescription credential:

    "A prescription credential carries attributes describing the dispensable
     medicine or therapeutic class (e.g. drug:antiretroviral), validity
     timestamps issued_at, not_before, expires_at used for time-based
     revocation (F1) ... The Pharmacy's dispensing policy is then a Boolean
     combination such as  drug:X AND (not_before <= now) AND (now <= expires_at)."

Range predicates over timestamps are, in ETSI TS 103 964, compiled into the
LSSS access structure.  For a self-contained proof of concept we render the
*same effect* by expanding the validity interval into a set of coarse-grained
"time-slot" attributes ``valid:<YYYY-MM>`` embedded in the credential, and by
having the pharmacy require the slot attribute of the *current* period.  An
expired credential simply lacks the current slot attribute, so the CP-ABE
decryption fails and no medicine is dispensed -- exactly the behaviour F1
prescribes, and the enforcement stays *inside* the ABE layer so the pharmacy
still learns only the single "policy satisfied" bit (S2).
"""
# TODO: Refactor policyies to handle more complex predicates on attributes, for example date_x<=date_y


from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Dict, FrozenSet, List, Set


# --------------------------------------------------------------------------- #
# Time-slot helpers                                                            #
# --------------------------------------------------------------------------- #
def month_slot(d: date) -> str:
    """Coarse validity slot for a date, e.g. date(2026, 6, 3) -> 'valid:2026-06'."""
    return f"valid:{d.year:04d}-{d.month:02d}"


def _iter_month_slots(not_before: date, expires_at: date) -> List[str]:
    """Every monthly slot in the inclusive interval [not_before, expires_at]."""
    slots: List[str] = []
    y, m = not_before.year, not_before.month
    while (y, m) <= (expires_at.year, expires_at.month):
        slots.append(f"valid:{y:04d}-{m:02d}")
        m += 1
        if m == 13:
            m, y = 1, y + 1
    return slots


# --------------------------------------------------------------------------- #
# Prescription content (what the Physician authors)                            #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Prescription:
    """The clinical content of a prescription.

    Note that this object is *never* handed to the pharmacy.  It is turned
    into an attribute set that lives inside the patient's secret key.
    """
    presc_id: str          # unique prescription identifier
    drug_code: str         # e.g. "antiretroviral"
    not_before: date
    expires_at: date

    def attributes(self) -> FrozenSet[str]:
        """The attribute set ``S`` embedded in the patient's ABE secret key."""
        attrs: Set[str] = {
            "role:patient",
            f"drug:{self.drug_code}",
            f"presc:{self.presc_id}",
        }
        attrs.update(_iter_month_slots(self.not_before, self.expires_at))
        return frozenset(attrs)


# --------------------------------------------------------------------------- #
# The request the patient shows at the counter                                 #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Request:
    """``req = RequestGen(S)``.

    Only the *non-identifying* information required to dispense is revealed:
    which medicine is wanted (the patient is, after all, asking for it) and
    the current time period (public knowledge).  The prescription id and the
    exact validity window stay secret inside the key -- the pharmacy never
    sees them, honouring S2.
    """
    drug_code: str
    period: str            # a 'valid:YYYY-MM' slot for "now"


#NOTE: HERE MAYBE WE SHOULD CHANGE THIS TO TAKE A NUMBER IN INPUT FOR THE CHOSEN DRUG FROM THE ATTRIBUTE SET
def RequestGen(attributes: FrozenSet[str], now: date) -> Request:
    """Derive the presentation request from the credential attributes and the
    current date.  In a real deployment the drug is chosen by the patient at
    the counter; here we read it back from the first element of ``S`` for convenience."""
    drug = next((a.split(":", 1)[1] for a in attributes if a.startswith("drug:")), None)
    if drug is None:
        raise ValueError("credential carries no drug attribute")
    return Request(drug_code=drug, period=month_slot(now))


# --------------------------------------------------------------------------- #
# Access-policy AST  (the LSSS access structure, abstractly)                    #
# --------------------------------------------------------------------------- #
class Policy:
    """Base class for a monotone Boolean access policy over string attributes."""

    def attributes(self) -> Set[str]:
        raise NotImplementedError

    def satisfied_by(self, attrs: FrozenSet[str]) -> bool:
        raise NotImplementedError

    def canonical(self) -> str:
        """Deterministic string form -- used as the label bound into the
        challenge (so the policy is authenticated by the FO hash) and to
        render an openABE policy expression."""
        raise NotImplementedError


@dataclass(frozen=True)
class Leaf(Policy):
    attr: str

    def attributes(self) -> Set[str]:
        return {self.attr}

    def satisfied_by(self, attrs: FrozenSet[str]) -> bool:
        return self.attr in attrs

    def canonical(self) -> str:
        return self.attr


@dataclass(frozen=True)
class And(Policy):
    children: tuple

    def attributes(self) -> Set[str]:
        s: Set[str] = set()
        for c in self.children:
            s |= c.attributes()
        return s

    def satisfied_by(self, attrs: FrozenSet[str]) -> bool:
        return all(c.satisfied_by(attrs) for c in self.children)

    def canonical(self) -> str:
        return "(" + " and ".join(sorted(c.canonical() for c in self.children)) + ")"


@dataclass(frozen=True)
class Or(Policy):
    children: tuple

    def attributes(self) -> Set[str]:
        s: Set[str] = set()
        for c in self.children:
            s |= c.attributes()
        return s

    def satisfied_by(self, attrs: FrozenSet[str]) -> bool:
        return any(c.satisfied_by(attrs) for c in self.children)

    def canonical(self) -> str:
        return "(" + " or ".join(sorted(c.canonical() for c in self.children)) + ")"


@dataclass(frozen=True)
class Threshold(Policy):
    k: int
    children: tuple

    def attributes(self) -> Set[str]:
        s: Set[str] = set()
        for c in self.children:
            s |= c.attributes()
        return s

    def satisfied_by(self, attrs: FrozenSet[str]) -> bool:
        return sum(1 for c in self.children if c.satisfied_by(attrs)) >= self.k

    def canonical(self) -> str:
        inner = ", ".join(sorted(c.canonical() for c in self.children))
        return f"{self.k}of({inner})"


def PolicyGen(req: Request) -> Policy:
    """``AP = PolicyGen(req)``.

    The dispensing rule the pharmacy enforces:  the credential must be for
    the requested drug *and* still be valid in the current period.  This is
    the concrete instance of

        drug:X AND (not_before <= now) AND (now <= expires_at)

    with the time range rendered as the current monthly slot.
    """
    return And((Leaf(f"drug:{req.drug_code}"), Leaf(req.period)))


# --------------------------------------------------------------------------- #
# The medicine associated to a request                                         #
# --------------------------------------------------------------------------- #
# A tiny "formulary" mapping drug codes to a human-readable dispensed item.
_FORMULARY: Dict[str, str] = {
    "antiretroviral": "Tenofovir/Emtricitabine 200/245 mg - 30 tablets",
    "insulin": "Insulin glargine 100 U/mL - 5 pens",
    "levothyroxine": "Levothyroxine 100 mcg - 90 tablets",
    "salbutamol": "Salbutamol inhaler 100 mcg - 200 doses",
    "statin": "Atorvastatin 20 mg - 30 tablets",
}


def DataGen(req: Request) -> str:
    """``data = DataGen(req)`` -- the medicine that will be handed over on a
    successful handshake."""
    return _FORMULARY.get(req.drug_code, f"[unlisted medicine for {req.drug_code}]")


def formulary_drugs() -> List[str]:
    return list(_FORMULARY.keys())
