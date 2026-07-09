"""
Attribute encoding and the RequestGen / PolicyGen / DataGen pipeline.

    S  --RequestGen-->  req  --PolicyGen-->  AP        (access policy)
                             --DataGen--->   data      (the medicine)

--------------------------------------------------
OpenABE's policy language supports And, or, **numerical attributes** and integer **comparisons** (``<``, ``<=``,
``=``, ``>=``, ``>``), which it compiles into a compact bit-encoded LSSS. 
We exploit this directly:

    * the credential carries the validity window as two numerical attributes
      ``not_before = <days>`` and ``expires_at = <days>`` (days since 2000-01-01,
      a small, dense, monotonic integer -- ~14 bits);
    * the pharmacy's dispensing policy compares them against the current day:

          drug_<X>  and  not_before <= <today>  and  expires_at >= <today>

        An expired (or not-yet-valid) credential fails the comparison, so CP-ABE
        decryption fails and nothing is dispensed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Dict, FrozenSet, List, Tuple, Optional, Literal

# Epoch for the compact integer date encoding.  Days since this date are small,
# positive and monotonic, which keeps the numerical comparisons cheap.
_EPOCH = date(2000, 1, 1)


def date_to_int(d: date) -> int:
    """Encode a date as a small non-negative integer (days since 2000-01-01)."""
    return (d - _EPOCH).days

def nullifier_to_int(nullifier: bytes) -> int:
    """Encode nulllifier as int"""
    return int.from_bytes(nullifier[:4], 'big')


def _san(name: str) -> str:
    """Sanitise a categorical attribute name to an OpenABE-safe token."""
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


# --------------------------------------------------------------------------- #
# Generic OpenABE access-policy AST                                            #
# --------------------------------------------------------------------------- #
class Policy:
    """A generic OpenABE policy node.

    ``render()`` returns an OpenABE policy expression; ``canonical()`` returns a
    deterministic string used both as the OpenABE policy and as the label bound
    into the challenge by the FO transform (so AP is authenticated by the hash).
    """

    def render(self) -> str:
        raise NotImplementedError

    def canonical(self) -> str:
        return self.render()


@dataclass(frozen=True)
class Attr(Policy):
    """A categorical attribute, e.g. ``drug_antiretroviral``."""
    name: str

    def render(self) -> str:
        return _san(self.name)


@dataclass(frozen=True)
class Num(Policy):
    """A numerical comparison, e.g. ``expires_at >= 9663``.

    ``op`` is one of ``<``, ``<=``, ``>=``, ``>``.
    """
    attr: str
    op: Literal["<", "<=", ">=", ">"]
    value: int

    def render(self) -> str:
        return f"{_san(self.attr)} {self.op} {self.value}"


@dataclass(frozen=True)
class And(Policy):
    children: Tuple[Policy, ...]

    def render(self) -> str:
        return "(" + " and ".join(c.render() for c in self.children) + ")"


@dataclass(frozen=True)
class Or(Policy):
    children: Tuple[Policy, ...]

    def render(self) -> str:
        return "(" + " or ".join(c.render() for c in self.children) + ")"


# --------------------------------------------------------------------------- #
# Prescription content (what the Physician authors)                            #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Prescription:
    """The clinical content of a prescription.

    Never handed to the pharmacy: it is turned into the attribute set that
    lives inside the patient's ABE secret key.
    """
    presc_id: str
    drug_code: str
    not_before: date
    expires_at: date
    uses: Optional[int] = None  # Uses is None only under assumption A5: Infinite uses


    def key_attributes(self) -> FrozenSet[str]:
        """The attribute set ``S`` embedded in the patient's ABE secret key, in
        OpenABE's native form: two categorical attributes plus the validity
        window as two numerical (date) attributes."""
        return frozenset({
            _san("role_patient"),
            _san(f"drug_{self.drug_code}"),
            f"not_before = {date_to_int(self.not_before)}",
            f"expires_at = {date_to_int(self.expires_at)}",
            f"nullifier = 1",  # empry nullifier always added to both S and policy
        })


# --------------------------------------------------------------------------- #
# The request the patient shows at the counter                                 #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Request:
    """``req = RequestGen(S, now)`` -- only non-identifying information: the
    medicine wanted and the current day.  The prescription id and the exact
    validity window stay secret inside the key."""
    drug_code: str
    today: int                # current day, as days-since-2000
    now: date
    nullifier: bytes = b"\1"  # empty nullifier b"\1" when no nullifier is expected
                              # The natural choice would be b"\0" but OpenABE can't handle
                              # 0 in comparisons


def _drug_from_attributes(attributes: FrozenSet[str]) -> str:
    """At the moment this takes the first drug in the attribute set ``S``
    
    NOTE:HERE MAYBE WE SHOULD CHANGE THIS TO TAKE A NUMBER IN INPUT FOR THE CHOSEN DRUG FROM THE ATTRIBUTE SET, AT THE MOMENT FOR SIMPLICITY THIS ONLY HANDLES THE FIRST DRUG
    """
    prefix = _san("drug_")
    for a in attributes:
        if a.startswith(prefix):
            return a[len(prefix):]
    raise ValueError("credential carries no drug attribute")


def RequestGen(attributes: FrozenSet[str], nullifier: bytes = b"\1", now: date = datetime.now().date()) -> Request:
    """Derive the presentation request from the credential attributes and the
    current date (the drug is what the patient asks for at the counter)."""
    return Request(drug_code=_drug_from_attributes(attributes),
                   today=date_to_int(now), now=now, nullifier=nullifier)


# NOTE: This policyGen function is an example but it could be more complex asking for the number of milligrams of a given medicine or the age of the patient,for simplicity we considered only one drug, no dosage, a validity time for the prescription
def PolicyGen(req: Request, max_uses: int = 10) -> Policy:
    """``AP = PolicyGen(req)`` -- the dispensing rule::

        drug_<X>  and  not_before <= today  and  expires_at >= today

    i.e. the report's  drug:X AND (not_before <= now) AND (now <= expires_at),
    with the two time bounds expressed as OpenABE numerical comparisons.
    """

    nullifier_nodes = [And(
        (Num("nullifier", ">=", 1),
         Num("nullifier", "<=", 1))
    )]

    nullifier_nodes.extend([And(
        (Num(f"nullifier_{i}", ">=", nullifier_to_int(req.nullifier)),
         Num(f"nullifier_{i}", "<=", nullifier_to_int(req.nullifier)))
        ) for i in range(max_uses)])


    return And((
        Attr(f"drug_{req.drug_code}"),
        Num("not_before", "<=", req.today),
        Num("expires_at", ">=", req.today),
        Or(tuple(nullifier_nodes))
        
        #NOTE: Since it is not possible to express nullifier equality
        #      directly in OpenABE we express as double inequality

    ))


# --------------------------------------------------------------------------- #
# The medicine associated to a request                                         #
# --------------------------------------------------------------------------- #

# Example formulary
_FORMULARY: Dict[str, str] = {
    "antiretroviral": "Tenofovir/Emtricitabine 200/245 mg - 30 tablets",
    "insulin": "Insulin glargine 100 U/mL - 5 pens",
    "levothyroxine": "Levothyroxine 100 mcg - 90 tablets",
    "salbutamol": "Salbutamol inhaler 100 mcg - 200 doses",
    "statin": "Atorvastatin 20 mg - 30 tablets",
}


def DataGen(req: Request) -> str:
    """``data = DataGen(req)`` -- the medicine handed over on success."""
    return _FORMULARY.get(req.drug_code, f"[unlisted medicine for {req.drug_code}]")


def formulary_drugs() -> List[str]:
    return list(_FORMULARY.keys())
