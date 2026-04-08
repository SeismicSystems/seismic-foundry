//! Seismic-specific ssolc warning codes.
//!
//! Kept in a separate file to minimize the diff against upstream `error.rs`.

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Named variants for all seismic/ssolc warning codes (>= 10000).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SeismicError {
    // -- Arithmetic / branching warnings (10301-10311) --
    /// Shielded addition leaks if operands are public
    ShieldedArithAdd,
    /// Shielded subtraction leaks if operands are public
    ShieldedArithSub,
    /// Shielded multiplication leaks if operands are public
    ShieldedArithMul,
    /// Shielded division leaks if operands are public
    ShieldedArithDiv,
    /// Shielded modulo leaks if operands are public
    ShieldedArithMod,
    /// Shielded exponentiation leaks if operands are public
    ShieldedArithExp,
    /// Shielded shift-left leaks if operands are public
    ShieldedArithShl,
    /// Shielded shift-right leaks if operands are public
    ShieldedArithShr,
    /// Shielded value used as if-condition (leaks via branch)
    ShieldedCondIf,
    /// Shielded value used as ternary condition (leaks via branch)
    ShieldedCondTernary,
    /// Shielded value used as while/for condition (leaks via branch)
    ShieldedCondLoop,

    // -- Constructor param warning (10103) --
    /// Constructor has shielded parameter types (CREATE doesn't encrypt calldata)
    ShieldedConstructorParam,

    // -- Literal in `new(...)` expression args (10401, 10404, 10407, 10410, 10413) --
    /// Shielded literal in `new(...)` expression args (int)
    ShieldedLiteralNewExprInt,
    /// Shielded literal in `new(...)` expression args (bool)
    ShieldedLiteralNewExprBool,
    /// Shielded literal in `new(...)` expression args (address)
    ShieldedLiteralNewExprAddress,
    /// Shielded literal in `new(...)` expression args (fixedbytes)
    ShieldedLiteralNewExprFixedbytes,
    /// Shielded literal in `new(...)` expression args (enum)
    ShieldedLiteralNewExprEnum,

    // -- Literal in external call args (10402, 10405, 10408, 10411, 10414) --
    /// Shielded literal in external call args (int)
    ShieldedLiteralExtCallInt,
    /// Shielded literal in external call args (bool)
    ShieldedLiteralExtCallBool,
    /// Shielded literal in external call args (address)
    ShieldedLiteralExtCallAddress,
    /// Shielded literal in external call args (fixedbytes)
    ShieldedLiteralExtCallFixedbytes,
    /// Shielded literal in external call args (enum)
    ShieldedLiteralExtCallEnum,

    // -- Literal in other contexts (10403, 10406, 10409, 10412, 10415) --
    /// Shielded literal in other context (int)
    ShieldedLiteralOtherInt,
    /// Shielded literal in other context (bool)
    ShieldedLiteralOtherBool,
    /// Shielded literal in other context (address)
    ShieldedLiteralOtherAddress,
    /// Shielded literal in other context (fixedbytes)
    ShieldedLiteralOtherFixedbytes,
    /// Shielded literal in other context (enum)
    ShieldedLiteralOtherEnum,

    // -- S-literal syntax (10416) --
    /// Shielded number literal (s-literal syntax, e.g. `5s`)
    ShieldedNumberLiteral,
}

impl SeismicError {
    /// String alias usable in `foundry.toml` `ignored_error_codes`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ShieldedArithAdd => "shielded-arith-add",
            Self::ShieldedArithSub => "shielded-arith-sub",
            Self::ShieldedArithMul => "shielded-arith-mul",
            Self::ShieldedArithDiv => "shielded-arith-div",
            Self::ShieldedArithMod => "shielded-arith-mod",
            Self::ShieldedArithExp => "shielded-arith-exp",
            Self::ShieldedArithShl => "shielded-arith-shl",
            Self::ShieldedArithShr => "shielded-arith-shr",
            Self::ShieldedCondIf => "shielded-cond-if",
            Self::ShieldedCondTernary => "shielded-cond-ternary",
            Self::ShieldedCondLoop => "shielded-cond-loop",
            Self::ShieldedConstructorParam => "shielded-constructor-param",
            Self::ShieldedLiteralNewExprInt => "shielded-literal-new-int",
            Self::ShieldedLiteralNewExprBool => "shielded-literal-new-bool",
            Self::ShieldedLiteralNewExprAddress => "shielded-literal-new-address",
            Self::ShieldedLiteralNewExprFixedbytes => "shielded-literal-new-fixedbytes",
            Self::ShieldedLiteralNewExprEnum => "shielded-literal-new-enum",
            Self::ShieldedLiteralExtCallInt => "shielded-literal-ext-call-int",
            Self::ShieldedLiteralExtCallBool => "shielded-literal-ext-call-bool",
            Self::ShieldedLiteralExtCallAddress => "shielded-literal-ext-call-address",
            Self::ShieldedLiteralExtCallFixedbytes => "shielded-literal-ext-call-fixedbytes",
            Self::ShieldedLiteralExtCallEnum => "shielded-literal-ext-call-enum",
            Self::ShieldedLiteralOtherInt => "shielded-literal-other-int",
            Self::ShieldedLiteralOtherBool => "shielded-literal-other-bool",
            Self::ShieldedLiteralOtherAddress => "shielded-literal-other-address",
            Self::ShieldedLiteralOtherFixedbytes => "shielded-literal-other-fixedbytes",
            Self::ShieldedLiteralOtherEnum => "shielded-literal-other-enum",
            Self::ShieldedNumberLiteral => "shielded-number-literal",
        }
    }

    /// Numeric ssolc warning code.
    pub fn code(&self) -> u64 {
        match self {
            Self::ShieldedArithAdd => 10301,
            Self::ShieldedArithSub => 10302,
            Self::ShieldedArithMul => 10303,
            Self::ShieldedArithDiv => 10304,
            Self::ShieldedArithMod => 10305,
            Self::ShieldedArithExp => 10306,
            Self::ShieldedArithShl => 10307,
            Self::ShieldedArithShr => 10308,
            Self::ShieldedCondIf => 10309,
            Self::ShieldedCondTernary => 10310,
            Self::ShieldedCondLoop => 10311,
            Self::ShieldedConstructorParam => 10103,
            Self::ShieldedLiteralNewExprInt => 10401,
            Self::ShieldedLiteralNewExprBool => 10404,
            Self::ShieldedLiteralNewExprAddress => 10407,
            Self::ShieldedLiteralNewExprFixedbytes => 10410,
            Self::ShieldedLiteralNewExprEnum => 10413,
            Self::ShieldedLiteralExtCallInt => 10402,
            Self::ShieldedLiteralExtCallBool => 10405,
            Self::ShieldedLiteralExtCallAddress => 10408,
            Self::ShieldedLiteralExtCallFixedbytes => 10411,
            Self::ShieldedLiteralExtCallEnum => 10414,
            Self::ShieldedLiteralOtherInt => 10403,
            Self::ShieldedLiteralOtherBool => 10406,
            Self::ShieldedLiteralOtherAddress => 10409,
            Self::ShieldedLiteralOtherFixedbytes => 10412,
            Self::ShieldedLiteralOtherEnum => 10415,
            Self::ShieldedNumberLiteral => 10416,
        }
    }

    /// Try to convert a numeric code to a named seismic variant.
    pub fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            10301 => Self::ShieldedArithAdd,
            10302 => Self::ShieldedArithSub,
            10303 => Self::ShieldedArithMul,
            10304 => Self::ShieldedArithDiv,
            10305 => Self::ShieldedArithMod,
            10306 => Self::ShieldedArithExp,
            10307 => Self::ShieldedArithShl,
            10308 => Self::ShieldedArithShr,
            10309 => Self::ShieldedCondIf,
            10310 => Self::ShieldedCondTernary,
            10311 => Self::ShieldedCondLoop,
            10103 => Self::ShieldedConstructorParam,
            10401 => Self::ShieldedLiteralNewExprInt,
            10404 => Self::ShieldedLiteralNewExprBool,
            10407 => Self::ShieldedLiteralNewExprAddress,
            10410 => Self::ShieldedLiteralNewExprFixedbytes,
            10413 => Self::ShieldedLiteralNewExprEnum,
            10402 => Self::ShieldedLiteralExtCallInt,
            10405 => Self::ShieldedLiteralExtCallBool,
            10408 => Self::ShieldedLiteralExtCallAddress,
            10411 => Self::ShieldedLiteralExtCallFixedbytes,
            10414 => Self::ShieldedLiteralExtCallEnum,
            10403 => Self::ShieldedLiteralOtherInt,
            10406 => Self::ShieldedLiteralOtherBool,
            10409 => Self::ShieldedLiteralOtherAddress,
            10412 => Self::ShieldedLiteralOtherFixedbytes,
            10415 => Self::ShieldedLiteralOtherEnum,
            10416 => Self::ShieldedNumberLiteral,
            _ => return None,
        })
    }

    /// Try to parse a string alias to a named seismic variant.
    pub fn from_alias(s: &str) -> Option<Self> {
        Some(match s {
            "shielded-arith-add" => Self::ShieldedArithAdd,
            "shielded-arith-sub" => Self::ShieldedArithSub,
            "shielded-arith-mul" => Self::ShieldedArithMul,
            "shielded-arith-div" => Self::ShieldedArithDiv,
            "shielded-arith-mod" => Self::ShieldedArithMod,
            "shielded-arith-exp" => Self::ShieldedArithExp,
            "shielded-arith-shl" => Self::ShieldedArithShl,
            "shielded-arith-shr" => Self::ShieldedArithShr,
            "shielded-cond-if" => Self::ShieldedCondIf,
            "shielded-cond-ternary" => Self::ShieldedCondTernary,
            "shielded-cond-loop" => Self::ShieldedCondLoop,
            "shielded-constructor-param" => Self::ShieldedConstructorParam,
            "shielded-literal-new-int" => Self::ShieldedLiteralNewExprInt,
            "shielded-literal-new-bool" => Self::ShieldedLiteralNewExprBool,
            "shielded-literal-new-address" => Self::ShieldedLiteralNewExprAddress,
            "shielded-literal-new-fixedbytes" => Self::ShieldedLiteralNewExprFixedbytes,
            "shielded-literal-new-enum" => Self::ShieldedLiteralNewExprEnum,
            "shielded-literal-ext-call-int" => Self::ShieldedLiteralExtCallInt,
            "shielded-literal-ext-call-bool" => Self::ShieldedLiteralExtCallBool,
            "shielded-literal-ext-call-address" => Self::ShieldedLiteralExtCallAddress,
            "shielded-literal-ext-call-fixedbytes" => Self::ShieldedLiteralExtCallFixedbytes,
            "shielded-literal-ext-call-enum" => Self::ShieldedLiteralExtCallEnum,
            "shielded-literal-other-int" => Self::ShieldedLiteralOtherInt,
            "shielded-literal-other-bool" => Self::ShieldedLiteralOtherBool,
            "shielded-literal-other-address" => Self::ShieldedLiteralOtherAddress,
            "shielded-literal-other-fixedbytes" => Self::ShieldedLiteralOtherFixedbytes,
            "shielded-literal-other-enum" => Self::ShieldedLiteralOtherEnum,
            "shielded-number-literal" => Self::ShieldedNumberLiteral,
            _ => return None,
        })
    }

    /// All known seismic variants, for exhaustive testing.
    pub const ALL: &'static [SeismicError] = &[
        Self::ShieldedArithAdd,
        Self::ShieldedArithSub,
        Self::ShieldedArithMul,
        Self::ShieldedArithDiv,
        Self::ShieldedArithMod,
        Self::ShieldedArithExp,
        Self::ShieldedArithShl,
        Self::ShieldedArithShr,
        Self::ShieldedCondIf,
        Self::ShieldedCondTernary,
        Self::ShieldedCondLoop,
        Self::ShieldedConstructorParam,
        Self::ShieldedLiteralNewExprInt,
        Self::ShieldedLiteralNewExprBool,
        Self::ShieldedLiteralNewExprAddress,
        Self::ShieldedLiteralNewExprFixedbytes,
        Self::ShieldedLiteralNewExprEnum,
        Self::ShieldedLiteralExtCallInt,
        Self::ShieldedLiteralExtCallBool,
        Self::ShieldedLiteralExtCallAddress,
        Self::ShieldedLiteralExtCallFixedbytes,
        Self::ShieldedLiteralExtCallEnum,
        Self::ShieldedLiteralOtherInt,
        Self::ShieldedLiteralOtherBool,
        Self::ShieldedLiteralOtherAddress,
        Self::ShieldedLiteralOtherFixedbytes,
        Self::ShieldedLiteralOtherEnum,
        Self::ShieldedNumberLiteral,
    ];
}

impl fmt::Display for SeismicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SeismicError {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_alias(s).ok_or_else(|| format!("unknown seismic error alias: {s}"))
    }
}

impl Serialize for SeismicError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SeismicError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_alias(&s).ok_or_else(|| serde::de::Error::custom(format!("unknown seismic error: {s}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_roundtrip_code() {
        for variant in SeismicError::ALL {
            let code = variant.code();
            let back = SeismicError::from_code(code)
                .unwrap_or_else(|| panic!("from_code({code}) returned None"));
            assert_eq!(*variant, back, "code round-trip failed for {code}");
        }
    }

    #[test]
    fn all_variants_roundtrip_str() {
        for variant in SeismicError::ALL {
            let s = variant.as_str();
            let back = SeismicError::from_alias(s)
                .unwrap_or_else(|| panic!("from_alias({s:?}) returned None"));
            assert_eq!(*variant, back, "str round-trip failed for {s}");
        }
    }

    #[test]
    fn all_codes_are_seismic_range() {
        for variant in SeismicError::ALL {
            assert!(variant.code() >= 10000, "{:?} has code {} < 10000", variant, variant.code());
        }
    }

    #[test]
    fn unknown_code_returns_none() {
        assert!(SeismicError::from_code(9999).is_none());
        assert!(SeismicError::from_code(0).is_none());
        assert!(SeismicError::from_code(99999).is_none());
    }

    #[test]
    fn unknown_alias_returns_none() {
        assert!(SeismicError::from_alias("not-a-thing").is_none());
        assert!(SeismicError::from_alias("").is_none());
    }

    #[test]
    fn expected_variant_count() {
        // 11 arith/cond + 1 constructor + 5 new-expr + 5 ext-call + 5 other + 1 s-literal = 28
        assert_eq!(SeismicError::ALL.len(), 28);
    }
}
