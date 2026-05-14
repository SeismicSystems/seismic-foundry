use std::{fmt, str::FromStr};

/// Named seismic/ssolc warning codes that are not represented as top-level
/// `SolidityErrorCode` variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeismicError {
    /// Warning: shielded literal in other contexts (int)
    ShieldedLiteralOtherInt,
    /// Warning: shielded literal in other contexts (bool)
    ShieldedLiteralOtherBool,
    /// Warning: shielded literal in other contexts (address)
    ShieldedLiteralOtherAddress,
    /// Warning: shielded literal in other contexts (fixedbytes)
    ShieldedLiteralOtherFixedbytes,
    /// Warning: shielded literal in other contexts (enum)
    ShieldedLiteralOtherEnum,
    /// Warning: shielded number literal syntax (e.g. `5s`)
    ShieldedNumberLiteral,
    /// Warning: shielded arithmetic in addition
    ShieldedArithmeticAddition,
    /// Warning: shielded arithmetic in subtraction
    ShieldedArithmeticSubtraction,
    /// Warning: shielded arithmetic in multiplication
    ShieldedArithmeticMultiplication,
    /// Warning: shielded arithmetic in division
    ShieldedArithmeticDivision,
    /// Warning: shielded arithmetic in modulo
    ShieldedArithmeticModulo,
    /// Warning: shielded arithmetic in exponentiation
    ShieldedArithmeticExponentiation,
    /// Warning: shielded arithmetic in shift left
    ShieldedArithmeticShiftLeft,
    /// Warning: shielded arithmetic in shift right
    ShieldedArithmeticShiftRight,
    /// Warning: shielded branching in if conditions
    ShieldedBranchingIfCondition,
    /// Warning: shielded branching in ternary conditions
    ShieldedBranchingTernaryCondition,
    /// Warning: shielded branching in while/for conditions
    ShieldedBranchingWhileForCondition,
}

impl SeismicError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ShieldedLiteralOtherInt => "shielded-literal-other-int",
            Self::ShieldedLiteralOtherBool => "shielded-literal-other-bool",
            Self::ShieldedLiteralOtherAddress => "shielded-literal-other-address",
            Self::ShieldedLiteralOtherFixedbytes => "shielded-literal-other-fixedbytes",
            Self::ShieldedLiteralOtherEnum => "shielded-literal-other-enum",
            Self::ShieldedNumberLiteral => "shielded-number-literal",
            Self::ShieldedArithmeticAddition => "shielded-arithmetic-addition",
            Self::ShieldedArithmeticSubtraction => "shielded-arithmetic-subtraction",
            Self::ShieldedArithmeticMultiplication => "shielded-arithmetic-multiplication",
            Self::ShieldedArithmeticDivision => "shielded-arithmetic-division",
            Self::ShieldedArithmeticModulo => "shielded-arithmetic-modulo",
            Self::ShieldedArithmeticExponentiation => "shielded-arithmetic-exponentiation",
            Self::ShieldedArithmeticShiftLeft => "shielded-arithmetic-shift-left",
            Self::ShieldedArithmeticShiftRight => "shielded-arithmetic-shift-right",
            Self::ShieldedBranchingIfCondition => "shielded-branching-if-condition",
            Self::ShieldedBranchingTernaryCondition => "shielded-branching-ternary-condition",
            Self::ShieldedBranchingWhileForCondition => "shielded-branching-while-for-condition",
        }
    }

    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            10403 => Some(Self::ShieldedLiteralOtherInt),
            10406 => Some(Self::ShieldedLiteralOtherBool),
            10409 => Some(Self::ShieldedLiteralOtherAddress),
            10412 => Some(Self::ShieldedLiteralOtherFixedbytes),
            10415 => Some(Self::ShieldedLiteralOtherEnum),
            10416 => Some(Self::ShieldedNumberLiteral),
            10301 => Some(Self::ShieldedArithmeticAddition),
            10302 => Some(Self::ShieldedArithmeticSubtraction),
            10303 => Some(Self::ShieldedArithmeticMultiplication),
            10304 => Some(Self::ShieldedArithmeticDivision),
            10305 => Some(Self::ShieldedArithmeticModulo),
            10306 => Some(Self::ShieldedArithmeticExponentiation),
            10307 => Some(Self::ShieldedArithmeticShiftLeft),
            10308 => Some(Self::ShieldedArithmeticShiftRight),
            10309 => Some(Self::ShieldedBranchingIfCondition),
            10310 => Some(Self::ShieldedBranchingTernaryCondition),
            10311 => Some(Self::ShieldedBranchingWhileForCondition),
            _ => None,
        }
    }
}

impl From<SeismicError> for u64 {
    fn from(error: SeismicError) -> Self {
        match error {
            SeismicError::ShieldedLiteralOtherInt => 10403,
            SeismicError::ShieldedLiteralOtherBool => 10406,
            SeismicError::ShieldedLiteralOtherAddress => 10409,
            SeismicError::ShieldedLiteralOtherFixedbytes => 10412,
            SeismicError::ShieldedLiteralOtherEnum => 10415,
            SeismicError::ShieldedNumberLiteral => 10416,
            SeismicError::ShieldedArithmeticAddition => 10301,
            SeismicError::ShieldedArithmeticSubtraction => 10302,
            SeismicError::ShieldedArithmeticMultiplication => 10303,
            SeismicError::ShieldedArithmeticDivision => 10304,
            SeismicError::ShieldedArithmeticModulo => 10305,
            SeismicError::ShieldedArithmeticExponentiation => 10306,
            SeismicError::ShieldedArithmeticShiftLeft => 10307,
            SeismicError::ShieldedArithmeticShiftRight => 10308,
            SeismicError::ShieldedBranchingIfCondition => 10309,
            SeismicError::ShieldedBranchingTernaryCondition => 10310,
            SeismicError::ShieldedBranchingWhileForCondition => 10311,
        }
    }
}

impl fmt::Display for SeismicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl FromStr for SeismicError {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "shielded-literal-other-int" => Ok(Self::ShieldedLiteralOtherInt),
            "shielded-literal-other-bool" => Ok(Self::ShieldedLiteralOtherBool),
            "shielded-literal-other-address" => Ok(Self::ShieldedLiteralOtherAddress),
            "shielded-literal-other-fixedbytes" => Ok(Self::ShieldedLiteralOtherFixedbytes),
            "shielded-literal-other-enum" => Ok(Self::ShieldedLiteralOtherEnum),
            "shielded-number-literal" => Ok(Self::ShieldedNumberLiteral),
            "shielded-arithmetic-addition" => Ok(Self::ShieldedArithmeticAddition),
            "shielded-arithmetic-subtraction" => Ok(Self::ShieldedArithmeticSubtraction),
            "shielded-arithmetic-multiplication" => Ok(Self::ShieldedArithmeticMultiplication),
            "shielded-arithmetic-division" => Ok(Self::ShieldedArithmeticDivision),
            "shielded-arithmetic-modulo" => Ok(Self::ShieldedArithmeticModulo),
            "shielded-arithmetic-exponentiation" => Ok(Self::ShieldedArithmeticExponentiation),
            "shielded-arithmetic-shift-left" => Ok(Self::ShieldedArithmeticShiftLeft),
            "shielded-arithmetic-shift-right" => Ok(Self::ShieldedArithmeticShiftRight),
            "shielded-branching-if-condition" => Ok(Self::ShieldedBranchingIfCondition),
            "shielded-branching-ternary-condition" => Ok(Self::ShieldedBranchingTernaryCondition),
            "shielded-branching-while-for-condition" => {
                Ok(Self::ShieldedBranchingWhileForCondition)
            }
            _ => Err(format!("Unknown seismic variant {s}")),
        }
    }
}
