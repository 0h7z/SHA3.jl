# THE SIX LOGICAL FUNCTIONS
#
# Bit shifting and rotation (used by the six SHA-XYZ logical functions
#
# NOTE: The naming of R and S appears backwards here (R is a SHIFT and S is a
# ROTATION) because the SHA2-256/384/512 description document uses this same
# "backwards" definition. See:
# https://web.archive.org/web/20070208150402/https://csrc.nist.gov/cryptval/shs/sha256-384-512.pdf

# 32-bit Rotate-right (equivalent to S32 in SHA-256) and rotate-left
rrot(b::Integer, x::Unsigned, width::Integer)::Unsigned = (x >> b) | (x << (width - b))
lrot(b::Integer, x::Unsigned, width::Integer)::Unsigned = (x << b) | (x >> (width - b))

# Shift-right (used in SHA-256, SHA-384, and SHA-512)
R(b::Integer, x::Unsigned)::Unsigned = (x >> b)
# 32-bit Rotate-right (used in SHA-256)
S32(b::Integer, x::UInt32)::UInt32 = rrot(b, x, 32)
# 64-bit Rotate-right (used in SHA-384 and SHA-512)
S64(b::Integer, x::UInt64)::UInt64 = rrot(b, x, 64)
# 64-bit Rotate-left (used in SHA3)
L64(b::Integer, x::UInt64)::UInt64 = lrot(b, x, 64)

# Two of six logical functions used in SHA-256, SHA-384, and SHA-512
Ch(x::Unsigned, y::Unsigned, z::Unsigned)::Unsigned  = (x & y) ⊻ (~x & z)
Maj(x::Unsigned, y::Unsigned, z::Unsigned)::Unsigned = (x & y) ⊻ (x & z) ⊻ (y & z)

# Four of six logical functions used in SHA-256
Sigma0_256(x::UInt32)::UInt32 = S32(02, UInt32(x)) ⊻ S32(13, UInt32(x)) ⊻ S32(22, UInt32(x))
Sigma1_256(x::UInt32)::UInt32 = S32(06, UInt32(x)) ⊻ S32(11, UInt32(x)) ⊻ S32(25, UInt32(x))
sigma0_256(x::UInt32)::UInt32 = S32(07, UInt32(x)) ⊻ S32(18, UInt32(x)) ⊻ R(0003, UInt32(x))
sigma1_256(x::UInt32)::UInt32 = S32(17, UInt32(x)) ⊻ S32(19, UInt32(x)) ⊻ R(0010, UInt32(x))

# Four of six logical functions used in SHA-384 and SHA-512
Sigma0_512(x::UInt64)::UInt64 = S64(28, UInt64(x)) ⊻ S64(34, UInt64(x)) ⊻ S64(39, UInt64(x))
Sigma1_512(x::UInt64)::UInt64 = S64(14, UInt64(x)) ⊻ S64(18, UInt64(x)) ⊻ S64(41, UInt64(x))
sigma0_512(x::UInt64)::UInt64 = S64(01, UInt64(x)) ⊻ S64(08, UInt64(x)) ⊻ R(0007, UInt64(x))
sigma1_512(x::UInt64)::UInt64 = S64(19, UInt64(x)) ⊻ S64(61, UInt64(x)) ⊻ R(0006, UInt64(x))

# Let us be able to bswap vector of these types as well
bswap!(x::Vector{<:Integer}) = map!(bswap, x, x)

# ErrorException
@noinline boundserror(a, i) = throw(BoundsError(a, i))

