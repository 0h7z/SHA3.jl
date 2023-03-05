"""
	SHA3

The SHA3 module provides hashing functionality for SHA1, SHA2, and SHA3
algorithms.

They are implemented as both pure functions for hashing single pieces of
data, or a stateful context which can be updated with the `update!` function
and finalized with `digest!`.

# Examples
```jldoctest
julia> sha3_512('a'^71)
64-element Vector{UInt8}:
 0x07
 0x0f
    ⋮
 0xe2
 0x8c

julia> sha3_512('a'^71) |> bytes2hex
"070faf98d2a8fddf8ed886408744dc06456096c2e045f26f3c7b010530e6bbb3db535a54d636856f4e0e1e982461cb9a7e8e57ff8895cff1619af9f0e486e28c"
```
"""
module SHA3

# Export convenience functions, context types, update!(), and digest!() functions
export sha1, SHA1_CTX, update!, digest!
export sha224, sha256, sha384, sha512
export sha2_224, sha2_256, sha2_384, sha2_512
export sha3_224, sha3_256, sha3_384, sha3_512
export SHA224_CTX, SHA256_CTX, SHA384_CTX, SHA512_CTX
export SHA2_224_CTX, SHA2_256_CTX, SHA2_384_CTX, SHA2_512_CTX
export SHA3_224_CTX, SHA3_256_CTX, SHA3_384_CTX, SHA3_512_CTX
export HMAC_CTX, hmac_sha1
export hmac_sha224, hmac_sha256, hmac_sha384, hmac_sha512
export hmac_sha2_224, hmac_sha2_256, hmac_sha2_384, hmac_sha2_512
export hmac_sha3_224, hmac_sha3_256, hmac_sha3_384, hmac_sha3_512

include("base_func.jl")
include("const.jl")
include("type.jl")

include("common.jl")
include("hmac.jl")
include("sha_1.jl")
include("sha_2.jl")
include("sha_3.jl")

# Create data types and convenience functions for each hash implemented
for (f, ctx) in [
	(:sha1, :SHA1_CTX)
	(:sha224, :SHA224_CTX)
	(:sha256, :SHA256_CTX)
	(:sha384, :SHA384_CTX)
	(:sha512, :SHA512_CTX)
	(:sha2_224, :SHA2_224_CTX)
	(:sha2_256, :SHA2_256_CTX)
	(:sha2_384, :SHA2_384_CTX)
	(:sha2_512, :SHA2_512_CTX)
	(:sha3_224, :SHA3_224_CTX)
	(:sha3_256, :SHA3_256_CTX)
	(:sha3_384, :SHA3_384_CTX)
	(:sha3_512, :SHA3_512_CTX)
]
	g = Symbol(:hmac_, f)

	@eval begin
		# Our basic function is to process vector of bytes
		"""
			$($f)(data)

		Hash data using the `$($f)` algorithm and return the resulting digest.
		See also [`$($ctx)`](@ref).
		"""
		function $f(data::AbstractBytes)
			ctx = $ctx()
			update!(ctx, data)
			digest!(ctx)
		end

		"""
			$($g)(key, data)

		Hash data using the `$($f)` algorithm using the passed key.
		See also [`HMAC_CTX`](@ref).
		"""
		function $g(key::Vector{UInt8}, data::AbstractBytes)
			ctx = HMAC_CTX($ctx(), key)
			update!(ctx, data)
			digest!(ctx)
		end

		# AbstractStrings are a pretty handy thing to be able to crunch through
		$f(str::AbstractString)                     = $f(String(str)) # always crunch UTF-8
		$f(str::String)                             = $f(codeunits(str))
		$g(key::Vector{UInt8}, str::AbstractString) = $g(key, String(str))
		$g(key::Vector{UInt8}, str::String)         = $g(key, codeunits(str))

		"""
			$($f)(io::IO)

		Hash data from io using `$($f)` algorithm.
		"""
		function $f(io::IO, chunk_size = 4 * 1024)
			ctx = $ctx()
			buff = Vector{UInt8}(undef, chunk_size)
			while !eof(io)
				num_read = readbytes!(io, buff)
				update!(ctx, buff, num_read)
			end
			digest!(ctx)
		end

		"""
			$($g)(key, io::IO)

		Hash data from `io` with the passed key using `$($f)` algorithm.
		"""
		function $g(key::Vector{UInt8}, io::IO, chunk_size = 4 * 1024)
			ctx = HMAC_CTX($ctx(), key)
			buff = Vector{UInt8}(undef, chunk_size)
			while !eof(io)
				num_read = readbytes!(io, buff)
				update!(ctx, buff, num_read)
			end
			digest!(ctx)
		end
	end
end

end # module

