using SHA3, Test
const SHA = SHA3

include("const.jl")

function describe_hash(T::Type{S}) where S <: SHA.SHA_CTX
	T <: SHA.SHA1_CTX && return "SHA1"
	T <: SHA.SHA2_CTX && return "SHA2-$(8SHA.digestlen(T))"
	T <: SHA.SHA3_CTX && return "SHA3-$(8SHA.digestlen(T))"
end

@debug("Loaded hash types: $(join(sort([describe_hash(t[2]) for t in sha_types]), ", ", ", and "))")

@testset "Hashing" begin
	# First, test processing the data in one go
	@testset "Complete" begin
		for idx in eachindex(data)
			@testset "$(data_desc[idx])" begin
				for sha_func in sha_funcs
					hash = bytes2hex(sha_func(deepcopy(data[idx])))
					@test hash == answers[sha_func][idx]
				end
			end
		end
	end

	# Do another test on the "so many 'a's" data where we chunk up the data into two chunks, (sized appropriately to AVOID overflow from one update to another) in order to test multiple update!() calls
	@testset "Chunked Properly" begin
		for sha_func in sha_funcs
			ctx = sha_types[sha_func]()
			SHA.update!(ctx, so_many_as_array[1:2SHA.blocklen(typeof(ctx))])
			SHA.update!(ctx, so_many_as_array[1+2SHA.blocklen(typeof(ctx)):end])
			hash = bytes2hex(SHA.digest!(ctx))
			@test hash == answers[sha_func][end]
			ctx = sha_types[sha_func]()
			@test_throws BoundsError SHA.update!(ctx, so_many_as_array, length(so_many_as_array) + 1)
		end
	end

	# Do another test on the "so many 'a's" data where we chunk up the data into three chunks, (sized appropriately to CAUSE overflow from one update to another) in order to test multiple update!() calls as well as the overflow codepaths
	@testset "Chunked clumsily" begin
		for sha_func in sha_funcs
			ctx = sha_types[sha_func]()

			# Get indices awkwardly placed for the blocklength of this hash type
			idx0 = round(Int, 0.3SHA.blocklen(typeof(ctx)))
			idx1 = round(Int, 1.7SHA.blocklen(typeof(ctx)))
			idx2 = round(Int, 2.6SHA.blocklen(typeof(ctx)))

			# Feed data in according to our dastardly blocking scheme
			SHA.update!(ctx, so_many_as_array[00000+1:1idx0])
			SHA.update!(ctx, so_many_as_array[1idx0+1:2idx0])
			SHA.update!(ctx, so_many_as_array[2idx0+1:3idx0])
			SHA.update!(ctx, so_many_as_array[3idx0+1:4idx0])
			SHA.update!(ctx, so_many_as_array[4idx0+1:1idx1])
			SHA.update!(ctx, so_many_as_array[1idx1+1:1idx2])
			SHA.update!(ctx, so_many_as_array[1idx2+1:end])

			# Ensure the hash is the appropriate one
			hash = bytes2hex(SHA.digest!(ctx))
			@test hash == answers[sha_func][end]
		end
	end
end

@testset "HMAC" begin
	# Test hmac correctness using the examples from Wikipedia
	# https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Examples
	for (key, msg, fun, hash) in hmac_data
		digest = bytes2hex(fun(Vector{UInt8}(key), Vector{UInt8}(msg)))
		@test digest == hash
		digest = bytes2hex(fun(Vector{UInt8}(key), SubString(msg)))
		@test digest == hash
		digest = bytes2hex(fun(Vector{UInt8}(key), IOBuffer(msg)))
		@test digest == hash
	end
end

replstr(x) = sprint((io, x) -> show(IOContext(io, :limit => true), MIME("text/plain"), x), x)
@testset "REPL" begin
	for idx in eachindex(ctxs)
		@test typeof(copy(ctxs[idx]())) == typeof(ctxs[idx]())
		@test replstr(ctxs[idx]()) == shws[idx]
		@test_throws ErrorException copy(ctxs[idx]()).nonexistingfield
	end
end

@testset "Type-checking" begin
	for f in sha_funcs
		@test_throws MethodError f(UInt32[0x23467, 0x324775])
	end
end

