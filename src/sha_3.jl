function transform!(context::T) where T <: SHA3_CTX
	# First, update state with buffer
	pbuf = Ptr{eltype(context.state)}(pointer(context.buffer))
	for idx in 1:blocklen(T)÷8
		context.state[idx] ⊻= unsafe_load(pbuf, idx)
	end
	bc    = context.bc
	state = context.state

	# We always assume 24 rounds
	@inbounds for round in 1:24
		# Theta function
		for i in 1:5
			bc[i] = state[i] ⊻ state[i+5] ⊻ state[i+10] ⊻ state[i+15] ⊻ state[i+20]
		end

		for i in 1:5
			temp = bc[rem(i + 3, 5)+1] ⊻ L64(1, bc[rem(i, 5)+1])
			for j in 0:5:20
				state[i+j] ⊻= temp
			end
		end

		# Rho Pi
		temp = state[2]
		for i in 1:24
			j = SHA3_PILN[i]
			bc[1] = state[j]
			state[j] = L64(SHA3_ROTC[i], temp)
			temp = bc[1]
		end

		# Chi
		for j in 0:5:20
			for i in 1:5
				bc[i] = state[i+j]
			end
			for i in 1:5
				state[i+j] ⊻= ~bc[rem(i, 5)+1] & bc[rem(i + 1, 5)+1]
			end
		end

		# Iota
		state[1] ⊻= SHA3_ROUND_CONSTS[round]
	end

	context.state
end



# Finalize data in the buffer, append total bitlength, and return our precious hash!
function digest!(context::T) where T <: SHA3_CTX
	usedspace = context.bytecount % blocklen(T)
	# Pad and transform that data (buffer is never full; two cases: at least two bytes free or only one)
	if usedspace < blocklen(T) - 1
		# Begin padding with a 0x06
		context.buffer[usedspace+1] = 0x06
		# Fill with zeros up until the last byte
		context.buffer[usedspace+2:end-1] .= 0x00
		# Finish it off with a 0x80
		context.buffer[end] = 0x80
	else
		# Finish it off with a 0x86
		context.buffer[end] = 0x86
	end

	# Final transform
	transform!(context)

	# Return the digest
	reinterpret(UInt8, context.state)[1:digestlen(T)]
end

