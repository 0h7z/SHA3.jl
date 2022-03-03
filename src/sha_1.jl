# Nonlinear functions, in order to encourage inlining, these sadly are not a vector of lambdas
Round1(b, c, d) = UInt32((b & c) | (~b & d))
Round2(b, c, d) = UInt32(b ⊻ c ⊻ d)
Round3(b, c, d) = UInt32((b & c) | (b & d) | (c & d))
Round4(b, c, d) = UInt32(b ⊻ c ⊻ d)

function transform!(context::SHA1_CTX)
	# Buffer is 16 elements long, we expand to 80
	pbuf = buffer_pointer(context)
	@inbounds for i in 1:16
		context.W[i] = bswap(unsafe_load(pbuf, i))
	end

	# First round of expansions
	@inbounds for i in 17:32
		context.W[i] = lrot(1, context.W[i-3] ⊻ context.W[i-8] ⊻ context.W[i-14] ⊻ context.W[i-16], 32)
	end

	# Second round of expansions (possibly 4-way SIMD-able)
	@inbounds for i in 33:80
		context.W[i] = lrot(2, context.W[i-6] ⊻ context.W[i-16] ⊻ context.W[i-28] ⊻ context.W[i-32], 32)
	end

	# Initialize registers with the previous intermediate values (our state)
	a = context.state[1]
	b = context.state[2]
	c = context.state[3]
	d = context.state[4]
	e = context.state[5]

	# Run our rounds, manually separated into the four rounds, unfortunately using a vector of lambdas really kills performance and causes a huge number of allocations, so we make it easy on the compiler
	@inbounds for i in 1:20
		temp = UInt32(lrot(5, a, 32) + Round1(b, c, d) + e + context.W[i] + K1[1])
		e = d
		d = c
		c = lrot(30, b, 32)
		b = a
		a = temp
	end

	@inbounds for i in 21:40
		temp = UInt32(lrot(5, a, 32) + Round2(b, c, d) + e + context.W[i] + K1[2])
		e = d
		d = c
		c = lrot(30, b, 32)
		b = a
		a = temp
	end

	@inbounds for i in 41:60
		temp = UInt32(lrot(5, a, 32) + Round3(b, c, d) + e + context.W[i] + K1[3])
		e = d
		d = c
		c = lrot(30, b, 32)
		b = a
		a = temp
	end

	@inbounds for i in 61:80
		temp = UInt32(lrot(5, a, 32) + Round4(b, c, d) + e + context.W[i] + K1[4])
		e = d
		d = c
		c = lrot(30, b, 32)
		b = a
		a = temp
	end

	context.state[1] += a
	context.state[2] += b
	context.state[3] += c
	context.state[4] += d
	context.state[5] += e

	nothing
end

