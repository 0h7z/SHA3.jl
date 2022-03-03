#	SHA3.jl
[![CI status](https://github.com/0h7z/SHA3.jl/actions/workflows/CI.yml/badge.svg)](https://github.com/0h7z/SHA3.jl/actions/workflows/CI.yml)
[![codecov.io](https://codecov.io/gh/0h7z/SHA3.jl/branch/master/graph/badge.svg)](https://app.codecov.io/gh/0h7z/SHA3.jl)

*****
##	Usage
```julia
pkg> registry add https://github.com/0h7z/0hjl.git
pkg> add SHA3

julia> using SHA3
julia> hash = ""          |> sha3_512 |> bytes2hex  # a69f73cca23a9ac5...
julia> hash = 'a'^71      |> sha3_512 |> bytes2hex  # 070faf98d2a8fddf...
julia> hash = read($file) |> sha3_512 |> bytes2hex
```

