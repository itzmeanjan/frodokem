> [!CAUTION]
> This FrodoKEM implementation is conformant with FrodoKEM specification @ https://frodokem.org/files/FrodoKEM-standard_proposal-20230314.pdf. I also try to make it timing leakage free, using `dudect` (see https://github.com/oreparaz/dudect) -based tests, but be informed that this implementation is not yet audited. *If you consider using it in production, be careful !*

# frodokem
FrodoKEM: Practical Quantum-secure Key Encapsulation from Generic Lattices

## Overview

FrodoKEM is a post-quantum key encapsulation mechanism (KEM), based on the hardness of learning with errors (LWE) problem, which has close connections to conjectured-hard problems on generic, algebraically unstructured lattices, offering IND-CCA security. FrodoKEM is built on top of FrodoPKE, which is a public key encryption (PKE) algorithm, can be used for encrypting fixed length messages, offering IND-CPA security.

Scheme | What does it offer ?
--- | --:
FrodoPKE | Lets you encrypt a fixed length message M, using your peer's public key, resulting in a cipher text, which can only be decrypted by respective peer's secret key.
FrodoKEM | Helps in establishing secure communication channel between two parties - (a) starting communication over insecure channel, (b) later on begins using some authenticated encryption (AEAD) scheme for encrypting their messages, using the common key ( = shared secret ) that both of them arrived at by using the KEM scheme.

Here I'm maintaining a header-only, easy-to-use ( see [below](#usage) ) C++20 library, offering FrodoKEM API, for three security levels, each for two usage scenarios ( i.e. static and ephemeral ).

> [!NOTE]
> Right now this library only provides you with FrodoKEM implementation s.t. generation of matrix `A` always uses SHAKE128 Xof. I've not *yet* implemented AES128 backed matrix `A` generation logic.

Scheme | Target Security Level
:-- | --:
(e)Frodo-640 KEM | NIST-I
(e)Frodo-976 KEM | NIST-III
(e)Frodo-1344 KEM | NIST-V

> [!NOTE]
> (STATIC): Long term use of same keypair s.t. many cipher texts can be computed per public key. KEM variants whose names look like Frodo-{640, 976, 1344} KEM.

> [!NOTE]
> (EPHEMERAL): Only small number of cipher texts are produced per public key. Begins with an `e` i.e. eFrodo-{640,976,1344} KEM.

While working on this implementation, I've mainly followed the FrodoKEM specification @ https://frodokem.org/files/FrodoKEM-standard_proposal-20230314.pdf. Though for certain function implementations, I found an older version of specifiction, living @ https://frodokem.org/files/FrodoKEM-specification-20210604.pdf, more comprehensive. I suggest you go through them for an in-depth understanding of the scheme.

## Prerequisites

- A C++ compiler with support for C++20 standard library.

```bash
$  g++ --version
g++ (Ubuntu 13.2.0-4ubuntu3) 13.2.0

$ clang++ --version
Ubuntu clang version 17.0.2 (1~exp1ubuntu2.1)
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```

- Build tools.

```bash
$ make --version
GNU Make 4.3

$ cmake --version
cmake version 3.27.4
```

- For testing functional correctness of FrodoKEM and its components, you need to globally install `google-test` headers and library. Follow the guide @ https://github.com/google/googletest/tree/main/googletest#standalone-cmake-project.
- For benchmarking FrodoKEM algorithms, you must have `google-benchmark` headers and library available in `$PATH`. I found the installation guide @ https://github.com/google/benchmark#installation helpful.

> [!NOTE]
> If you are on a machine running GNU/Linux kernel and you want to obtain CPU cycle count for KEM algorithms, you should consider building `google-benchmark` library with libPFM support, following the step-by-step guide @ https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7. Find more about libPFM @ https://perfmon2.sourceforge.net.

> [!TIP]
> Git submodule based dependencies will generally be imported automatically, but in case that doesn't work, you can manually initialize and update them by issuing `$ git submodule update --init` from inside the root of this repository.

## Testing

For ensuring functional correctness of FrodoKEM and its constituting components, issue following command. Issuing following command also runs necessary tests, which ensures that this FrodoKEM implementation is conformant with the specification, by checking keypair/ cipher text/ shared secret values for given seeds, using known answer tests (KATs).

> [!NOTE]
> Known Answer Tests (KATs) living in [this](./kats) directory are computed by following (reproducible) steps, described in the gist @ https://gist.github.com/itzmeanjan/38d506a69073bdeb0933245401f42186.

```bash
make -j            # Run tests without any sort of sanitizers
make asan_test -j  # Run tests with AddressSanitizer enabled
make ubsan_test -j # Run tests with UndefinedBehaviourSanitizer enabled
```

```bash
[13/13] FrodoKEM.Frodo1344KEMKAT (1838 ms)
PASSED TESTS (13/13):
       5 ms: build/test.out FrodoKEM.ZqEncodeDecode
       6 ms: build/test.out FrodoKEM.MatrixEncodeDecode
      11 ms: build/test.out FrodoKEM.MatrixPackUnpack
      11 ms: build/test.out FrodoKEM.MatrixTranspose
      17 ms: build/test.out FrodoKEM.MatrixAddSub
      18 ms: build/test.out FrodoKEM.Lemma2_18
     203 ms: build/test.out FrodoKEM.KeygenEncapsDecaps
     529 ms: build/test.out FrodoKEM.eFrodo640KEMKAT
     747 ms: build/test.out FrodoKEM.Frodo640KEMKAT
    1044 ms: build/test.out FrodoKEM.Frodo976KEMKAT
    1173 ms: build/test.out FrodoKEM.eFrodo976KEMKAT
    1792 ms: build/test.out FrodoKEM.eFrodo1344KEMKAT
    1838 ms: build/test.out FrodoKEM.Frodo1344KEMKAT
```

You can run timing leakage tests, using `dudect`; execute following

> [!NOTE]
> `dudect` is integrated into this library implementation of FrodoKEM to find any sort of timing leakages. It checks for constant-timeness of key generation, encapsulation and decapsulation function implementations, for only one variant i.e. *frodo640*.

```bash
# Can only be built and run on x86_64 machine.
make dudect_test_build -j

# Before running the constant-time tests, it's a good idea to put all CPU cores on "performance" mode.
# You may find the guide @ https://github.com/google/benchmark/blob/main/docs/reducing_variance.md helpful.

# Given FrodoKEM operations is slow, compared to Kyber/ Saber, following tests are required to be 
# run for longer, so that we can collect enough execution timing samples.
timeout 4h taskset -c 0 ./build/dudect/test_frodo640_keygen.out
timeout 4h taskset -c 0 ./build/dudect/test_frodo640_encaps.out
timeout 4h taskset -c 0 ./build/dudect/test_frodo640_decaps.out
```

> [!TIP]
> `dudect` documentation says if `t` statistic is `< 10`, we're *probably* good, yes *probably*. You may want to read `dudect` documentation @ https://github.com/oreparaz/dudect. Also you might find the original paper @ https://ia.cr/2016/1123 interesting.

```bash
# frodo640-keygen
...
meas:    0.06 M, max t:   +2.71, max tau: 1.15e-02, (5/tau)^2: 1.88e+05. For the moment, maybe constant time.
meas:    0.06 M, max t:   +2.90, max tau: 1.22e-02, (5/tau)^2: 1.68e+05. For the moment, maybe constant time.
meas:    0.06 M, max t:   +2.92, max tau: 1.23e-02, (5/tau)^2: 1.66e+05. For the moment, maybe constant time.
meas:    0.06 M, max t:   +2.49, max tau: 1.03e-02, (5/tau)^2: 2.35e+05. For the moment, maybe constant time.
meas:    0.06 M, max t:   +2.27, max tau: 9.31e-03, (5/tau)^2: 2.88e+05. For the moment, maybe constant time.
meas:    0.06 M, max t:   +2.23, max tau: 9.14e-03, (5/tau)^2: 2.99e+05. For the moment, maybe constant time.
meas:    0.06 M, max t:   +2.38, max tau: 9.63e-03, (5/tau)^2: 2.70e+05. For the moment, maybe constant time.
meas:    0.06 M, max t:   +2.23, max tau: 8.96e-03, (5/tau)^2: 3.11e+05. For the moment, maybe constant time.
meas:    0.43 M, max t:   +2.21, max tau: 3.38e-03, (5/tau)^2: 2.19e+06. For the moment, maybe constant time.
meas:    0.43 M, max t:   +2.22, max tau: 3.38e-03, (5/tau)^2: 2.19e+06. For the moment, maybe constant time.
meas:    0.06 M, max t:   +2.43, max tau: 9.58e-03, (5/tau)^2: 2.73e+05. For the moment, maybe constant time.
meas:    0.06 M, max t:   +2.42, max tau: 9.50e-03, (5/tau)^2: 2.77e+05. For the moment, maybe constant time.
meas:    0.07 M, max t:   +2.65, max tau: 1.03e-02, (5/tau)^2: 2.35e+05. For the moment, maybe constant time.

# frodo640-encaps
...
meas:    2.35 M, max t:   +1.98, max tau: 1.29e-03, (5/tau)^2: 1.50e+07. For the moment, maybe constant time.
meas:    2.43 M, max t:   +1.91, max tau: 1.22e-03, (5/tau)^2: 1.67e+07. For the moment, maybe constant time.
meas:    2.52 M, max t:   +1.87, max tau: 1.18e-03, (5/tau)^2: 1.79e+07. For the moment, maybe constant time.
meas:    2.61 M, max t:   +2.00, max tau: 1.24e-03, (5/tau)^2: 1.62e+07. For the moment, maybe constant time.
meas:    2.69 M, max t:   +1.69, max tau: 1.03e-03, (5/tau)^2: 2.35e+07. For the moment, maybe constant time.
meas:    2.78 M, max t:   +1.59, max tau: 9.53e-04, (5/tau)^2: 2.75e+07. For the moment, maybe constant time.
meas:    2.86 M, max t:   +1.70, max tau: 1.01e-03, (5/tau)^2: 2.46e+07. For the moment, maybe constant time.
meas:    2.90 M, max t:   +1.71, max tau: 1.01e-03, (5/tau)^2: 2.47e+07. For the moment, maybe constant time.
meas:    2.98 M, max t:   +1.69, max tau: 9.76e-04, (5/tau)^2: 2.63e+07. For the moment, maybe constant time.
meas:    3.07 M, max t:   +1.67, max tau: 9.56e-04, (5/tau)^2: 2.74e+07. For the moment, maybe constant time.
meas:    3.15 M, max t:   +1.76, max tau: 9.94e-04, (5/tau)^2: 2.53e+07. For the moment, maybe constant time.

# frodo640-decaps
...
meas:    6.24 M, max t:   +1.30, max tau: 5.21e-04, (5/tau)^2: 9.21e+07. For the moment, maybe constant time.
meas:    5.97 M, max t:   +1.38, max tau: 5.65e-04, (5/tau)^2: 7.84e+07. For the moment, maybe constant time.
meas:    6.07 M, max t:   +1.57, max tau: 6.38e-04, (5/tau)^2: 6.15e+07. For the moment, maybe constant time.
meas:    6.16 M, max t:   +1.61, max tau: 6.47e-04, (5/tau)^2: 5.97e+07. For the moment, maybe constant time.
meas:    6.25 M, max t:   +1.34, max tau: 5.37e-04, (5/tau)^2: 8.66e+07. For the moment, maybe constant time.
meas:    6.34 M, max t:   +1.36, max tau: 5.41e-04, (5/tau)^2: 8.53e+07. For the moment, maybe constant time.
meas:    6.43 M, max t:   +1.34, max tau: 5.28e-04, (5/tau)^2: 8.98e+07. For the moment, maybe constant time.
meas:    6.52 M, max t:   +1.42, max tau: 5.55e-04, (5/tau)^2: 8.13e+07. For the moment, maybe constant time.
meas:    6.61 M, max t:   +1.38, max tau: 5.37e-04, (5/tau)^2: 8.66e+07. For the moment, maybe constant time.
meas:    5.28 M, max t:   +1.26, max tau: 5.49e-04, (5/tau)^2: 8.30e+07. For the moment, maybe constant time.
meas:    6.80 M, max t:   +1.27, max tau: 4.88e-04, (5/tau)^2: 1.05e+08. For the moment, maybe constant time.
```

## Benchmarking

For benchmarking all instantiations of FrodoKEM keygen/ encaps/ decaps algorithms, issue following command.

```bash
make benchmark  # If you haven't built google-benchmark library with libPFM support.
make perf       # Must do if you have built google-benchmark library with libPFM support.
```

> [!CAUTION]
> When benchmarking, ensure that all your CPU cores are running in performance mode. You may find the guide @ https://github.com/google/benchmark/blob/2dd015df/docs/reducing_variance.md helpful.

> [!NOTE]
> `make perf` - was issued when collecting following benchmark results. Notice, *CYCLES* column, denoting latency of FrodoKEM routines, in terms of CPU cycles h/w event.

### On 12th Gen Intel(R) Core(TM) i7-1260P

Compiled with **gcc version 13.2.0 (Ubuntu 13.2.0-4ubuntu3)**.

```bash
$ uname -srm
Linux 6.5.0-17-generic x86_64
```

```bash
2024-02-11T20:56:26+04:00
Running ./build/perf.out
Run on (16 X 2235.51 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.27, 0.21, 0.27
-----------------------------------------------------------------------------------------------
Benchmark                         Time             CPU   Iterations     CYCLES items_per_second
-----------------------------------------------------------------------------------------------
frodo1344-encaps_mean          6.62 ms         6.62 ms           10   30.4711M        151.067/s
frodo1344-encaps_median        6.62 ms         6.62 ms           10   30.4514M        151.068/s
frodo1344-encaps_stddev       0.019 ms        0.019 ms           10   95.7336k       0.432687/s
frodo1344-encaps_cv            0.29 %          0.29 %            10      0.31%            0.29%
frodo1344-encaps_min           6.59 ms         6.59 ms           10   30.3396M        150.346/s
frodo1344-encaps_max           6.65 ms         6.65 ms           10   30.6488M        151.722/s
efrodo976-decaps_mean          3.51 ms         3.51 ms           10   16.1006M        285.133/s
efrodo976-decaps_median        3.51 ms         3.51 ms           10   16.0825M        285.288/s
efrodo976-decaps_stddev       0.015 ms        0.015 ms           10   68.8345k         1.2265/s
efrodo976-decaps_cv            0.43 %          0.43 %            10      0.43%            0.43%
efrodo976-decaps_min           3.48 ms         3.48 ms           10   15.9793M        283.321/s
efrodo976-decaps_max           3.53 ms         3.53 ms           10   16.2091M        287.518/s
efrodo640-decaps_mean          1.55 ms         1.55 ms           10   7.12353M        643.616/s
efrodo640-decaps_median        1.55 ms         1.55 ms           10   7.12147M        643.999/s
efrodo640-decaps_stddev       0.006 ms        0.006 ms           10   25.6908k         2.4091/s
efrodo640-decaps_cv            0.38 %          0.37 %            10      0.36%            0.37%
efrodo640-decaps_min           1.54 ms         1.54 ms           10   7.07939M        639.377/s
efrodo640-decaps_max           1.56 ms         1.56 ms           10   7.17499M        648.448/s
efrodo976-keygen_mean          3.48 ms         3.48 ms           10   16.2829M        287.503/s
efrodo976-keygen_median        3.48 ms         3.48 ms           10    16.279M         287.55/s
efrodo976-keygen_stddev       0.012 ms        0.012 ms           10    49.513k       0.957008/s
efrodo976-keygen_cv            0.33 %          0.33 %            10      0.30%            0.33%
efrodo976-keygen_min           3.46 ms         3.46 ms           10   16.1973M        285.756/s
efrodo976-keygen_max           3.50 ms         3.50 ms           10   16.3747M        289.112/s
frodo1344-decaps_mean          6.60 ms         6.60 ms           10   30.3498M        151.488/s
frodo1344-decaps_median        6.60 ms         6.60 ms           10   30.3725M        151.415/s
frodo1344-decaps_stddev       0.017 ms        0.017 ms           10   86.6302k       0.391924/s
frodo1344-decaps_cv            0.26 %          0.26 %            10      0.29%            0.26%
frodo1344-decaps_min           6.57 ms         6.57 ms           10    30.174M        151.051/s
frodo1344-decaps_max           6.62 ms         6.62 ms           10    30.461M        152.156/s
frodo640-decaps_mean           1.56 ms         1.56 ms           10    7.1362M        642.162/s
frodo640-decaps_median         1.56 ms         1.56 ms           10   7.13334M        642.333/s
frodo640-decaps_stddev        0.004 ms        0.004 ms           10   21.6827k        1.50606/s
frodo640-decaps_cv             0.23 %          0.23 %            10      0.30%            0.23%
frodo640-decaps_min            1.55 ms         1.55 ms           10   7.10198M        639.988/s
frodo640-decaps_max            1.56 ms         1.56 ms           10   7.17464M        644.212/s
frodo976-decaps_mean           3.52 ms         3.52 ms           10   16.1165M         284.44/s
frodo976-decaps_median         3.51 ms         3.51 ms           10   16.1062M        284.576/s
frodo976-decaps_stddev        0.017 ms        0.016 ms           10   54.1092k        1.33077/s
frodo976-decaps_cv             0.47 %          0.47 %            10      0.34%            0.47%
frodo976-decaps_min            3.49 ms         3.49 ms           10   16.0302M        282.152/s
frodo976-decaps_max            3.54 ms         3.54 ms           10   16.2264M        286.515/s
efrodo640-keygen_mean          1.56 ms         1.56 ms           10   7.29768M        639.509/s
efrodo640-keygen_median        1.56 ms         1.56 ms           10   7.29686M        640.651/s
efrodo640-keygen_stddev       0.010 ms        0.010 ms           10   17.2719k        4.15551/s
efrodo640-keygen_cv            0.66 %          0.66 %            10      0.24%            0.65%
efrodo640-keygen_min           1.56 ms         1.56 ms           10   7.27065M        628.238/s
efrodo640-keygen_max           1.59 ms         1.59 ms           10   7.32187M        643.004/s
frodo976-keygen_mean           3.49 ms         3.49 ms           10   16.3317M        286.152/s
frodo976-keygen_median         3.49 ms         3.49 ms           10   16.3472M        286.174/s
frodo976-keygen_stddev        0.009 ms        0.009 ms           10   78.0192k       0.701863/s
frodo976-keygen_cv             0.25 %          0.25 %            10      0.48%            0.25%
frodo976-keygen_min            3.48 ms         3.48 ms           10   16.1404M        285.107/s
frodo976-keygen_max            3.51 ms         3.51 ms           10   16.4208M        287.108/s
efrodo1344-keygen_mean         6.26 ms         6.26 ms           10   29.2232M        159.801/s
efrodo1344-keygen_median       6.25 ms         6.25 ms           10   29.2266M        160.045/s
efrodo1344-keygen_stddev      0.038 ms        0.038 ms           10   89.8566k        0.95973/s
efrodo1344-keygen_cv           0.61 %          0.61 %            10      0.31%            0.60%
efrodo1344-keygen_min          6.23 ms         6.23 ms           10   29.0581M        157.176/s
efrodo1344-keygen_max          6.36 ms         6.36 ms           10   29.3706M        160.432/s
efrodo1344-decaps_mean         6.59 ms         6.59 ms           10    30.255M        151.683/s
efrodo1344-decaps_median       6.58 ms         6.58 ms           10   30.2235M        151.884/s
efrodo1344-decaps_stddev      0.032 ms        0.032 ms           10   119.694k       0.736086/s
efrodo1344-decaps_cv           0.49 %          0.49 %            10      0.40%            0.49%
efrodo1344-decaps_min          6.55 ms         6.55 ms           10   30.0595M        150.553/s
efrodo1344-decaps_max          6.64 ms         6.64 ms           10   30.4526M        152.673/s
efrodo1344-encaps_mean         6.62 ms         6.62 ms           10   30.3774M        151.013/s
efrodo1344-encaps_median       6.61 ms         6.61 ms           10   30.3647M        151.217/s
efrodo1344-encaps_stddev      0.039 ms        0.039 ms           10   113.925k       0.888824/s
efrodo1344-encaps_cv           0.60 %          0.59 %            10      0.38%            0.59%
efrodo1344-encaps_min          6.58 ms         6.58 ms           10   30.1723M        149.441/s
efrodo1344-encaps_max          6.69 ms         6.69 ms           10   30.5479M         152.05/s
frodo976-encaps_mean           3.54 ms         3.54 ms           10   16.1421M        282.434/s
frodo976-encaps_median         3.53 ms         3.53 ms           10   16.1647M         283.36/s
frodo976-encaps_stddev        0.050 ms        0.048 ms           10   93.7958k        3.77185/s
frodo976-encaps_cv             1.41 %          1.37 %            10      0.58%            1.34%
frodo976-encaps_min            3.50 ms         3.49 ms           10   16.0079M        272.683/s
frodo976-encaps_max            3.67 ms         3.67 ms           10   16.2651M        286.138/s
frodo1344-keygen_mean          6.27 ms         6.27 ms           10   29.1648M        159.567/s
frodo1344-keygen_median        6.26 ms         6.26 ms           10    29.227M        159.802/s
frodo1344-keygen_stddev       0.039 ms        0.039 ms           10   143.248k       0.986201/s
frodo1344-keygen_cv            0.62 %          0.62 %            10      0.49%            0.62%
frodo1344-keygen_min           6.21 ms         6.21 ms           10   28.8626M        157.785/s
frodo1344-keygen_max           6.34 ms         6.34 ms           10   29.2907M        161.026/s
frodo640-encaps_mean           1.57 ms         1.57 ms           10   7.18844M        636.403/s
frodo640-encaps_median         1.57 ms         1.57 ms           10   7.19561M        637.318/s
frodo640-encaps_stddev        0.009 ms        0.009 ms           10   20.6636k        3.73659/s
frodo640-encaps_cv             0.60 %          0.59 %            10      0.29%            0.59%
frodo640-encaps_min            1.56 ms         1.56 ms           10   7.15194M        626.363/s
frodo640-encaps_max            1.60 ms         1.60 ms           10   7.21422M         639.49/s
efrodo976-encaps_mean          3.53 ms         3.53 ms           10   16.1462M        283.676/s
efrodo976-encaps_median        3.53 ms         3.53 ms           10   16.1506M        283.667/s
efrodo976-encaps_stddev       0.018 ms        0.018 ms           10   54.7041k        1.42886/s
efrodo976-encaps_cv            0.51 %          0.51 %            10      0.34%            0.50%
efrodo976-encaps_min           3.50 ms         3.50 ms           10   16.0729M        280.773/s
efrodo976-encaps_max           3.56 ms         3.56 ms           10   16.2216M        285.517/s
frodo640-keygen_mean           1.57 ms         1.57 ms           10   7.29374M        636.722/s
frodo640-keygen_median         1.57 ms         1.57 ms           10   7.28768M        638.414/s
frodo640-keygen_stddev        0.016 ms        0.016 ms           10   29.3617k         6.5475/s
frodo640-keygen_cv             1.04 %          1.04 %            10      0.40%            1.03%
frodo640-keygen_min            1.55 ms         1.55 ms           10    7.2428M        623.181/s
frodo640-keygen_max            1.60 ms         1.60 ms           10    7.3373M        643.374/s
efrodo640-encaps_mean          1.57 ms         1.57 ms           10    7.1777M        638.021/s
efrodo640-encaps_median        1.57 ms         1.57 ms           10   7.17894M        637.668/s
efrodo640-encaps_stddev       0.006 ms        0.006 ms           10   26.5846k        2.40775/s
efrodo640-encaps_cv            0.38 %          0.38 %            10      0.37%            0.38%
efrodo640-encaps_min           1.56 ms         1.56 ms           10    7.1278M        634.345/s
efrodo640-encaps_max           1.58 ms         1.58 ms           10   7.22033M        642.807/s
```

### On ARM Cortex-A72 (i.e. Raspberry Pi 4B)

Compiled with **gcc version 13.2.0 (Ubuntu 13.2.0-4ubuntu3)**.

```bash
$ uname -srm
Linux 6.5.0-1009-raspi aarch64
```

```bash
2024-02-11T22:14:52+04:00
Running ./build/perf.out
Run on (4 X 1800 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x4)
  L1 Instruction 48 KiB (x4)
  L2 Unified 1024 KiB (x1)
Load Average: 1.60, 1.13, 0.77
-----------------------------------------------------------------------------------------------
Benchmark                         Time             CPU   Iterations     CYCLES items_per_second
-----------------------------------------------------------------------------------------------
frodo1344-encaps_mean          47.4 ms         47.4 ms           10   84.6791M        21.1338/s
frodo1344-encaps_median        46.6 ms         46.6 ms           10   83.2982M        21.4695/s
frodo1344-encaps_stddev        1.54 ms         1.54 ms           10   2.71976M       0.663789/s
frodo1344-encaps_cv            3.26 %          3.25 %            10      3.21%            3.14%
frodo1344-encaps_min           45.9 ms         45.9 ms           10   82.0799M        19.8866/s
frodo1344-encaps_max           50.3 ms         50.3 ms           10   89.8951M        21.7879/s
efrodo640-decaps_mean          9.68 ms         9.68 ms           10   17.3376M        103.352/s
efrodo640-decaps_median        9.63 ms         9.63 ms           10   17.2489M        103.866/s
efrodo640-decaps_stddev       0.105 ms        0.103 ms           10   182.922k         1.0873/s
efrodo640-decaps_cv            1.08 %          1.07 %            10      1.06%            1.05%
efrodo640-decaps_min           9.59 ms         9.59 ms           10   17.1955M        100.761/s
efrodo640-decaps_max           9.93 ms         9.92 ms           10   17.7819M        104.234/s
efrodo1344-encaps_mean         47.1 ms         47.1 ms           10   84.1601M        21.2586/s
efrodo1344-encaps_median       46.8 ms         46.7 ms           10   83.5835M        21.3983/s
efrodo1344-encaps_stddev       1.15 ms         1.15 ms           10    2.0118M       0.506047/s
efrodo1344-encaps_cv           2.44 %          2.43 %            10      2.39%            2.38%
efrodo1344-encaps_min          46.0 ms         45.9 ms           10   82.0646M        20.3409/s
efrodo1344-encaps_max          49.2 ms         49.2 ms           10   87.8076M        21.7769/s
frodo1344-decaps_mean          46.8 ms         46.8 ms           10   83.6376M        21.3951/s
frodo1344-decaps_median        46.4 ms         46.4 ms           10   82.9505M        21.5644/s
frodo1344-decaps_stddev        1.15 ms         1.16 ms           10   2.03636M       0.504859/s
frodo1344-decaps_cv            2.45 %          2.47 %            10      2.43%            2.36%
frodo1344-decaps_min           46.0 ms         46.0 ms           10   82.2246M        20.0637/s
frodo1344-decaps_max           49.8 ms         49.8 ms           10   89.0684M        21.7499/s
efrodo640-encaps_mean          9.89 ms         9.89 ms           10    17.709M         101.33/s
efrodo640-encaps_median        9.62 ms         9.62 ms           10   17.2474M        103.942/s
efrodo640-encaps_stddev       0.437 ms        0.437 ms           10   764.988k        4.31709/s
efrodo640-encaps_cv            4.42 %          4.42 %            10      4.32%            4.26%
efrodo640-encaps_min           9.60 ms         9.59 ms           10   17.1873M        94.8031/s
efrodo640-encaps_max           10.6 ms         10.5 ms           10   18.8679M        104.235/s
frodo976-decaps_mean           27.9 ms         27.9 ms           10    49.932M        35.8486/s
frodo976-decaps_median         27.6 ms         27.6 ms           10    49.303M        36.2868/s
frodo976-decaps_stddev        0.770 ms        0.770 ms           10   1.36128M        0.94769/s
frodo976-decaps_cv             2.76 %          2.76 %            10      2.73%            2.64%
frodo976-decaps_min            27.4 ms         27.4 ms           10   49.0373M        33.5564/s
frodo976-decaps_max            29.8 ms         29.8 ms           10   53.2898M          36.49/s
frodo640-keygen_mean           6.90 ms         6.90 ms           10   12.3493M        144.994/s
frodo640-keygen_median         6.85 ms         6.85 ms           10   12.2692M        146.055/s
frodo640-keygen_stddev        0.074 ms        0.074 ms           10   118.811k        1.54981/s
frodo640-keygen_cv             1.07 %          1.07 %            10      0.96%            1.07%
frodo640-keygen_min            6.83 ms         6.83 ms           10   12.2382M        142.624/s
frodo640-keygen_max            7.01 ms         7.01 ms           10   12.5443M        146.386/s
efrodo640-keygen_mean          6.85 ms         6.85 ms           10   12.2714M        145.947/s
efrodo640-keygen_median        6.85 ms         6.84 ms           10   12.2607M        146.097/s
efrodo640-keygen_stddev       0.018 ms        0.016 ms           10   20.1735k       0.335968/s
efrodo640-keygen_cv            0.27 %          0.23 %            10      0.16%            0.23%
efrodo640-keygen_min           6.84 ms         6.84 ms           10   12.2545M        145.342/s
efrodo640-keygen_max           6.88 ms         6.88 ms           10   12.3093M        146.231/s
frodo976-keygen_mean           14.5 ms         14.5 ms           10   25.9959M        68.8309/s
frodo976-keygen_median         14.5 ms         14.5 ms           10   25.9689M        68.9324/s
frodo976-keygen_stddev        0.059 ms        0.057 ms           10   91.1154k       0.270653/s
frodo976-keygen_cv             0.41 %          0.40 %            10      0.35%            0.39%
frodo976-keygen_min            14.5 ms         14.5 ms           10   25.9162M        68.1511/s
frodo976-keygen_max            14.7 ms         14.7 ms           10   26.2227M        69.0961/s
frodo976-encaps_mean           27.6 ms         27.6 ms           10   49.3442M        36.2609/s
frodo976-encaps_median         27.5 ms         27.5 ms           10   49.1757M        36.3873/s
frodo976-encaps_stddev        0.185 ms        0.181 ms           10   308.288k       0.236214/s
frodo976-encaps_cv             0.67 %          0.66 %            10      0.62%            0.65%
frodo976-encaps_min            27.4 ms         27.4 ms           10   49.1213M        35.7161/s
frodo976-encaps_max            28.0 ms         28.0 ms           10   50.0886M        36.4385/s
efrodo1344-decaps_mean         46.8 ms         46.8 ms           10   83.6398M        21.3944/s
efrodo1344-decaps_median       46.4 ms         46.4 ms           10   83.0595M        21.5446/s
efrodo1344-decaps_stddev      0.927 ms        0.927 ms           10   1.62053M       0.411193/s
efrodo1344-decaps_cv           1.98 %          1.98 %            10      1.94%            1.92%
efrodo1344-decaps_min          46.0 ms         46.0 ms           10   82.3521M        20.3773/s
efrodo1344-decaps_max          49.1 ms         49.1 ms           10    87.685M        21.7198/s
frodo640-decaps_mean           9.80 ms         9.80 ms           10   17.5542M         102.19/s
frodo640-decaps_median         9.64 ms         9.63 ms           10   17.2581M        103.812/s
frodo640-decaps_stddev        0.380 ms        0.379 ms           10   667.139k        3.70384/s
frodo640-decaps_cv             3.88 %          3.87 %            10      3.80%            3.62%
frodo640-decaps_min            9.59 ms         9.59 ms           10   17.1901M        93.0409/s
frodo640-decaps_max            10.8 ms         10.7 ms           10   19.2309M        104.302/s
efrodo976-encaps_mean          28.0 ms         28.0 ms           10   50.0138M        35.7767/s
efrodo976-encaps_median        27.8 ms         27.8 ms           10   49.6357M         36.018/s
efrodo976-encaps_stddev       0.624 ms        0.625 ms           10   1.09564M       0.780385/s
efrodo976-encaps_cv            2.23 %          2.24 %            10      2.19%            2.18%
efrodo976-encaps_min           27.5 ms         27.5 ms           10   49.1357M        34.0789/s
efrodo976-encaps_max           29.3 ms         29.3 ms           10   52.4383M        36.4127/s
efrodo976-keygen_mean          14.6 ms         14.6 ms           10   26.0988M        68.5479/s
efrodo976-keygen_median        14.5 ms         14.5 ms           10   26.0037M        68.8383/s
efrodo976-keygen_stddev       0.136 ms        0.134 ms           10   216.209k       0.620174/s
efrodo976-keygen_cv            0.93 %          0.92 %            10      0.83%            0.90%
efrodo976-keygen_min           14.5 ms         14.5 ms           10    25.949M         67.121/s
efrodo976-keygen_max           14.9 ms         14.9 ms           10   26.6001M        68.9562/s
frodo640-encaps_mean           9.86 ms         9.86 ms           10   17.6547M        101.601/s
frodo640-encaps_median         9.62 ms         9.62 ms           10   17.2337M        103.966/s
frodo640-encaps_stddev        0.385 ms        0.386 ms           10   680.556k        3.82278/s
frodo640-encaps_cv             3.91 %          3.91 %            10      3.85%            3.76%
frodo640-encaps_min            9.57 ms         9.57 ms           10   17.1531M        94.0607/s
frodo640-encaps_max            10.6 ms         10.6 ms           10   19.0328M        104.479/s
efrodo976-decaps_mean          27.7 ms         27.7 ms           10   49.5708M         36.111/s
efrodo976-decaps_median        27.4 ms         27.4 ms           10   49.0488M        36.4792/s
efrodo976-decaps_stddev       0.637 ms        0.640 ms           10    1.1341M       0.800265/s
efrodo976-decaps_cv            2.30 %          2.31 %            10      2.29%            2.22%
efrodo976-decaps_min           27.4 ms         27.4 ms           10   49.0179M         34.108/s
efrodo976-decaps_max           29.3 ms         29.3 ms           10   52.4395M        36.5323/s
efrodo1344-keygen_mean         27.5 ms         27.5 ms           10   49.2267M        36.3677/s
efrodo1344-keygen_median       27.5 ms         27.5 ms           10    49.231M        36.3591/s
efrodo1344-keygen_stddev      0.042 ms        0.034 ms           10   42.4153k      0.0451281/s
efrodo1344-keygen_cv           0.15 %          0.12 %            10      0.09%            0.12%
efrodo1344-keygen_min          27.4 ms         27.4 ms           10   49.1579M        36.3173/s
efrodo1344-keygen_max          27.6 ms         27.5 ms           10   49.2842M        36.4382/s
frodo1344-keygen_mean          27.5 ms         27.5 ms           10   49.2686M        36.3289/s
frodo1344-keygen_median        27.5 ms         27.5 ms           10   49.1584M        36.4076/s
frodo1344-keygen_stddev       0.147 ms        0.143 ms           10   215.554k        0.18671/s
frodo1344-keygen_cv            0.53 %          0.52 %            10      0.44%            0.51%
frodo1344-keygen_min           27.4 ms         27.4 ms           10   49.1308M        35.8653/s
frodo1344-keygen_max           27.9 ms         27.9 ms           10   49.8054M        36.4467/s
```

### On Apple M1 Max

Compiled with **Apple clang version 15.0.0 (clang-1500.1.0.2.5)**.

```bash
$ uname -srm
Darwin 23.3.0 arm64
```

```bash
2024-02-10T19:45:50+04:00
Running ./build/bench.out
Run on (10 X 24 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB
  L1 Instruction 128 KiB
  L2 Unified 4096 KiB (x10)
Load Average: 6.99, 4.42, 4.17
------------------------------------------------------------------------------------
Benchmark                         Time             CPU   Iterations items_per_second
------------------------------------------------------------------------------------
frodo1344-decaps_mean          15.4 ms         15.3 ms           10        65.2019/s
frodo1344-decaps_median        15.3 ms         15.3 ms           10        65.4979/s
frodo1344-decaps_stddev       0.180 ms        0.180 ms           10       0.745988/s
frodo1344-decaps_cv            1.17 %          1.17 %            10            1.14%
frodo1344-decaps_min           15.3 ms         15.3 ms           10        63.1579/s
frodo1344-decaps_max           15.9 ms         15.8 ms           10        65.5337/s
frodo1344-encaps_mean          15.3 ms         15.3 ms           10         65.496/s
frodo1344-encaps_median        15.3 ms         15.3 ms           10        65.5554/s
frodo1344-encaps_stddev       0.045 ms        0.043 ms           10       0.184255/s
frodo1344-encaps_cv            0.29 %          0.28 %            10            0.28%
frodo1344-encaps_min           15.3 ms         15.2 ms           10        64.9749/s
frodo1344-encaps_max           15.5 ms         15.4 ms           10        65.5848/s
efrodo640-keygen_mean          2.00 ms         1.99 ms           10        502.681/s
efrodo640-keygen_median        1.99 ms         1.98 ms           10        505.387/s
efrodo640-keygen_stddev       0.032 ms        0.028 ms           10        6.86121/s
efrodo640-keygen_cv            1.62 %          1.41 %            10            1.36%
efrodo640-keygen_min           1.99 ms         1.98 ms           10        483.437/s
efrodo640-keygen_max           2.09 ms         2.07 ms           10        505.442/s
frodo640-decaps_mean           3.65 ms         3.64 ms           10        275.062/s
frodo640-decaps_median         3.64 ms         3.63 ms           10        275.551/s
frodo640-decaps_stddev        0.018 ms        0.016 ms           10        1.20987/s
frodo640-decaps_cv             0.48 %          0.44 %            10            0.44%
frodo640-decaps_min            3.64 ms         3.63 ms           10         271.84/s
frodo640-decaps_max            3.69 ms         3.68 ms           10        275.755/s
efrodo1344-decaps_mean         15.3 ms         15.2 ms           10        65.5787/s
efrodo1344-decaps_median       15.3 ms         15.2 ms           10        65.5991/s
efrodo1344-decaps_stddev      0.023 ms        0.017 ms           10      0.0714561/s
efrodo1344-decaps_cv           0.15 %          0.11 %            10            0.11%
efrodo1344-decaps_min          15.2 ms         15.2 ms           10        65.4398/s
efrodo1344-decaps_max          15.3 ms         15.3 ms           10        65.6402/s
frodo976-keygen_mean           4.07 ms         4.06 ms           10        246.485/s
frodo976-keygen_median         4.07 ms         4.06 ms           10        246.496/s
frodo976-keygen_stddev        0.004 ms        0.002 ms           10       0.148473/s
frodo976-keygen_cv             0.11 %          0.06 %            10            0.06%
frodo976-keygen_min            4.06 ms         4.05 ms           10        246.246/s
frodo976-keygen_max            4.08 ms         4.06 ms           10         246.64/s
frodo640-keygen_mean           1.99 ms         1.98 ms           10        504.964/s
frodo640-keygen_median         1.99 ms         1.98 ms           10        505.631/s
frodo640-keygen_stddev        0.006 ms        0.005 ms           10        1.19111/s
frodo640-keygen_cv             0.32 %          0.24 %            10            0.24%
frodo640-keygen_min            1.98 ms         1.98 ms           10        502.698/s
frodo640-keygen_max            2.00 ms         1.99 ms           10        505.752/s
efrodo1344-keygen_mean         7.59 ms         7.56 ms           10        132.279/s
efrodo1344-keygen_median       7.58 ms         7.55 ms           10        132.416/s
efrodo1344-keygen_stddev      0.027 ms        0.025 ms           10       0.431867/s
efrodo1344-keygen_cv           0.35 %          0.33 %            10            0.33%
efrodo1344-keygen_min          7.55 ms         7.55 ms           10         131.07/s
efrodo1344-keygen_max          7.65 ms         7.63 ms           10         132.49/s
frodo976-decaps_mean           5.54 ms         5.52 ms           10        181.069/s
frodo976-decaps_median         5.53 ms         5.51 ms           10        181.368/s
frodo976-decaps_stddev        0.026 ms        0.015 ms           10        0.48885/s
frodo976-decaps_cv             0.47 %          0.27 %            10            0.27%
frodo976-decaps_min            5.51 ms         5.51 ms           10        179.991/s
frodo976-decaps_max            5.59 ms         5.56 ms           10        181.432/s
efrodo640-encaps_mean          3.66 ms         3.64 ms           10        274.572/s
efrodo640-encaps_median        3.65 ms         3.64 ms           10        274.841/s
efrodo640-encaps_stddev       0.013 ms        0.012 ms           10       0.868905/s
efrodo640-encaps_cv            0.34 %          0.32 %            10            0.32%
efrodo640-encaps_min           3.64 ms         3.64 ms           10        272.149/s
efrodo640-encaps_max           3.69 ms         3.67 ms           10        275.082/s
frodo1344-keygen_mean          7.61 ms         7.58 ms           10        131.971/s
frodo1344-keygen_median        7.58 ms         7.55 ms           10        132.449/s
frodo1344-keygen_stddev       0.052 ms        0.054 ms           10       0.929096/s
frodo1344-keygen_cv            0.68 %          0.71 %            10            0.70%
frodo1344-keygen_min           7.57 ms         7.55 ms           10        129.565/s
frodo1344-keygen_max           7.74 ms         7.72 ms           10        132.477/s
efrodo1344-encaps_mean         15.3 ms         15.3 ms           10        65.4314/s
efrodo1344-encaps_median       15.3 ms         15.3 ms           10        65.5241/s
efrodo1344-encaps_stddev      0.048 ms        0.052 ms           10       0.221589/s
efrodo1344-encaps_cv           0.32 %          0.34 %            10            0.34%
efrodo1344-encaps_min          15.3 ms         15.3 ms           10        64.8406/s
efrodo1344-encaps_max          15.5 ms         15.4 ms           10        65.5518/s
frodo976-encaps_mean           5.55 ms         5.53 ms           10        180.743/s
frodo976-encaps_median         5.55 ms         5.53 ms           10        180.809/s
frodo976-encaps_stddev        0.007 ms        0.005 ms           10        0.16868/s
frodo976-encaps_cv             0.13 %          0.09 %            10            0.09%
frodo976-encaps_min            5.54 ms         5.53 ms           10         180.28/s
frodo976-encaps_max            5.57 ms         5.55 ms           10        180.854/s
efrodo640-decaps_mean          3.67 ms         3.65 ms           10        274.383/s
efrodo640-decaps_median        3.64 ms         3.63 ms           10         275.68/s
efrodo640-decaps_stddev       0.088 ms        0.045 ms           10        3.26627/s
efrodo640-decaps_cv            2.39 %          1.22 %            10            1.19%
efrodo640-decaps_min           3.64 ms         3.63 ms           10        265.425/s
efrodo640-decaps_max           3.92 ms         3.77 ms           10        275.755/s
frodo640-encaps_mean           3.65 ms         3.64 ms           10        274.956/s
frodo640-encaps_median         3.65 ms         3.63 ms           10         275.11/s
frodo640-encaps_stddev        0.008 ms        0.004 ms           10        0.31175/s
frodo640-encaps_cv             0.22 %          0.11 %            10            0.11%
frodo640-encaps_min            3.64 ms         3.63 ms           10        274.123/s
frodo640-encaps_max            3.66 ms         3.65 ms           10        275.136/s
efrodo976-encaps_mean          5.59 ms         5.56 ms           10        179.794/s
efrodo976-encaps_median        5.56 ms         5.53 ms           10        180.765/s
efrodo976-encaps_stddev       0.096 ms        0.077 ms           10        2.42502/s
efrodo976-encaps_cv            1.71 %          1.39 %            10            1.35%
efrodo976-encaps_min           5.55 ms         5.53 ms           10        173.032/s
efrodo976-encaps_max           5.86 ms         5.78 ms           10        180.831/s
efrodo976-keygen_mean          4.07 ms         4.06 ms           10        246.432/s
efrodo976-keygen_median        4.07 ms         4.05 ms           10        246.648/s
efrodo976-keygen_stddev       0.014 ms        0.007 ms           10       0.402812/s
efrodo976-keygen_cv            0.35 %          0.16 %            10            0.16%
efrodo976-keygen_min           4.05 ms         4.05 ms           10        245.645/s
efrodo976-keygen_max           4.10 ms         4.07 ms           10        246.734/s
efrodo976-decaps_mean          5.56 ms         5.53 ms           10        180.721/s
efrodo976-decaps_median        5.53 ms         5.51 ms           10        181.336/s
efrodo976-decaps_stddev       0.076 ms        0.061 ms           10        1.93287/s
efrodo976-decaps_cv            1.36 %          1.10 %            10            1.07%
efrodo976-decaps_min           5.53 ms         5.51 ms           10        175.226/s
efrodo976-decaps_max           5.77 ms         5.71 ms           10        181.439/s
```

## Usage

FrodoKEM is a header-only C++20 library, which is fairly easy to use.

- Clone the repository.
- Import dependencies, by enabling git submodule.

```bash
# First clone the repository, and then
pushd frodokem
git submodule update --init
popd
```

- Write programs, which makes use of FrodoKEM API, by including proper header file(s), living inside `./include` directory, using functions/ constants from proper namespace.

Interested in using ? | Then include | Namespace of interest
:-- | --: | --:
Frodo-640 KEM | `include/frodo640_kem.hpp` | `frodo640_kem::`
Frodo-976 KEM | `include/frodo976_kem.hpp` | `frodo976_kem::`
Frodo-1344 KEM | `include/frodo1344_kem.hpp` | `frodo1344_kem::`
eFrodo-640 KEM | `include/efrodo640_kem.hpp` | `efrodo640_kem::`
eFrodo-976 KEM | `include/efrodo976_kem.hpp` | `efrodo976_kem::`
eFrodo-1344 KEM | `include/efrodo1344_kem.hpp` | `efrodo1344_kem::`

- Finally compile your program, while letting your compiler know where it can find FrodoKEM headers ( `./include` ), along with `sha3` ( `./sha3/include` ) and `subtle` ( `./subtle/include` ) header files.

---

Let's see how to use Frodo-640 KEM API.

1) First, generate a public/ private keypair, using seeds. Key generation routine takes following three seeds.

- 16 -bytes seed `s`
- 32 -byte seed `seedSE`
- 16 -bytes seed `z`

```cpp
#include "frodo640_kem.hpp"
#include <vector>
#include <span>

int
main()
{
  constexpr size_t S_LEN = 16;
  constexpr size_t SEED_SE_LEN = 32;
  constexpr size_t Z_LEN = 16;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(frodo640_kem::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo640_kem::SEC_KEY_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, frodo640_kem::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo640_kem::SEC_KEY_LEN> _skey{ skey };

  // Pseudo-random number generator
  prng::prng_t prng;

  prng.read(_s);
  prng.read(_seedSE);
  prng.read(_z);

  frodo640_kem::keygen(_s, _seedSE, _z, _pkey, _skey);

  // ...
}
```

2) Let's now try to encapsulate a 16 -bytes shared secret using recipient's public key, producing a cipher text, which can be shared with the recipient. Encapsulation routine takes two other inputs too.

- A 16 -bytes key `μ`
- And a 32 -bytes `salt`

> **Note** 
In case you're trying to use eFrodoKEM-{640, 976, 1344} API, you'll notice that it doesn't take a salt as input during key encapsulation. That is only required if you're using FrodoKEM in static settings, not in ephemeral one.

```cpp
int
main()
{
  // Key generation
  // ...

  constexpr size_t μ_LEN = 16;
  constexpr size_t SALT_LEN = 32;
  constexpr size_t SS_LEN = 16;

  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> salt(SALT_LEN, 0);
  std::vector<uint8_t> ss0(SS_LEN, 0);
  std::vector<uint8_t> cipher(frodo640_kem::CIPHER_LEN, 0);

  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, SALT_LEN> _salt{ salt };
  std::span<uint8_t, SS_LEN> _ss0{ ss0 };
  std::span<uint8_t, frodo640_kem::CIPHER_LEN> _cipher{ cipher };

  prng.read(_μ);
  prng.read(_salt);

  frodo640_kem::encaps(_μ, _salt, _pkey, _cipher, _ss0);

  // ...
}
```

3) Finally recipient has the cipher text ( and its secret key, obviously ) which can now be decapsulated, computing 16 -bytes shared secret, which the sending party also arrived at. This shared secret can now be used for encrypting their communication with symmetric key constructions, say [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) schemes.

```cpp
// ...
#include <algorithm>
#include <cassert>

int
main()
{
  // Key generation
  // ...

  // Encapsulation
  // ...

  std::vector<uint8_t> ss1(SS_LEN, 0);
  std::span<uint8_t, SS_LEN> _ss1{ ss1 };

  frodo640_kem::decaps(_skey, _cipher, _ss1);

  // ensure that both parties arrived at same shared secret !
  assert(std::ranges::equal(_ss0, _ss1));
  return 0;
}
```

I keep example programs demonstrating usage of {e}FrodoKEM-640 API in the [./examples](./examples/) directory. You may go through them for better understanding of Frodo KEM API surface.

```bash
$ g++ -std=c++20 -O3 -march=native -Wall -I include -I sha3/include -I subtle/include examples/frodo640_kem.cpp && ./a.out

Frodo-640 KEM

Public Key    : 646348792d425d1171a5252c8d3ffa49119ee9a3cbca78c7bdcccb6743146ea369a81b13450434b089c06d77947106be649abb1129b2023a87db083c8837b2fe69a722a1b0391d2c4b295a9b08e7e2b0cacbc31320819e30dd139db85de0e78126c15ca426b150bc6ec9b43928562eb67358b99c6d3076f507192f61f3a364e8530bbda3669ffc8b30965e94fcd7a1acb65c7c9f3ad344561c0c3879a5a2a76633f40fd1cb2e1e4d9a5f6064f3ab9c5b87397caf522ffd10ec00073dc053cbb6535cd0aac901331364cb2f6ea00361e74a86364d06a07c0eba7a99f351848bfbc1eb4953d183d8d301c8f35562e324c302a58f380c7569ec30d9cb58b955902fa869f15e17f74ae52590242330886640c92913559f8f73e791a44be5caaf40a94d3cf1c54b1f3b0bd19507b14a27f083007021d313c10c94150b0ae73d36f7d2bbbf097d68248753ce53fe1c677eb2aa0790bdca2bad197622ce6859e87192685d9772b1b9ef8b49e2d3930a2050b25aac8bcbcb249375bc07f78bf73fedc7a3155db1bd1a1000a9ddb385fc072fd8d6d3e8cbd2f4888784a5544265d045b425da586f74a125d5f9b3995457b03597c9668016d35b14d3e586895dadbcc17cba8fa7c18d8ad8548ccc35721c3213010dbd20159a1a2467e820984cfc4130a68c9a91c41e5f740ea38150eefc6478d63ada37c277d39019ad5846f83423a9b4803a777107f60a1b8a3f9bce18bca76bc3963cc5bf2e0287eb62f08b7645902a762eb35255a37f4a39b7b1daf25c0f9cf0336dbb6370ca5c84a4e9d815bdee9ddcdb9915cad439215050b5e8bfa9685bc84a2ea6a2b458deb1646a7d5e64e4ad33f01c7f0152504e9da458c2af0cc02d9efbb401adc1427bdc5b7d76e8e42ec4fd685421c6a201814811a33184a3dd884d960cd3219887a5193d1c15ada5556d9704a362e582e77065611936d2ac0526628a4f96f4fa022cf7851ad81fd5ea95770eedcc8a9f5d9df9311de818a02c4655e2442af3646f6865a8ccc5e5dfeeec18fa2f59005d8a76213379117fda808d0368a2658a9fd2a69b6daf80f64a82a50ddeef29915cb815b58c0a76068b7094aae04d099ea09c5497a7b2f3a39fd01a255e38079f73ced92469225555096ec481077454cbf840c1f968929d157682e1e96b0ce9b61278912ed25521a86bc11339370e4d5f01fad64e4a77798ea45b3b24009b7c2744d131758db54269b7436b9b981a2834f126067f3d204aa5483f5862c25160984415becd08d37b85834557d5bdd7c9fd57fedc88b70ebc499baf9e4a6cac0978dfe93ed67134bf329b84c27b8ca5cddda8bb94bcc367133983b5d0cd6a0fe97bb8cbe4f883d70be0776d154578ff39387ba7527d785a8cbc053c47b40b10eb15d6157278dc094dd0eaaa320960b4bde764a2bb933bd9c8a8bfc11cbdb84f8fcaed325e887fa07032b190172a1945f972af9cbef18127c2afbbb7159e03bedd42376b61f100216b8dbb9c453bf13ee04b5e096ec48a97514426e5e7b05e4c639debed61b1e9194e583724e5cfae91f467177ea09d8ce612ed76397dced3ce4ab48427967cc9d923c2ac6301886ebc75a3208dbfb3daedfd50f88b850b3580098f9106bb4f1d3aea3338f6e045305c0ded9224848021fb0e900442250e7761ddfd41ac456263bcae46074fcb3bcd8a34d4d54157d876fd385e53575a087dd66e1052737e5a1d4d39752317d38f39beb2613d10c9fb91ba4510dc6ff05693575a43134447d1dae6d3feb50e4adf940155972ba1d5e15a03843d8d3c665260988e0b9e44e2adcc2c73e9b0af399c2b1d55826e9ea167b411542cd33f1d89881e9fa706f58fc24287298f4b91fc57b5b1ac4e8578a0e0d7238f66c79a87f2d045d3fe29561259e683dd8d58b5ca3fe6888a93850cbffe8815e25c03c5f28ed1d47f7adc1f0cc93c5cdae4c5b2b682de541fd86c453007f27b89c6872864fff189b79149b72ea272c9cdd7c64623ad6b79204d2c223146174c9fd4d4e341cc5e5ad31a264b92b1fe09111edd9f5443dbdc85415b9546a8224a7d31fd4b975e22dc0d01a88a23ec1632bf91587c4b8ce3c95951e4e1c39f23221f2e95459b90c86cf6875a6c64be7972d868d96d306af84a8e85f7c0a4cc6fd08829a776cd489c5ab8750aa409efa3b37c6a9729794c7f192ad4896c9d53381a87518a48d84699f8d0a12dfb9ce6689587865ce3b245965df68b67a5a1e39d7a1ecf3dd1ba4a8f4a3f07d0206d438c41bd5bc4b23f2f2dde475d147db5940f23dc1bb897b54f9d38f4c6da615df3a9234e9465c6f99e73fedb158729eb0af138297b7fbf3ff9161b0956cf2bcc84333615388c2253d551061005ffc7f9572daeb6282c6d216fa3590eac8a48c379891776230472cded6da404c0a828df13cee3189605fff24d4e72226259f6d90b8c51c14693e3c966383f60df9964837abb0298c8b26d786b36196f348f6f267c21b34d0a89aa3ac983aa517023c2f9e7108a2a8fd30f03750f3d793b241a3ee80a6d65ca16227e74810ba193188c7464179e16ac1681758a71514923a8515327bccab98074f77a791fc429a94e66453f514b66ed9efb08139bae27d0c10dd1d85122fb4aba555c2928d75b828083eb4d1c4e86300c44332a453f824fe5c9adc69aad138b742f7c40c04c83fab9beac766818775a62d7cb6b0f683e3802cbd6276397326d5c3949a78a8f391186f358976c8231ed94ae1c7235f04ca635b0cd4c7aecb80df60ae335c5963bab7bcf4c6936e49613b6b6726a6deada0639f2ed141e55d94f171b1bc22d1468e9f6a5d1a6b0c00938290a4e3a8ed102300e4a28fa5088a762d3782da6032093885d01c94aff812f95373bf801478446a9dbd7fed9a92dcda6fe2e93d820a2aa9ffcdb3b768951c2e091e350bdb5a6cc6583561a2bd31444d558dddf1316b006ce9dbb61c57a7831ac99a0ff694339fd1037f8202da457d58a01a4881678559b4aa92805fe829214b8e4f170505d3885bfcd842524df955e976b2afc4d536bc1a4a65517683cd431a9dd272ee518e8424cd4d5929621a0239e746c37760b2f10dfa98365ee9e4bdd7e8024da54a61ade27dab78b9bd0236c75c8a908692981149347e881f2baaceedc01c26ac272cbe9c4daabdec86f02ab2b6120da4a11213eceb0e2d7791d34dd997085f4aa280d141f379b294f3a86cd24045802b883efdc81cd3e71ab9619ec98f307d990239a5ed931c83aa18cd5a76832eab6d06f5ef9f299e82de2a17fc339b01334d2cee0b7efe73977528a2b72f7474d05799149faba3c0d759c3839721163082003f7925fb5100081f332716ab30e0414daccbf64577a8ffcaea9c307ef29c8c2749c2b478a10ac21c129b180dc53ff402596c71542e316fb23fec567beb83481f92314727fbb66c0bed3615ffa5a151f30a8efa9660b5b4d766f8cf3f10d7f2f330c1b6a0c7976f007f48fc7b7998e8dc5574ad5f7b519d9fae0a93bd791153675cdd6971ab0af098e11b77be4ade90e76537d9791bf5aa33dac31586743707729191de3d5463e8ba6daeb30b6b0d8ab98ae7b13f9d783ae6beb0114fa8e5f13da3421dfefac5039f64eaa0acd0e59c1e55c7c1f2ad300d8b2c36fe87d438153ed709d5a9e486ebb9d51be3adb26da623ff2ff2bcf18c9e0435322cf915dc181061c64947949a897e39e41a2741c5071fe0cb053f00acfe583f830adefffdfdba48e0caadcae01eecc356935ab413ffc60cabc18e2c8ea7987d635027562295358a99db0069f24fb155244bd5112ece4d442f56e8dd99cf6ad9da9891f11d181d234051c64ba2fc05f3b97916a3f5d5131266992aa12bc50dfb9bd60202989035d0586081485661f9ea6a6669030998b937bbf2a634b8b0a0650639c683b1c1db0a873a24fcf5aa97c215ad709df79a24b29b87a009e5c813cade160d4210c31c9aa0716c76bbf49065396ce254f8227abfabe1b4ed51f9e4420c3e158f638b74fc0d4af0ca9e23a0d13b19cd9e385d1daf5af774759b51d8466a2bdb6298169724434ebaa7f9fb179f8ede5924196fc5be919f0ea2c7823df334f1dd62610b4f9e33815638b3f5ec678aa7df8142aa97dea538983a31244a10d84fa7d70181b3a76ff48f717c9fd313bcaf2e67bfe7e9af1ebbffc16318e89b570eb33b953994c1c48d10ce1dee35cae46c47f7165021d00d5bf58bc9cdff7026b8eb9a7ad2a530c3fa2b71995b16a89f3f779279d78acfcc62ee54014b322881822cf9281b9c3e4a52e21bf568e5250b58e00248e8786c122410fdcfe6652538bd7ac6266e9a2b92186552ecf3164636d67d63998e18fc543090d16557354e0da68ddba3dec1b17c56b6db99eb5fc91c316fb2e34e85428804cc73deea0b235d4d814439d7b3b6146f4772c7c8a2119ddd26c596c610375d43e33fb2f649e09d4dd2d3bd3ccb4921fc9ced8c3d368d23d2530a023c9f602a962641dce3c7832945eace9485d6556ab6c93097372268bf7cb9e6be8494faa5102bdc336da7150fb440fc0d0eb85485515602175dd8d9fabd0c67bff62a0ca04dfdfee8bcafcbb5f1005a7d5bf7b5ca620d237daefd0559b0412b9e3ee4c5c1f3cde50d59eaa4f7f35f583eaed1af87d0a8ff6666ebd668657682b9bb0482d559ecc9983ecd4aa9cfa3a0b512eac25cc37aed8728b38954ae7700a05777a5979c031a456124596443cd0f72bb3176b08a8c689e8c195f43bf951e48907a1fffe81d484eb0205e21db666c23aaa3493da69397a2ab14160e6cac657df7785b6926cc7122f7e3d80fbb5fc4bca2c65e966000d2d1c072394369cba82eb9cd988eba5bf0ea401e71b42bb3fdfe8bdc6e0f26bb6a2d87cfd9f6f531818037c57d35066e74669f1b89ccb4ca22519ac95cceac37955e0ff55ff1ca3bd9cb248826b3de7b1da0f48598551e1f71a23adb6a4984d931aaa5c62cdd8c20b36cbc1d4f03a1336724f8a4547395208c3926956e4d4eff24f21c537fef4813055aeb7b8afccb66bec8e23cd5c4e120adf0843c578c37ae926ea428bca9b87c32fe88f04edc599a83d5107ab7d4a48372e52dba097783fd1d4cbcc73ad1d715fea55900cd4916f3310a7519ae7c6cb418afba5e610a3eb22cdbe44f5c91891d044779af12c68bc74c02ed2b2a64109c98e0391b9a00a2aaf1c18ad3145bff267aa15699806534dd8e31ac5b7a03c8345c3ef6a939a478e3a7ca949eb440ca9755899536efa5c3ede950ce02101f69a428567024214df3276564de7fa2045d1ec4c71bac433054c370b31d06a6e19e0d173b2cc4f0000195d41933f508d0add2f38849b45123d48a9c00327091438148c8059082ce2d3ce3f9afde1dea1acc21b681278b16600b4546f1b9ef2c2bbadbecbfc7b8c9366f853a9e14dfe1d6898c8fd1bb42518d3eed66411787dec59c1d11baeed714ad6373f36480ff379141769310635e1a1ec80ff70caacdbacd798ddc372cd7d2553cf362372e16dc0cf034b937bd0ddfc5755303cbb4406f66b113fd154e3464df92bb47de38b77cdc95e773bbae3f975921f2a7216321bf518c7610a048a45faa53db2fb68a17a996ade9ffbee2bdc7fb6dbac2f37c3ee4348fe9e09d979130bca1301a0274f608b791e9c01225185d2b9a6ee90b6b41d4b7a9e60edf5275582190d4d9b08bd40cc3e9d893320cb036b84aea91803c3d592bd319501a3f6b86c2b5bfd5233e9b54c2e991fab463039f6cb85879a13dda78421110eadfb1dd3494dbc90359b1bc8cf93c92314ba02fec1638caea1bc02879c8d0e5754ade07177354901200078be96d64dc51ffb6d634abc7f2528103a1f47285505adab976a589938dc9ac9959d73d048cbef2afab12618c9a57e0b6ce6d58870ad0d5eed8e77ef41b219d8bff06ca7f5b5158f2728e4d311a35f4803b62b6dd3a0f49dccba03216dcbc0eaa96c13dad9d7d894777613a596009f410021e6b78b0de126e5e9772b7d3bb2dac23619faef5c558e44c2f990aa538365a6ae2e1d83b02929b7f4f2a4abcbed8dd6153918ebae883150bca4e820ccb445cd47a733ab42fdc37b56fc08046f7aca4c69d63902424ef77e41a27b4ca0693bb1e69d06fb63e17b7286259de684cecd7744bb30f82c4499dac3868cbaf7b677b388f7500be80dbbc02426372901cf66c27280dfe74d420fe1b67c94a208a6549ea5d6df4011b513daf5f4c1f84cb39a1d467e2011b1c1cc3ce336a7616543bf866e76e393fd2ba693871393d08d8f00b5bfd26bee4492db49fff2e496805c0da4226f775af127444d6fc5de5b9d4c32ccbf7bdf5928ac8fff7e28eb5b502c10ff2437f53df4657e985d6a0f38ce6f76cf5e410217ff16aa728ca4f5baa1f2c90ec649469eeba0e3f3f8964349321865f84997849ce3e9c6cf7e6e3b7fc5e376c1950b2556b506d844db799749f03e93c3c898e7b5d8a079ed5756f6378d38ceb7f8142cac469cf8a2ec1006edcb4c9110571b57da577f57c1be80f99580d8aa32c38723342bc341438e8930b024c1c7aa00ce1a7579deaf68651dd2d307863d16fafe4896e89db778944f7170b341b4115ae11a39a85a0f822eab45e11174c9915c79d08189b2457e5e78b2153868e1b20b327df182042f1ea74cc01861f036112438cffb3e1c5b2af4d995056e757389369e52d4aa234cb2968c059ba5a193857ee1d0dc99e210cdb0865badf4d5d1c5e6a4f0f5407f134ca18805fa1ac16355ed19badda65a4e2dbe5118f3aca8ac147dc3bdd318779e44ee490e187ce76a3c2523749cfd4d771d4bef98946819a1d04e1ecf8fca053be32303a48f9d409da2d20d384d1aaa23fed14ced459bdf38b03faa10d05002c9bfb81da7747b0871db1ae52b0e6d69220d4cfb6351b3071a8a5c107bdcd06dd70d04b445a5237be1e92e5ef65e4d94b1f7693930368bc86e3ba38613b3456b1ea3d24fe016ebdedef73ea453ada21f85468460be58287a222056a72e87387fba7eb1941e3fde98152eb713f87459e62d70a3177c26372fe5a9d78398fd522f128d2c9b4ee27670e9d8760b7534f61cf31e828195fb160de04b73a2f0b6e5400d655e7e2b05cc3d50a496ad7097fc4a25e2e5339d105296eefc32c2e227ad994a5aa48d231af143d34c4b19489c55a6ac5d501b5f92953fdcd150f162c88b25189ab9dcf68674f0e3f7ecec329671287939b7ed4a842051b89fce01f8a55a8facce5820ee62375fca135fe8f82bb15c31e21efd6d142c46f53163d23354e6ac1b9b07228469616cb7dc9ba077f4f3ed2dd2f063c5e3c23a35ce4aecf03adae589442c8b706c90a0374c41151089f0177793cf2c5802f63b8e62011ba3ab2dda0a03e80f0dbdc9a7d91224c7072ebe6a8e5728ca5108afee66bb12fc14044ed4d5c1aeb7ff602d61b2c6b887c1ef6cbc6c0920b0aeb6f1fe454fd44b263cbfdd730b086fd73a7b3a0040bebfd78dc3c7456c54d560bc62de4ca822e46c26af576b8d5333f478e27e4234a26795899cb50cb7bc6635bb803cf60f923033000847ad355001b77c4b4b52859c3b81551bcf636939826a53e987e9eabfa12b3196701c9bd24c7f8a1d0223a0072620a579b122717acfaf72beb1ec8415769f0c245c68ac94f619a399d2d773e8816120c9e342158f91f90bc2af2c417e6221322fabb79e50ec88269b7f0670231016e1bf56861d231d5b8e5aa491863e28610512af47a413455cdc4d3425a7680f43b257b55d7de0803966fc3d65e498bb2a3f711954b8c28e7d45aff0244f8ba66fb2e95bc074f5473bbcf31195eda7e91c41f4d50b2f83afdd40dd377ff723cb45cf0ab53e6f00e2a20ea02b9629f96cb5f1ba50b71b3c86c1944ebc96d298d90db3e7785c49e2cd0a8532358ed815ffbc808372094b88f58c0db7494a33fb7564e9b2f93e8a0e115d8282aa71ac76a11f4c51aadbfb3dad467f2a6c8cdd56927eec137cf1dd9a532b783e0f866935aedacf96cd4c7d0d056c688d5863bc265b74903b9108e19d19ee6b15f9c95929ab64ca596acd0753b987f39620fe9735e5aaa4856305eb328755188e09f3bf3d85a4f0dd078156926d46be9f77013f4db0a1ee83bbfefa17e01176fb8560d065de45cfbd1e8336be62b3108c026d1e765c7c34f2cf5a39e88a72e97f6b331ead87ecc4bcca3a4ed1ae6b1ad845549e558d83568bd2be1efe254a9ee5a9aa405c80cc4e8f96ea03cb054e9bc969a91526d18507eda3abab3a3f8f96696494ae51957f0ea4b055011dd262e5288017ce2e41a13c6bb4ee3958c0208fdeceb5ea0691d65ffd3747408f8f2b18c60e9b50efd455ac2f6f0b0f3bf224127a3e2a59931b950846e10f9f08eb5e8955d4421a84a34e43898ca68f9a2ae0fa572fde0c556896fb741600ac1e5682af4a5bb3d67a367c814bd0ccc8e43a00fcf9de1710b422110d9aa2f9d8a9693f894cedd6700e597b4f8158d79c457365effcd44e060c9949a6bf78f3d8b365c975ad0c6275de364de4070a33df7fd88772eac4aab68de9ca12ae1aad5fa596976a288e3963b81007e35c6af1e55bd932ad0548586aadd172a306e289421e624b4115cf4aa2fd4e92cd6763984a7006ab45ddf67632e956d353c585dc8711aca316f27d234ebe19f780a8400b38861bff784a1aab785fa7c7e72453d5d35b0b786b59049da1848df5c636eecaa127731170b4f539562961ccce6ea2e61f7da21c0ec605a5ad4c13e96788f64cf1ba2e51fd44d05114c5337b3844f166cfc6b74d13c12add07911598abdeefa2ee723c44867042e14a620cdb878fd527a81a963f10330e9d7fb7a935ee398aa5a3fefa2a405c93882d9b9c0b9bb62611c824dad71473b5e13a2c5897172af0e189b1e3bc95e4925ce879edd1661c1462bcfc036c985515154e842eff0741ddfdb9426d8b92b18c537d5c8e96b20cedba8e46c5b3e30978d132393f358359b964a6583ee82db781ce7bf47c877d83237dd80be849a9fb5183a9e769c13f6fa42fffa02b7e66a6fb4236f680757b053526d70658b37de1b4e09c3399aa044f1e61821fe3ac5c02e1a8df78d625d4745a01812622f2af53b42d2dd7b7989379f855bfeca19fab37bb78d6d4829fcdbb81ce1975d34c8ee0a974f2b5b82a374bd56468e46b529a7f8aa761359bd1c38c599786182b3f4f0c94f6c2f0668d93a97ea7d9bd3f78f5b4e816468c84261a5e5beb63aa56bc5f4ba47f2918ba336f912743f554b66a836c9be5492b5b8f019bd384eeb00bd55dce3deb63011753dd47b73153106fdf6fe8864ea3e3928484645f676a727bb12f87fbe5889e568d1e8a85acd9385ec358d93131a8c5f2c86a7d43e811c00be1fc676c8a75f0143a03eeae54e47fd8edab7d10a4f27da33e1690218a6bd6354e66caec8cedeaa4c7b165be48a2333a0d87916a2c9fa0b6ed102f0edf3887283bb9f80c3817ae0358a0478364025d10be33d44d798df9d0cdb5891a748fb525ef8e02ac9e571e3322f35cb38e7633e6e8e00ee7bea80d58ae02c7b5230443e9390c9dd01183630b82ba6b552c6516242a3b6089c0fefd8473b9b8695b85d49a3106c1e03b554ac5c3c3af67d460c1bd2318184488a19b78e99226c71de0caf78871e9e3a0bc6ef1ff6ff1d7a450cfcc580ff187d4350fa84434da0805cd446a7fa4c85616ee3eee4c0a8e7b4801d0bdf855fca7d92f0e96f298cac958ea6629e3011fa5b4f746533e5b11a5c9f076fd4742831849230451ecad594af773abf4f8fe1c4d310446badeef2b1863f34530fb4998a859015b1edd56fc995dbe02d7737543b51f3dd99beefda6516747dc2e12d37eb6dee29efa7c3e9345e6b677ffee3bec42da96b2403c5c5f54bd770219bdfd3cef3f7026775a27119a6ea3045cca287e6be892bcdf8fb6304dc688150ea7b4a0d261781c108e4e060044cce2fda679180de854b318d3db1830d8c807ddaccc6325eee48ab533dc37064814148ebba0d99443819def76892feb09f96a0c0338d014b4db9e3117b8ce16051e3c8672f97a2cd7d7efdd41bb24745d843e0495755596da1c78f52706cc4605f5e17bd1d7a77b60a7f8a36af1f28d1161f240b55b0447fbcc42b638b145b6ce8b2eb55e706ea2afc3168dc7b8c6f3d854d100f435de883245facc1a6381fd4fde66402cb5f3ea397dc387cac8e74a0ce577c98d8324b6737a9054badc66ec734ef45415ddf258b7158ef87893f95ebd590af50a0a22db09ce4fcdca29db52722c13a2f44cf3db9c611c035eaf358df4d5fc0bc50f71bf5d57f70a7484fe51518c5244d9215643d6c2b1f0f22ba8691e7132296cbe4ebe099e272350e26209642dd38650b1150a1ab21609bd26c59b4bfd23f130caef9df217060905749bb0b319152ecfb6c97f1ee16d1b39bf06dc03702396ef4ebf010e9823e0eb01c1024d5eb1e33620a230cca0ab7593fc04ba4217e9111816c0d4a2d4ed8205c7ac6f623ef9ed3af492be6624609969b61127c191965b345b836a2125c705fd5e906cb13b60cb04dfa7abca3615df724d21a16664291205f216575d56f1f1bdd2f12553239c65647e492002a5b059f1298d75e9c572f1a34d73faace492f8927f927faf072b0a8cd6d2e8b957adb12d2e7bbe63c4376aa80f1dfa3115070cf343f07a6fd02bd5816cc57968da0c5c723443ec1f2729ac1d30794f58ac4abf0e6b78dd110e86828bfd141a39f00e142c9f7bdd369267693121cdb4496c72cf9d39f168783b18b63fefa59b39d5db610a77c759db774a19208838e4da3606517d2464cdd7a473ed1a2840320f8fb27e61f6fb0e273e47d8ad3b33b9d3197952b757b97d752eee1a2ccd59799401f8e19824eb66a36d249d99b9eadbf6dc1ef7b64dad646fbc737b484077d69900555ca7da509685a4b4d385e9a2c19de7ca9ff6eee41ac35ee2522d1580725bec2be8ddcb93fefb15673de18890637f966af3cfb3c4e847fadeb6087b500e970b31632ca249f1912443e325a7f5de54ac9e7205d2a9f73e05effe9308068a87e2a4d9612b6ba95dc8e88387140e05044a5a58850cb2a97fc8b641ffcd7ee6ac127fec428cac8cdc22b372ab3e6c0b934b161ac8231668fdea8f624d6ae8dff25e1fb12335b3208a39621c3d61d4c7968d1a8411abe4e4d59f940644a357f9b89f886948e4f23c9df35537b3f9ae3d028bc29f7bbc44beb88ae4a3db537ddb3c7feba751610ee82331b933d8393bfee563631ec5dabb2f07cbadd91a2df5b4fd7e12c54adfc3babae29399d4e301bce0792de0402a268ffc83dc150340c6ff34fa2d2bdb69e18cbd67597c2454ef275a6877c171d2b923beca07eb7470117748fd5fe5ac4f45904f168acfadf098862f83b7fa7a2e093d03cc3468135c5f45dc76bec6882d55aabf54ab0d82f51396dba5b50080893c1673992f30b185dd1e5ab79274bdfc8071e13093afd20224942c887024abf98d1133040dc9f420f7a23baa440067cb5cfe45b87a761fd882ec3dc00f0e264da114a49dc6799d3b60e223e00d1e5af39d8dac7160db91677a86b0348ce45422ac947045dcd7257ed795c04c7178abca9a7dbbbe29b47628f243b0015ddad61ca7d4b5e185189bea6edfeddd3828a155468b222654118331cc681d3cadcedc60230c7e747695e84e4ed21468845a7b5728357f6bca59af7263f452a34de6e3767d3edfd3eaf4b3888214c2696216dfc27b694371de0abc2c817e3a5e609a8a870b1bc2ce01fa547f18eacec248711db2175597db478435e4cb7103882010cde9db525bf7852ed21979bf5aa4bc7db4cfa8c91416ec8d9f41e548962f4f308b29c256a9c4131018abacdf90d4939cf2c5b22bc7f94d413981218fdff2ac767cd4f69ed82a93ff8fda981b4bcf9133a53249681479714463646875bac2311709de460772d4fafc9629c2147a5d28e875267381d96185036a731ea10028bea9cba94d851e6a766323a4c3bd18fff20d6a6f32d1040db9fa8547a62fcfc2292b3afe094267ca8c70ea6f7fe812b54979d8113ed34940f81cdbaf456f4726e2622e1da07abb6cc4ebd639a87c0a7167ffc0cfa6914263a01dc8c284b9f473475b86157403842ccd93142efe171c00a730f090f38f371b22af32857908e3496eb3fee252c4738b6a0b071fe083a354da305e4d10806ccfa5d23a3adf3e3d55dcdb838b90382408ae94231c9bc1ab002e8b22f65e9d1293a36ca55b07a5f17c673b75b6b0c7d75e4d325d9c448baf39b976a5456bee391f22f7dd044909a0d22fb2819e31cde11fd1722a10642552bfb2b31c6c6835d16bf34608722e8dea214be8cc1211657596a63b61b1778b3c53f407255f1bc55d9c9b4e739b16bf4d4e3028d7ed6c8c6184788a6b206baefa4d8111bf6087d57f1863b7f7517cdab2e5a4a708aaa23620df7b970fba29373ffefb47fb147a83817e0adb8ad266de4b12e8c3c278053e0dabb641d1aed5450f9e75a48b543637ac86beb277c97949cf197cb05c0d7c2d84497b8846bfb3acbb892a91a59794f3f86261cfa911987b0a04bad451ff67f5897b63d9a010db87e48094365bb7ebd4999eab40f2f0bf8b2f66371812c9e7b37e0780dc006688418ea80710fd1c0582eaa22eaa67c3a89f499bf7d09d5f74e23395b365ff5f1646549cddcc4495b8de5d5e6a965b5d0623b30215ead7f0ad104d8c3e66cd68b22dd862aee69d9635edad2517b82090bb656bfae4083101131de7a1b17cf54d4d38f9e09fe99698101e9fc44927ed47a3ccb8f18e81763627d037ecfd05464f70403507af064f0fd0b927ae464d35b5a4800927dceeda24959145e630060d58563cbb77366238fbd8571b55a4d6d0037903bce2e004ffeaa2acae3f3ad30980ac47503ff25a3cc157c4f4bc472a9dfcc8b6a807e4c9fe8e452abf115ef1d3382f8206a61a8a9d412e43313cb2561679e735c340c0acdd039c741b191accecca69474a81fad8680b8fc8b086f683d80e9e29bd3a18a444d3311f5af85b9b1bafc332fa2ac43daaa16464fda989989ebbc35f7df515a47d73dd9e408f7b69a38e24a6b1809f5db224fc53487598b6708eaaefccaed1561f623e660045f12ff704965ad7a7b3634ad8a203a9364d0d0411ce5412798f93d3d840f63a9c9731e18af3dbcb0e97bd9191a422002cd12904dc1fe8e1e4cfe9b981d7d97f849eec08d0e3854562ea599d5b2104bb4acc2e6dee4b33b6318ac5f07163d3e932340bf8afb85b278ef152ded3d104ac0e9e8bc62fec535a37a729d8fe8fce1e159ec7fcdd6a194f46343144cd99575e1aee100eb0f9f045d5417a4076119ecb6dc349de5a7f441063a991b73a7c839fdf21094de72a15e1776fbccd9dc881c14e5b85253dec082c5ce58dc7739cde8c7ef665dea4f238b8ad904858b46a8ad093e4477a764dcb89aeb053c92da3667639be9288036c858469d76048fe5f9a2a83ef7c8794d74ed0034ef5df77fef79ba3a7d01da6232193d2bb0aafe63255e50fcf187892e80e2f498b3f8dd67f737aaab2d3663351fb13c6f04d67a23187be471b
Secret Key    : 2c51ba7939a4b99767a2b75990698032646348792d425d1171a5252c8d3ffa49119ee9a3cbca78c7bdcccb6743146ea369a81b13450434b089c06d77947106be649abb1129b2023a87db083c8837b2fe69a722a1b0391d2c4b295a9b08e7e2b0cacbc31320819e30dd139db85de0e78126c15ca426b150bc6ec9b43928562eb67358b99c6d3076f507192f61f3a364e8530bbda3669ffc8b30965e94fcd7a1acb65c7c9f3ad344561c0c3879a5a2a76633f40fd1cb2e1e4d9a5f6064f3ab9c5b87397caf522ffd10ec00073dc053cbb6535cd0aac901331364cb2f6ea00361e74a86364d06a07c0eba7a99f351848bfbc1eb4953d183d8d301c8f35562e324c302a58f380c7569ec30d9cb58b955902fa869f15e17f74ae52590242330886640c92913559f8f73e791a44be5caaf40a94d3cf1c54b1f3b0bd19507b14a27f083007021d313c10c94150b0ae73d36f7d2bbbf097d68248753ce53fe1c677eb2aa0790bdca2bad197622ce6859e87192685d9772b1b9ef8b49e2d3930a2050b25aac8bcbcb249375bc07f78bf73fedc7a3155db1bd1a1000a9ddb385fc072fd8d6d3e8cbd2f4888784a5544265d045b425da586f74a125d5f9b3995457b03597c9668016d35b14d3e586895dadbcc17cba8fa7c18d8ad8548ccc35721c3213010dbd20159a1a2467e820984cfc4130a68c9a91c41e5f740ea38150eefc6478d63ada37c277d39019ad5846f83423a9b4803a777107f60a1b8a3f9bce18bca76bc3963cc5bf2e0287eb62f08b7645902a762eb35255a37f4a39b7b1daf25c0f9cf0336dbb6370ca5c84a4e9d815bdee9ddcdb9915cad439215050b5e8bfa9685bc84a2ea6a2b458deb1646a7d5e64e4ad33f01c7f0152504e9da458c2af0cc02d9efbb401adc1427bdc5b7d76e8e42ec4fd685421c6a201814811a33184a3dd884d960cd3219887a5193d1c15ada5556d9704a362e582e77065611936d2ac0526628a4f96f4fa022cf7851ad81fd5ea95770eedcc8a9f5d9df9311de818a02c4655e2442af3646f6865a8ccc5e5dfeeec18fa2f59005d8a76213379117fda808d0368a2658a9fd2a69b6daf80f64a82a50ddeef29915cb815b58c0a76068b7094aae04d099ea09c5497a7b2f3a39fd01a255e38079f73ced92469225555096ec481077454cbf840c1f968929d157682e1e96b0ce9b61278912ed25521a86bc11339370e4d5f01fad64e4a77798ea45b3b24009b7c2744d131758db54269b7436b9b981a2834f126067f3d204aa5483f5862c25160984415becd08d37b85834557d5bdd7c9fd57fedc88b70ebc499baf9e4a6cac0978dfe93ed67134bf329b84c27b8ca5cddda8bb94bcc367133983b5d0cd6a0fe97bb8cbe4f883d70be0776d154578ff39387ba7527d785a8cbc053c47b40b10eb15d6157278dc094dd0eaaa320960b4bde764a2bb933bd9c8a8bfc11cbdb84f8fcaed325e887fa07032b190172a1945f972af9cbef18127c2afbbb7159e03bedd42376b61f100216b8dbb9c453bf13ee04b5e096ec48a97514426e5e7b05e4c639debed61b1e9194e583724e5cfae91f467177ea09d8ce612ed76397dced3ce4ab48427967cc9d923c2ac6301886ebc75a3208dbfb3daedfd50f88b850b3580098f9106bb4f1d3aea3338f6e045305c0ded9224848021fb0e900442250e7761ddfd41ac456263bcae46074fcb3bcd8a34d4d54157d876fd385e53575a087dd66e1052737e5a1d4d39752317d38f39beb2613d10c9fb91ba4510dc6ff05693575a43134447d1dae6d3feb50e4adf940155972ba1d5e15a03843d8d3c665260988e0b9e44e2adcc2c73e9b0af399c2b1d55826e9ea167b411542cd33f1d89881e9fa706f58fc24287298f4b91fc57b5b1ac4e8578a0e0d7238f66c79a87f2d045d3fe29561259e683dd8d58b5ca3fe6888a93850cbffe8815e25c03c5f28ed1d47f7adc1f0cc93c5cdae4c5b2b682de541fd86c453007f27b89c6872864fff189b79149b72ea272c9cdd7c64623ad6b79204d2c223146174c9fd4d4e341cc5e5ad31a264b92b1fe09111edd9f5443dbdc85415b9546a8224a7d31fd4b975e22dc0d01a88a23ec1632bf91587c4b8ce3c95951e4e1c39f23221f2e95459b90c86cf6875a6c64be7972d868d96d306af84a8e85f7c0a4cc6fd08829a776cd489c5ab8750aa409efa3b37c6a9729794c7f192ad4896c9d53381a87518a48d84699f8d0a12dfb9ce6689587865ce3b245965df68b67a5a1e39d7a1ecf3dd1ba4a8f4a3f07d0206d438c41bd5bc4b23f2f2dde475d147db5940f23dc1bb897b54f9d38f4c6da615df3a9234e9465c6f99e73fedb158729eb0af138297b7fbf3ff9161b0956cf2bcc84333615388c2253d551061005ffc7f9572daeb6282c6d216fa3590eac8a48c379891776230472cded6da404c0a828df13cee3189605fff24d4e72226259f6d90b8c51c14693e3c966383f60df9964837abb0298c8b26d786b36196f348f6f267c21b34d0a89aa3ac983aa517023c2f9e7108a2a8fd30f03750f3d793b241a3ee80a6d65ca16227e74810ba193188c7464179e16ac1681758a71514923a8515327bccab98074f77a791fc429a94e66453f514b66ed9efb08139bae27d0c10dd1d85122fb4aba555c2928d75b828083eb4d1c4e86300c44332a453f824fe5c9adc69aad138b742f7c40c04c83fab9beac766818775a62d7cb6b0f683e3802cbd6276397326d5c3949a78a8f391186f358976c8231ed94ae1c7235f04ca635b0cd4c7aecb80df60ae335c5963bab7bcf4c6936e49613b6b6726a6deada0639f2ed141e55d94f171b1bc22d1468e9f6a5d1a6b0c00938290a4e3a8ed102300e4a28fa5088a762d3782da6032093885d01c94aff812f95373bf801478446a9dbd7fed9a92dcda6fe2e93d820a2aa9ffcdb3b768951c2e091e350bdb5a6cc6583561a2bd31444d558dddf1316b006ce9dbb61c57a7831ac99a0ff694339fd1037f8202da457d58a01a4881678559b4aa92805fe829214b8e4f170505d3885bfcd842524df955e976b2afc4d536bc1a4a65517683cd431a9dd272ee518e8424cd4d5929621a0239e746c37760b2f10dfa98365ee9e4bdd7e8024da54a61ade27dab78b9bd0236c75c8a908692981149347e881f2baaceedc01c26ac272cbe9c4daabdec86f02ab2b6120da4a11213eceb0e2d7791d34dd997085f4aa280d141f379b294f3a86cd24045802b883efdc81cd3e71ab9619ec98f307d990239a5ed931c83aa18cd5a76832eab6d06f5ef9f299e82de2a17fc339b01334d2cee0b7efe73977528a2b72f7474d05799149faba3c0d759c3839721163082003f7925fb5100081f332716ab30e0414daccbf64577a8ffcaea9c307ef29c8c2749c2b478a10ac21c129b180dc53ff402596c71542e316fb23fec567beb83481f92314727fbb66c0bed3615ffa5a151f30a8efa9660b5b4d766f8cf3f10d7f2f330c1b6a0c7976f007f48fc7b7998e8dc5574ad5f7b519d9fae0a93bd791153675cdd6971ab0af098e11b77be4ade90e76537d9791bf5aa33dac31586743707729191de3d5463e8ba6daeb30b6b0d8ab98ae7b13f9d783ae6beb0114fa8e5f13da3421dfefac5039f64eaa0acd0e59c1e55c7c1f2ad300d8b2c36fe87d438153ed709d5a9e486ebb9d51be3adb26da623ff2ff2bcf18c9e0435322cf915dc181061c64947949a897e39e41a2741c5071fe0cb053f00acfe583f830adefffdfdba48e0caadcae01eecc356935ab413ffc60cabc18e2c8ea7987d635027562295358a99db0069f24fb155244bd5112ece4d442f56e8dd99cf6ad9da9891f11d181d234051c64ba2fc05f3b97916a3f5d5131266992aa12bc50dfb9bd60202989035d0586081485661f9ea6a6669030998b937bbf2a634b8b0a0650639c683b1c1db0a873a24fcf5aa97c215ad709df79a24b29b87a009e5c813cade160d4210c31c9aa0716c76bbf49065396ce254f8227abfabe1b4ed51f9e4420c3e158f638b74fc0d4af0ca9e23a0d13b19cd9e385d1daf5af774759b51d8466a2bdb6298169724434ebaa7f9fb179f8ede5924196fc5be919f0ea2c7823df334f1dd62610b4f9e33815638b3f5ec678aa7df8142aa97dea538983a31244a10d84fa7d70181b3a76ff48f717c9fd313bcaf2e67bfe7e9af1ebbffc16318e89b570eb33b953994c1c48d10ce1dee35cae46c47f7165021d00d5bf58bc9cdff7026b8eb9a7ad2a530c3fa2b71995b16a89f3f779279d78acfcc62ee54014b322881822cf9281b9c3e4a52e21bf568e5250b58e00248e8786c122410fdcfe6652538bd7ac6266e9a2b92186552ecf3164636d67d63998e18fc543090d16557354e0da68ddba3dec1b17c56b6db99eb5fc91c316fb2e34e85428804cc73deea0b235d4d814439d7b3b6146f4772c7c8a2119ddd26c596c610375d43e33fb2f649e09d4dd2d3bd3ccb4921fc9ced8c3d368d23d2530a023c9f602a962641dce3c7832945eace9485d6556ab6c93097372268bf7cb9e6be8494faa5102bdc336da7150fb440fc0d0eb85485515602175dd8d9fabd0c67bff62a0ca04dfdfee8bcafcbb5f1005a7d5bf7b5ca620d237daefd0559b0412b9e3ee4c5c1f3cde50d59eaa4f7f35f583eaed1af87d0a8ff6666ebd668657682b9bb0482d559ecc9983ecd4aa9cfa3a0b512eac25cc37aed8728b38954ae7700a05777a5979c031a456124596443cd0f72bb3176b08a8c689e8c195f43bf951e48907a1fffe81d484eb0205e21db666c23aaa3493da69397a2ab14160e6cac657df7785b6926cc7122f7e3d80fbb5fc4bca2c65e966000d2d1c072394369cba82eb9cd988eba5bf0ea401e71b42bb3fdfe8bdc6e0f26bb6a2d87cfd9f6f531818037c57d35066e74669f1b89ccb4ca22519ac95cceac37955e0ff55ff1ca3bd9cb248826b3de7b1da0f48598551e1f71a23adb6a4984d931aaa5c62cdd8c20b36cbc1d4f03a1336724f8a4547395208c3926956e4d4eff24f21c537fef4813055aeb7b8afccb66bec8e23cd5c4e120adf0843c578c37ae926ea428bca9b87c32fe88f04edc599a83d5107ab7d4a48372e52dba097783fd1d4cbcc73ad1d715fea55900cd4916f3310a7519ae7c6cb418afba5e610a3eb22cdbe44f5c91891d044779af12c68bc74c02ed2b2a64109c98e0391b9a00a2aaf1c18ad3145bff267aa15699806534dd8e31ac5b7a03c8345c3ef6a939a478e3a7ca949eb440ca9755899536efa5c3ede950ce02101f69a428567024214df3276564de7fa2045d1ec4c71bac433054c370b31d06a6e19e0d173b2cc4f0000195d41933f508d0add2f38849b45123d48a9c00327091438148c8059082ce2d3ce3f9afde1dea1acc21b681278b16600b4546f1b9ef2c2bbadbecbfc7b8c9366f853a9e14dfe1d6898c8fd1bb42518d3eed66411787dec59c1d11baeed714ad6373f36480ff379141769310635e1a1ec80ff70caacdbacd798ddc372cd7d2553cf362372e16dc0cf034b937bd0ddfc5755303cbb4406f66b113fd154e3464df92bb47de38b77cdc95e773bbae3f975921f2a7216321bf518c7610a048a45faa53db2fb68a17a996ade9ffbee2bdc7fb6dbac2f37c3ee4348fe9e09d979130bca1301a0274f608b791e9c01225185d2b9a6ee90b6b41d4b7a9e60edf5275582190d4d9b08bd40cc3e9d893320cb036b84aea91803c3d592bd319501a3f6b86c2b5bfd5233e9b54c2e991fab463039f6cb85879a13dda78421110eadfb1dd3494dbc90359b1bc8cf93c92314ba02fec1638caea1bc02879c8d0e5754ade07177354901200078be96d64dc51ffb6d634abc7f2528103a1f47285505adab976a589938dc9ac9959d73d048cbef2afab12618c9a57e0b6ce6d58870ad0d5eed8e77ef41b219d8bff06ca7f5b5158f2728e4d311a35f4803b62b6dd3a0f49dccba03216dcbc0eaa96c13dad9d7d894777613a596009f410021e6b78b0de126e5e9772b7d3bb2dac23619faef5c558e44c2f990aa538365a6ae2e1d83b02929b7f4f2a4abcbed8dd6153918ebae883150bca4e820ccb445cd47a733ab42fdc37b56fc08046f7aca4c69d63902424ef77e41a27b4ca0693bb1e69d06fb63e17b7286259de684cecd7744bb30f82c4499dac3868cbaf7b677b388f7500be80dbbc02426372901cf66c27280dfe74d420fe1b67c94a208a6549ea5d6df4011b513daf5f4c1f84cb39a1d467e2011b1c1cc3ce336a7616543bf866e76e393fd2ba693871393d08d8f00b5bfd26bee4492db49fff2e496805c0da4226f775af127444d6fc5de5b9d4c32ccbf7bdf5928ac8fff7e28eb5b502c10ff2437f53df4657e985d6a0f38ce6f76cf5e410217ff16aa728ca4f5baa1f2c90ec649469eeba0e3f3f8964349321865f84997849ce3e9c6cf7e6e3b7fc5e376c1950b2556b506d844db799749f03e93c3c898e7b5d8a079ed5756f6378d38ceb7f8142cac469cf8a2ec1006edcb4c9110571b57da577f57c1be80f99580d8aa32c38723342bc341438e8930b024c1c7aa00ce1a7579deaf68651dd2d307863d16fafe4896e89db778944f7170b341b4115ae11a39a85a0f822eab45e11174c9915c79d08189b2457e5e78b2153868e1b20b327df182042f1ea74cc01861f036112438cffb3e1c5b2af4d995056e757389369e52d4aa234cb2968c059ba5a193857ee1d0dc99e210cdb0865badf4d5d1c5e6a4f0f5407f134ca18805fa1ac16355ed19badda65a4e2dbe5118f3aca8ac147dc3bdd318779e44ee490e187ce76a3c2523749cfd4d771d4bef98946819a1d04e1ecf8fca053be32303a48f9d409da2d20d384d1aaa23fed14ced459bdf38b03faa10d05002c9bfb81da7747b0871db1ae52b0e6d69220d4cfb6351b3071a8a5c107bdcd06dd70d04b445a5237be1e92e5ef65e4d94b1f7693930368bc86e3ba38613b3456b1ea3d24fe016ebdedef73ea453ada21f85468460be58287a222056a72e87387fba7eb1941e3fde98152eb713f87459e62d70a3177c26372fe5a9d78398fd522f128d2c9b4ee27670e9d8760b7534f61cf31e828195fb160de04b73a2f0b6e5400d655e7e2b05cc3d50a496ad7097fc4a25e2e5339d105296eefc32c2e227ad994a5aa48d231af143d34c4b19489c55a6ac5d501b5f92953fdcd150f162c88b25189ab9dcf68674f0e3f7ecec329671287939b7ed4a842051b89fce01f8a55a8facce5820ee62375fca135fe8f82bb15c31e21efd6d142c46f53163d23354e6ac1b9b07228469616cb7dc9ba077f4f3ed2dd2f063c5e3c23a35ce4aecf03adae589442c8b706c90a0374c41151089f0177793cf2c5802f63b8e62011ba3ab2dda0a03e80f0dbdc9a7d91224c7072ebe6a8e5728ca5108afee66bb12fc14044ed4d5c1aeb7ff602d61b2c6b887c1ef6cbc6c0920b0aeb6f1fe454fd44b263cbfdd730b086fd73a7b3a0040bebfd78dc3c7456c54d560bc62de4ca822e46c26af576b8d5333f478e27e4234a26795899cb50cb7bc6635bb803cf60f923033000847ad355001b77c4b4b52859c3b81551bcf636939826a53e987e9eabfa12b3196701c9bd24c7f8a1d0223a0072620a579b122717acfaf72beb1ec8415769f0c245c68ac94f619a399d2d773e8816120c9e342158f91f90bc2af2c417e6221322fabb79e50ec88269b7f0670231016e1bf56861d231d5b8e5aa491863e28610512af47a413455cdc4d3425a7680f43b257b55d7de0803966fc3d65e498bb2a3f711954b8c28e7d45aff0244f8ba66fb2e95bc074f5473bbcf31195eda7e91c41f4d50b2f83afdd40dd377ff723cb45cf0ab53e6f00e2a20ea02b9629f96cb5f1ba50b71b3c86c1944ebc96d298d90db3e7785c49e2cd0a8532358ed815ffbc808372094b88f58c0db7494a33fb7564e9b2f93e8a0e115d8282aa71ac76a11f4c51aadbfb3dad467f2a6c8cdd56927eec137cf1dd9a532b783e0f866935aedacf96cd4c7d0d056c688d5863bc265b74903b9108e19d19ee6b15f9c95929ab64ca596acd0753b987f39620fe9735e5aaa4856305eb328755188e09f3bf3d85a4f0dd078156926d46be9f77013f4db0a1ee83bbfefa17e01176fb8560d065de45cfbd1e8336be62b3108c026d1e765c7c34f2cf5a39e88a72e97f6b331ead87ecc4bcca3a4ed1ae6b1ad845549e558d83568bd2be1efe254a9ee5a9aa405c80cc4e8f96ea03cb054e9bc969a91526d18507eda3abab3a3f8f96696494ae51957f0ea4b055011dd262e5288017ce2e41a13c6bb4ee3958c0208fdeceb5ea0691d65ffd3747408f8f2b18c60e9b50efd455ac2f6f0b0f3bf224127a3e2a59931b950846e10f9f08eb5e8955d4421a84a34e43898ca68f9a2ae0fa572fde0c556896fb741600ac1e5682af4a5bb3d67a367c814bd0ccc8e43a00fcf9de1710b422110d9aa2f9d8a9693f894cedd6700e597b4f8158d79c457365effcd44e060c9949a6bf78f3d8b365c975ad0c6275de364de4070a33df7fd88772eac4aab68de9ca12ae1aad5fa596976a288e3963b81007e35c6af1e55bd932ad0548586aadd172a306e289421e624b4115cf4aa2fd4e92cd6763984a7006ab45ddf67632e956d353c585dc8711aca316f27d234ebe19f780a8400b38861bff784a1aab785fa7c7e72453d5d35b0b786b59049da1848df5c636eecaa127731170b4f539562961ccce6ea2e61f7da21c0ec605a5ad4c13e96788f64cf1ba2e51fd44d05114c5337b3844f166cfc6b74d13c12add07911598abdeefa2ee723c44867042e14a620cdb878fd527a81a963f10330e9d7fb7a935ee398aa5a3fefa2a405c93882d9b9c0b9bb62611c824dad71473b5e13a2c5897172af0e189b1e3bc95e4925ce879edd1661c1462bcfc036c985515154e842eff0741ddfdb9426d8b92b18c537d5c8e96b20cedba8e46c5b3e30978d132393f358359b964a6583ee82db781ce7bf47c877d83237dd80be849a9fb5183a9e769c13f6fa42fffa02b7e66a6fb4236f680757b053526d70658b37de1b4e09c3399aa044f1e61821fe3ac5c02e1a8df78d625d4745a01812622f2af53b42d2dd7b7989379f855bfeca19fab37bb78d6d4829fcdbb81ce1975d34c8ee0a974f2b5b82a374bd56468e46b529a7f8aa761359bd1c38c599786182b3f4f0c94f6c2f0668d93a97ea7d9bd3f78f5b4e816468c84261a5e5beb63aa56bc5f4ba47f2918ba336f912743f554b66a836c9be5492b5b8f019bd384eeb00bd55dce3deb63011753dd47b73153106fdf6fe8864ea3e3928484645f676a727bb12f87fbe5889e568d1e8a85acd9385ec358d93131a8c5f2c86a7d43e811c00be1fc676c8a75f0143a03eeae54e47fd8edab7d10a4f27da33e1690218a6bd6354e66caec8cedeaa4c7b165be48a2333a0d87916a2c9fa0b6ed102f0edf3887283bb9f80c3817ae0358a0478364025d10be33d44d798df9d0cdb5891a748fb525ef8e02ac9e571e3322f35cb38e7633e6e8e00ee7bea80d58ae02c7b5230443e9390c9dd01183630b82ba6b552c6516242a3b6089c0fefd8473b9b8695b85d49a3106c1e03b554ac5c3c3af67d460c1bd2318184488a19b78e99226c71de0caf78871e9e3a0bc6ef1ff6ff1d7a450cfcc580ff187d4350fa84434da0805cd446a7fa4c85616ee3eee4c0a8e7b4801d0bdf855fca7d92f0e96f298cac958ea6629e3011fa5b4f746533e5b11a5c9f076fd4742831849230451ecad594af773abf4f8fe1c4d310446badeef2b1863f34530fb4998a859015b1edd56fc995dbe02d7737543b51f3dd99beefda6516747dc2e12d37eb6dee29efa7c3e9345e6b677ffee3bec42da96b2403c5c5f54bd770219bdfd3cef3f7026775a27119a6ea3045cca287e6be892bcdf8fb6304dc688150ea7b4a0d261781c108e4e060044cce2fda679180de854b318d3db1830d8c807ddaccc6325eee48ab533dc37064814148ebba0d99443819def76892feb09f96a0c0338d014b4db9e3117b8ce16051e3c8672f97a2cd7d7efdd41bb24745d843e0495755596da1c78f52706cc4605f5e17bd1d7a77b60a7f8a36af1f28d1161f240b55b0447fbcc42b638b145b6ce8b2eb55e706ea2afc3168dc7b8c6f3d854d100f435de883245facc1a6381fd4fde66402cb5f3ea397dc387cac8e74a0ce577c98d8324b6737a9054badc66ec734ef45415ddf258b7158ef87893f95ebd590af50a0a22db09ce4fcdca29db52722c13a2f44cf3db9c611c035eaf358df4d5fc0bc50f71bf5d57f70a7484fe51518c5244d9215643d6c2b1f0f22ba8691e7132296cbe4ebe099e272350e26209642dd38650b1150a1ab21609bd26c59b4bfd23f130caef9df217060905749bb0b319152ecfb6c97f1ee16d1b39bf06dc03702396ef4ebf010e9823e0eb01c1024d5eb1e33620a230cca0ab7593fc04ba4217e9111816c0d4a2d4ed8205c7ac6f623ef9ed3af492be6624609969b61127c191965b345b836a2125c705fd5e906cb13b60cb04dfa7abca3615df724d21a16664291205f216575d56f1f1bdd2f12553239c65647e492002a5b059f1298d75e9c572f1a34d73faace492f8927f927faf072b0a8cd6d2e8b957adb12d2e7bbe63c4376aa80f1dfa3115070cf343f07a6fd02bd5816cc57968da0c5c723443ec1f2729ac1d30794f58ac4abf0e6b78dd110e86828bfd141a39f00e142c9f7bdd369267693121cdb4496c72cf9d39f168783b18b63fefa59b39d5db610a77c759db774a19208838e4da3606517d2464cdd7a473ed1a2840320f8fb27e61f6fb0e273e47d8ad3b33b9d3197952b757b97d752eee1a2ccd59799401f8e19824eb66a36d249d99b9eadbf6dc1ef7b64dad646fbc737b484077d69900555ca7da509685a4b4d385e9a2c19de7ca9ff6eee41ac35ee2522d1580725bec2be8ddcb93fefb15673de18890637f966af3cfb3c4e847fadeb6087b500e970b31632ca249f1912443e325a7f5de54ac9e7205d2a9f73e05effe9308068a87e2a4d9612b6ba95dc8e88387140e05044a5a58850cb2a97fc8b641ffcd7ee6ac127fec428cac8cdc22b372ab3e6c0b934b161ac8231668fdea8f624d6ae8dff25e1fb12335b3208a39621c3d61d4c7968d1a8411abe4e4d59f940644a357f9b89f886948e4f23c9df35537b3f9ae3d028bc29f7bbc44beb88ae4a3db537ddb3c7feba751610ee82331b933d8393bfee563631ec5dabb2f07cbadd91a2df5b4fd7e12c54adfc3babae29399d4e301bce0792de0402a268ffc83dc150340c6ff34fa2d2bdb69e18cbd67597c2454ef275a6877c171d2b923beca07eb7470117748fd5fe5ac4f45904f168acfadf098862f83b7fa7a2e093d03cc3468135c5f45dc76bec6882d55aabf54ab0d82f51396dba5b50080893c1673992f30b185dd1e5ab79274bdfc8071e13093afd20224942c887024abf98d1133040dc9f420f7a23baa440067cb5cfe45b87a761fd882ec3dc00f0e264da114a49dc6799d3b60e223e00d1e5af39d8dac7160db91677a86b0348ce45422ac947045dcd7257ed795c04c7178abca9a7dbbbe29b47628f243b0015ddad61ca7d4b5e185189bea6edfeddd3828a155468b222654118331cc681d3cadcedc60230c7e747695e84e4ed21468845a7b5728357f6bca59af7263f452a34de6e3767d3edfd3eaf4b3888214c2696216dfc27b694371de0abc2c817e3a5e609a8a870b1bc2ce01fa547f18eacec248711db2175597db478435e4cb7103882010cde9db525bf7852ed21979bf5aa4bc7db4cfa8c91416ec8d9f41e548962f4f308b29c256a9c4131018abacdf90d4939cf2c5b22bc7f94d413981218fdff2ac767cd4f69ed82a93ff8fda981b4bcf9133a53249681479714463646875bac2311709de460772d4fafc9629c2147a5d28e875267381d96185036a731ea10028bea9cba94d851e6a766323a4c3bd18fff20d6a6f32d1040db9fa8547a62fcfc2292b3afe094267ca8c70ea6f7fe812b54979d8113ed34940f81cdbaf456f4726e2622e1da07abb6cc4ebd639a87c0a7167ffc0cfa6914263a01dc8c284b9f473475b86157403842ccd93142efe171c00a730f090f38f371b22af32857908e3496eb3fee252c4738b6a0b071fe083a354da305e4d10806ccfa5d23a3adf3e3d55dcdb838b90382408ae94231c9bc1ab002e8b22f65e9d1293a36ca55b07a5f17c673b75b6b0c7d75e4d325d9c448baf39b976a5456bee391f22f7dd044909a0d22fb2819e31cde11fd1722a10642552bfb2b31c6c6835d16bf34608722e8dea214be8cc1211657596a63b61b1778b3c53f407255f1bc55d9c9b4e739b16bf4d4e3028d7ed6c8c6184788a6b206baefa4d8111bf6087d57f1863b7f7517cdab2e5a4a708aaa23620df7b970fba29373ffefb47fb147a83817e0adb8ad266de4b12e8c3c278053e0dabb641d1aed5450f9e75a48b543637ac86beb277c97949cf197cb05c0d7c2d84497b8846bfb3acbb892a91a59794f3f86261cfa911987b0a04bad451ff67f5897b63d9a010db87e48094365bb7ebd4999eab40f2f0bf8b2f66371812c9e7b37e0780dc006688418ea80710fd1c0582eaa22eaa67c3a89f499bf7d09d5f74e23395b365ff5f1646549cddcc4495b8de5d5e6a965b5d0623b30215ead7f0ad104d8c3e66cd68b22dd862aee69d9635edad2517b82090bb656bfae4083101131de7a1b17cf54d4d38f9e09fe99698101e9fc44927ed47a3ccb8f18e81763627d037ecfd05464f70403507af064f0fd0b927ae464d35b5a4800927dceeda24959145e630060d58563cbb77366238fbd8571b55a4d6d0037903bce2e004ffeaa2acae3f3ad30980ac47503ff25a3cc157c4f4bc472a9dfcc8b6a807e4c9fe8e452abf115ef1d3382f8206a61a8a9d412e43313cb2561679e735c340c0acdd039c741b191accecca69474a81fad8680b8fc8b086f683d80e9e29bd3a18a444d3311f5af85b9b1bafc332fa2ac43daaa16464fda989989ebbc35f7df515a47d73dd9e408f7b69a38e24a6b1809f5db224fc53487598b6708eaaefccaed1561f623e660045f12ff704965ad7a7b3634ad8a203a9364d0d0411ce5412798f93d3d840f63a9c9731e18af3dbcb0e97bd9191a422002cd12904dc1fe8e1e4cfe9b981d7d97f849eec08d0e3854562ea599d5b2104bb4acc2e6dee4b33b6318ac5f07163d3e932340bf8afb85b278ef152ded3d104ac0e9e8bc62fec535a37a729d8fe8fce1e159ec7fcdd6a194f46343144cd99575e1aee100eb0f9f045d5417a4076119ecb6dc349de5a7f441063a991b73a7c839fdf21094de72a15e1776fbccd9dc881c14e5b85253dec082c5ce58dc7739cde8c7ef665dea4f238b8ad904858b46a8ad093e4477a764dcb89aeb053c92da3667639be9288036c858469d76048fe5f9a2a83ef7c8794d74ed0034ef5df77fef79ba3a7d01da6232193d2bb0aafe63255e50fcf187892e80e2f498b3f8dd67f737aaab2d3663351fb13c6f04d67a23187be471bfeffffff0300fffffefffcfffffffbffffff01000200020004000600fdff0400fdff0200fbfffefffeff01000500fcfffdff0000000001000100050000000400ffffffff010001000000fdff00000100010002000000fdfffdfffeffffff000001000200fefffeff0000fdff000002000400fffffefffaff010006000100000002000300fcff00000400fffffeff01000200fdff0000000005000100fbff04000400feff0000fefffdfffeff0000040002000300feff0000feffffff010004000100fffffeff01000000fbffffff0100ffff0300fefffffffdff0000ffff0000fbff030000000200feff010000000200fcff070001000200fefffaff000001000300fcfffdfffffffdff0000fcfffeff00000400fefffdff030003000300ffffffff04000100fbff02000100feff00000300feff01000000fbff02000200000001000000ffffffff0300fefffbff020004000500feff0400fdff0200ffff0200fcff0000010005000200fafffeff05000200020005000200feffffff0100fdff07000400fdff0400040000000200050000000300fcff030001000000000000000200feff000000000300feffffff02000700fbff0100fefffdffffff02000300fbffffff0300fcfffefffdfffefffdfffffffbffffff0200feff010001000100050005000000000001000400ffffffff0400fcfff9ff00000200030004000100feff0200feff0000fbfffdff0000faff0300fafffdfffefffeff0300fdff02000400fefffeff030000000100fffffdff02000300ffff02000100fcff0300fdff0400020003000700fefffcffffff0300fcff0100feff070001000400000003000200feff02000600f9fffeffffff0300fdff03000000fdff00000100040000000000fcff0000feff0400040002000000040000000100fdff0400fcff0000fdff0200fbff01000000fdfffdff0000fffffeff0300ffff0000fbffffff02000000fbff050002000500fffffcff0100fffffcff0100feffffff00000000feffffff01000100fffffdff0100fdff0100fdff0400fdff0200fdfffeff0200fcff000000000200fcff0200ffff01000300fdff0300fdffffff0200ffff0400fdfffcffffff0000fefffefffefffeff0100ffff00000100fcff01000200fffffbfffeffffff04000000feff0000fdff06000400000001000400fcff00000700fffffbff010000000200fdff0400ffff0200fffffdff0300ffff0000f8fffeffffff0500ffff0000fdffffff02000200ffff03000200ffff00000100fcff02000000010000000600feff01000300fcff0200fdff00000200feff040000000100020002000100fffffffffffffdff0200fcff01000300fdff010000000400fcff01000100020002000300ffff0500feff0100fbff0000000001000100010002000000fdff0000fffffbfffefffcff0500fffffcff03000200000003000100030000000400fdff00000000030002000100fefffcff020003000500ffffffff00000200fefffefffefffefffeff020001000100fdfffeff000000000000feff0100050001000300fdffffff0100040003000300fdff00000200ffff0200000001000200fdfffdff01000100fdfffeff0100feff02000300fffffbff00000000faff030003000400ffff00000300010001000100f9fffeff00000200fcffffff0100feff00000000fffffefffdff0300faffffffffff00000300feff0400040003000500ffff01000000fffffeff0100fffffeff0500ffff010001000000ffff0300ffff03000200000002000300ffff0200feffffff010000000000feff020001000100fbfffeff0000feff0200fdfffeff040004000200ffff05000000fefffffffdff0500fefffcffffff0100fcff0400020001000100000001000200fcfffeff0400060006000000fdfffdff0200fcff0200fefffbff0000fffffcfffcfffcfffbff0100fffffeff0400ffff02000100050004000000010003000500fdff000001000300fdff02000100ffff0300feffffff000001000400ffff0300feff0200ffff0200fdffffff0100f9fffcff00000100feffffff0000feff0000ffff0300feff030002000900ffff0100030000000000fcff000003000100030003000700fdfffbff00000200fefffdfffffffdff000002000400fffffdfffeff05000200fcff000001000000fefffcff0200faff010000000100020000000300feff0400fdff0000feff00000000fbfffdff0400030003000000ffff03000000020002000000feff0100fcff0300fcfffaff0000ffff0000fffffeff0500fffffffffdff050000000200feff0100fdffffff0100fffffdfffeff0200030002000200feffffffffff000005000300fcfffdfffcff010005000000fcff000000000000fffffeff0300000000000000ffff03000100fbff0700feff0300ffff0200fffffffffcfffffffeffffff02000000ffff000002000100fbfff9ff03000100fffffeffffff01000000feff020005000000fcff070002000000000003000300020000000100feff0300fbfffefffeff0200fffffeff020001000100ffff00000400fefffcff00000100fdff0200fcff0100ffff0500ffff0200fcff040000000200fffffffffffffbff0300fefff9ff00000200fdff030003000600fdff0000fdff00000500fcfffeff00000400ffff02000100fcff0000fcfffefffbfffeff000006000100020000000100fdff0300fcfffefffeffffff01000900fefffafffcff0000000007000200fffffeffffff02000000fcff0100feff0100fdff01000100feff0100ffff03000000ffff05000100fcfff9fffefffbff0200feffffff0000fbff010000000200000002000000030001000600fefffdff0000fdffffff01000500fdff0000000001000400fafffeff01000400fcfffbfffcff06000000000000000300fdff0000feff0200fffffeff0200fefffaff0200fcfffbff0300ffff02000000feff0200ffff020002000300fcfffbfffeffffff00000000fdff0200000000000200fdfffbff030001000600fffffcff0000fffffdff0000fcff0100fffffeff02000400000003000200fffffcfffeff0200fdff0000fefffefffaff01000000fdff010001000000ffff0000fbffffff00000100fdfffcff0100ffff000000000300fcff01000000ffff0200fefffeffffff04000000fefffeff04000300000003000300fffffeff03000000fafffffffefffffffffffbff0100fcff0100fbff0700040007000600fbffffff0200feff0200030001000200fbfffffffcfffdfffefff9fffefffdff000003000100fefffeff0100fdfffefffdffffff0300fcff0200ffff0300fefffeff0100fffff9fffffffcff00000000fafffefffcff0300000001000400fcff01000000020004000100feff04000100fefffcffffff00000000fdff0200fdff0300000000000400030001000200fcff0300fbff030000000400000003000600000000000400fffffafffeff0000fffffcfffafffefffafffcff0200020004000100faff0100fcff030000000200020000000300fdff0200fffffefffcfffdfffcff0200040003000000ffff0400f8ff02000200fefffeff030007000400fefffefffaff000002000600fffffefffffffaff010002000300fdffffffffffffff00000500fcfffcff040002000500020001000100feff00000400feff0000fcfffcfffdff02000500030001000400020000000000040001000000fcff0000ffff0000fffffbfffdff0000000001000200fcff010002000300fdff0100fefffefffefffeff0400050000000400020007000000fcff00000700fbff00000000fffffffffeff01000100fcfffefffdfffefffdff040004000200ffff0100fcfffffffeffffff0200fcff020005000300fefffffffffffdfffeff060001000500020000000500ffff0000fcfffffffffffdfffbff0100010003000100feff0000fefffdfffdfffffffbff01000400feff02000300feff0000fdfffdfff7fffeff03000100030000000000fcff050001000000feff00000200ffff0100feff00000500fdfffeff0000feff010007000200000002000500fbff0000fbff0400fdfffbfffeff0200fdfffdfffcfffeff0100fffffeff0000fdffffff020001000000fcfffcfffcfffeff0200feff0000020003000200fdfffeff0000ffffffff0000fffffeff0700fffffdff0100fdfffcff0000fdff05000000fefffeff0400fefffdfffdfffffffcfffeff0500fefffffffefffcfffdfffbff0000feff000002000300fefffefffeff0300ffff0000060006000300feff0200fefffafffcff04000800ffff020000000300020005000100feff01000200fffffefffeff0400fcffffff0100fcff030004000100f9ff0300ffff010000000000feff00000100ffff00000100fdfffdff0500feff00000000fffffdff0100ffff040000000500fcffffff050000000000fefffaff01000200fbff0600fdff010004000000feff0100feff02000100040000000100feff00000000ffff0100fafff9ff01000100000000000300ffffffff00000200feff0000fcfffcff0100fffffeff0200fffffcff00000600f9fffdffffff02000000fbfffefffffffdfffcff0300ffff0100fafffeff01000000ffff0000feff0500fdffffff0200fefffeff05000000ffff010002000400fefffcff030003000400fffffcffffff0300ffff0500fefffeff04000200fdff0300060003000100fcff0600fcfffefffffffefffbff010003000200050003000400fdff0200feff0200fdff0000fefffcff04000200feff0000ffff020003000100fefffcfffaffffff010002000100fbff0200010000000100fcffffff0500fdffffff00000200feff00000500fefffeffffff0500feff010006000200fdfffffffeffffff0000feff0200fffffffffefffbff0400000001000200020000000100ffff0100feff0100ffff0000fffffeffffff05000100ffff000004000000020005000100feff0000fbff0100feff0200fcffffff0100fcff000000000200ffff020002000300030001000200020000000500050002000100020003000000fcff05000500fffffffffafffeff00000300ffff05000300fafffafffdff0400ffff0300000001000400fefffdff040000000200ffff000000000100fcffffff0200010002000500fcffffff0400020004000200feff0000feff000000000200ffffffff01000600feff020004000200ffff0400fbfffeff01000300fffffbfffeff0400ffff0200feff0000060001000400fcff020000000300040001000000fdff0300feff00000200fffffeff0300fdff020000000500fffffefffbfffeff0300feff04000400feff0600fefffdfffcfffbff0200fbfffffffcff000003000300feff000001000300feff0300ffffffffffff02000300fdfffefffefff8ffffff0000fffffeff0200ffff0000fbfffeff03000300feff0300ffffffff0200fbff0100ffff020003000100feff0100feffffff06000000010002000300fefffffffdfffdff0400ffff01000200f9ff0500fefffdfffcfffeff0200fdfffafffeffffff020002000000fbfffcff010001000300fdff0100feff06000100fbff01000400fffffeff050000000300010001000200feff03000100fcfffeff0300ffffffff0100fcff0100fcff000000000200fdfffdff0100ffff040004000000000000000000010005000600fcff01000100ffff03000300fdfffffffdfffeffffffffff0400ffff0100fdff0000fdff0500fdff0300fafffeffffff040000000100fcfffdff0200fcff0100fdff0300ffffffffffffffff030003000300fcff0100010001000400ffff060000000300fffffffffcff020002000200fcff04000100000005000200feff0100fcff0000fffffeff01000400feff0300fffffbff000001000300ffff0500fdff05000400fcff0100f9ff000000000200feff030000000000000000000100fbff0000fdff0100feff0500fdfffdff00000000fffffdff0400ffff0200fcff020001000100060001000400ffff01000100fdff02000200fdff0200fcfffefffdff0400fffffbfffffffefffdff00000000f8ff0400fdff0300fbfffeff0200fdfffcff0200fdff0100030001000000fdff0100fbff05000000fefffeff0200030000000000ffff0100040001000200000000000100020002000500ffff0000fbfffeff0000feff010003000500fcff0100fefffdff040002000200fdfffdff0200feff0000000002000200fdff00000300fefffdff0300fdfffeffffff0000ffffffff030000000100fdff0200020006000300fdff0200fffffdff0300030005000100feffffff05000200fcfffcff00000000fdff02000600feff0100030001000200fffffeffffff00000000fcfffdfffcfffcff06000100030001000200ffff0600fbff010001000700fdff0100fdffffffffff0300fefffbff0000ffff02000400fffffdff0200060000000100feff0300020002000000fdff03000100ffff0000fcfffbfffdfffdff0000fdff0200fdfffeff01000200ffff0400feff0100feffffff0200fffffffffdff040001000200fffffbff02000100feff0000ffff0500fbfffdff020003000300060000000100feff0000fcfffcff0000feff0300feff0200fffffdff0100fffffeff01000000fefffbff0300fbfffdfffeff06000000fffffeff00000000fdff01000300fbff0000feff010000000000ffff02000000ffff0300050001000200fefffeff0000fdff0500fefffcffffff040005000000feff000000000000ffff0000ffff02000100010002000400fdfffeffffffffff0000ffff0200fdffffff0100ffff0500fefffcff0400feff040003000300fefffcffffff030003000000feff020007000000fcffffff0100fdff030000000200fcfffcff07000300feff0200000002000100feffffff0000feffffff0000fffffeff03000100ffff0000fdff0400feff01000400fefffbff0000fdff03000100000002000300fdfffefffefffffffdff03000100fcff0200040001000100feff000002000000ffff0400feff0600f9fffffffdff00000100020000000400010003000000feff0400fffffdff0300feff0200000001000100010001000000fffffdff0200fffffeffffff030002000100030002000300faff0300fcfffbff0400fffffeffffff05000200fdff01000200fdfffcfffffffefffdfffeff070001000000ffff0300ffff000001000100feff0200fcff0200feff0300fdfffdff0100feffffffffff00000500fcff0200fffffefffffffeff010004000200fdff000001000000fffffcff05000100feffffff0300f9ff0400010000000100000004000300010000000400faff0000fdff020005000000fcff000001000000000000000300feff0000ffff0400fdff02000100ffff0200fdff0000fdfffdff01000100feff0400010001000500feff020003000000010001000200fcff01000100fdfffffffaff0400feffffff0000fbfffdfffeff02000200fcff0000feff0000fefffbff0200fafffdff02000000feff0000fffffbfffeff03000000fffffefffffffcffffff0100f9ff06000100fdff0300fdffffff02000000feff0100ffff0100ffff05000500ffff00000000fbff0000fffffeff0300ffff0400000001000100fdff0300ffff0100ffffffff0100feff00000200fefffdff000002000100ffff07000300feff0200fcffffffffff0500ffff04000000feff040005000400000002000000fafffeff000001000000fcfffafffcff0000fbff0100050002000200040001000300ffff03000200feff0100fdfffaffffff010001000500020002000200ffff0000fffffeff0100ffff0200fefffcfffcfffcfffcff01000500f8ff0000fcfff9ffffff00000500ffff01000200faff0000ffff030004000000fffffcff00000400fffffdfffcff0300ffff010001000000feff02000100fffffeff0400feff0100f7ff0100feff0100fffffeff0300ffffffff0300fdffffffffffffff03000500000001000000ffff0100020001000600fffffcff0000fdfffffffbff0100030001000200fcff00000000010001000000010006000200030003000100fbff0000fcff0000fcffffff0000030005000100010001000200fefffffffefffafffdff0200000002000100fdff020000000000ffff020000000400020001000000feff0500ffff01000200020001000300fcfffbfffeff06000500ffff0000fdffffff000003000400f9ffffff00000500fcff000000000000fdffffff05000000fdff00000200fefffafffeff0200fbff0400000004000400fbfffefffeffffff0200fdfffcff01000300040004000500060002000100fdff0600fffffcff02000100fffffeff00000200fefffbfffffffffffcff000001000100fffffcfff9ff0200feff0000040002000200ffff0200feff02000000fffffbff0300000000000000ffff00000200030001000300fbff0600fcff0200fcff04000200fcff00000000fbfffdfffeff0300fdfffcff0300fbff0000f8ff0600feff0500fffffefffcff0100040002000200020001000200000004000000fcffffff03000300feff0500fffffeff04000400fffffffffefffeffffffffff0200fefffbfffffffdfffeff0100fdff01000000ffff0200fefffffffdff00000100fdff030002000200ffff0200030006000400feff0200030000000200000002000200fdfffaff0300fefffefffbff00000000feff05000200feff0400ffff0300030003000300010003000600fcff0100feff0100000002000100fcff0100040000000100000000000200040000000000feff040003000000fefffcff0200fdfffcff000004000200faff00000200feff00000100fffffeffffff0300010000000200fbff02000000fdff02000400fcfffeff0100000002000200fdffffff0100fdff020003000000fefffeff0100fefffeff010002000000ffff020000000000000000000300fbfffcfffefffefffeff0300fffffeffffff02000000fbff0100fdff02000000020001000100fefffdffffff02000000feff0100ffff0000fefffdff01000600ffff00000000fefffeff0100fdff0000fcff0000020002000300fffffdff0200fefffeff000000000000fdfffcff00000000feff00000200fffffbfffeff0400fcfffdfffeff0300ffff02000200fafffdfffcffffff00000000ffffffff000002000000000001000300ffff0000fffffefffefffcff00000000fcfffdfffdff00000000feffffffffffffff0000ffff0400fefffaff0200fafffeff000000000000030000000200fefffffffdfffeff0100000000000000faff0200fdfffeff0100faff03000000feff00000000030002000200feff0500000003000200ffff01000200fdfff9fffaff0200f9ff0300fefffeff0100fcff050003000100fffffeffffff0000000000000200fdff010001000000fefffdfffeff0000010005000400feff0200020000000500feff020001000100fdff02000200fdfffefffbfff9ff04000300ffffffff0400010005000100030000000200020005000000feff0200faff0300fafffdfffefffdff0100fffffeff0000fdfffaff01000300fefffdff0000fcff0200feff0000fefffeff04000400ffff040001000000fbff040002000500ffff050001000100030003000400fcfffcff0000feff00000100faff04000300fffffdff020006000400030001000300fcff0000ffff00000000fcff020001000000fdff030003000100020002000000feffffff0600fdffffff03000100fffffffffdff0400feff05000000ffff0200feffffff0400feff010002000100030003000000fdff0100fefffcfffefffdff04000000040009000000ffff01000100040000000500feff0000020002000200fefffffffcff040001000100020000000600fcfffdff0000fffffffffdff0300feff04000500feff0200ffff05000100010001000300fffffdff0300f9ff0600030000000000fdfffeff020000000100fdff0300010001000100fffffdff02000100fcfffbff060000000100ffff01000300fcfffdff01000000fdfffeff0000feff0100fcff01000200faff000001000000020003000400fffffffffefffdff0300ffff0000ffffffff0300020004000100fdff02000300ffff01000300ffff0200ffff000005000000ffff000001000000010000000500fefffeff0000020003000700ffff0100030000000400fdff010003000500fefffeff0000fcfffbff000001000200ffff0400ffff0500fffffeffffff0000fdffffff0000ffff0000fffffafffdff0100010002000000ffff0300ffff00000000050002000000020001000000fbff02000100fcff0000010001000800fcff0300ffff020002000000fcff0200feff00000100fefffdfffefffcff0000ffff00000400fffffdffffff0200ffffffff05000000fbff0100020003000400fcff00000000faff00000000fbff0000ffff02000300fcff01000100fdfffeff010001000100fefffcfffffffeff0000fdff0100fdff0000fdfffeff0500030004000100fdfffefffcff05000200ffff0100feff00000000ffff0000fdff020000000300060002000200040003000500ffffffffffff010000000100feffffff00000200faffffff0600ffff0400feff0900fdff03000400feff01000300f9ff00000400050000000000020000000300fefffcff0000faff0000ffff0100feff00000200020004000300fdff0200feff030007000000fffffdff090000000100fcfff7ff0600ffff0100fffffeffffff01000400feff0000fcff060002000100fcff0300fefffbff02000100fffffefffffffbff020002000200feff03000600feff02000000fcff01000000faff030002000200fdfffdffffff0100000000000000fcff0300feffffff0100080002000100050003000000ffff02000100010002000400fefffdff0100feff010002000000fcffffff0000fefffdff0000ffff000007000500ffff0300faff01000200fffffcff01000000040000000200040004000200ffffffff010001000300030001000200ffff0000fdff0000ffff000002000200fdff0200ffff0300fffff9ff0000fffffffffefffcffffff03000000faff0100fdfffeff0000020002000300010007000000090000000300010003000400f7ff0700feff010000000100020003000200ffff0300feff00000300fefffdff04000a000000fffffefffffffffffdfffcff0100010001000300feff000001000000fdffffffffff01000000ffff03000100fefffeffffff0000000001000100fefffdff0100f9ff010003000000fdff040001000300feff0000000001000000feff0100fefffdffffff01000200fffffdff00000100020002000000fdff000001000400fcffffff0000000000000300fcff0300feff0000fffffaff01000200fcff0500fcfffbfffdff01000400feff05000100010001000400ffff060005000100000000000300fdff04000000feff000001000000fdff0200fefffefffeff01000200050001000300feff0500fdfffafffcff00000200000002000300fffffeffffff0600030005000200fdff050000000100fdfffcff00000000050002000200020005000300f9ff020000000100fdff02000200fdff0200fefffefffbff0300ffff0400fefffeff0100feff0100fffffeff02000300fefffffffdff0100fefffffffbff05000100fdff010004000100040003000000000005000200fffffffffdff0100fbff0300fcff01000100fdfffffffeff000002000500fdff02000300feff0100fcfffcff0100fffffffffdff0200fbfffbff0300010003000300010000000100fcff0000ffff0200fdff0400ffff0100fcff050002000100010000000100010001000500010002000700fefffbfffefffffffaff03000500ffff0100fbff040000000100ffff0100ffffffff04000100fcfffdff05000600ffff0000ffff0200fdff0200f9ff0400020003000000ffff04000000fffffdfffdff0000fefffffffefffdff02000000ffff0100fcff00000200fdffffff0200fcff010002000600fcff02000300fffffefffcfffffffeff0100feff0100ffff0000000004000100000000000300feffffff03000200fdff01000600fdfffbff010001000600feff0200010007000100feff0000fcff0000faff0400fffffefffbff0100ffff0200fffffffffffffffffeffffff0300fdff04000000ffff0300feff00000000ffff0300010000000000ffff03000400ffff0000fdffffffffff0400fffffdff0100fbff03000100020004000400ffff02000300fefffdffffff0200ffff010007000200fbfffdff02000200ffff03000000ffff02000200feff0100020002000100010004000300fdffffff03000600feff00000000ffff0400fffffdff03000100030002000100010000000000fffffbff03000100fbfffeff04000000fcff01000100fdfff9fffeff0100fdfffffffeff0000ffff0400ffff0400010004000000fdfffbfffdff0100040000000300feff0100ffff04000000ffff000002000600ffffffffffff00000300050000000200ffff01000200fbfffffffffffeff0100faff0100fdff03000400ffff01000400feff02000700000000000100feff0100000000000200020001000300ffffffff0100000000000200fffffefffcff0100ffff0200fcff030002000100fdff00000600feff03000400fbff03000000030000000000fdff0100ffff0100fefffeff010003000100feff040001000000fcfffeffffffffff00000200fbff0100ffff01000200feff0200010000000100fcff0000feff01000000ffff00000100faff0200030001000000ffffffff0200ffff0200fdff01000400fdff0300fefffeff05000300fdff0000fffffffffefffeff0200020000000200fefffefffffffcff0100050000000300ffff010003000200fbff010000000400ffffffff00000300010003000500fffff8ff02000200fefffcfffefffdff04000300fffffeff01000000fcff0200feff0100ffff0200feff0200fdff020002000500fffffcff0300feffffff01000200feff020002000000ffff020003000200030002000200fcff010006000000feff030000000000fffffcfffdff03000100fefffeff02000000fdff02000000fdffffff03000500fcff0200feff0000fbff0100fdfffafffbfffdff05000000fffffffffffffdff0500fafffcff0000030001000400feff01000000fffffeff050001000500fffffafffdffffff0200010001000700feff0100ffffffff0300000002000100ffff000001000200fffffcff0200fcff0500fbfffdfffeff0000f9ff020000000000fffffeff01000100fcff0200fdff0100feff0500fcff02000100030001000100050004000200fcff0000fffffdfffeff010001000200fefffdff02000400fcfffcff0000fdfffffffbff00000800fdff02000300fdff0200fbff01000100ffff00000500fffffdfffdff0200050000000000fdff01000500fffffeffffff0100ffffffff0100020001000200fdffffff0000feff00000100fdff00000000faff0300fdff01000200020002000500fcff000003000000fdffffff0500070002000100ffffffffffffffff000000000200ffff05000100010005000100feffffff02000100feffffff010000000000fefffcfffaff020000000100ffff0100ffff000000000200ffff0200ffff000002000300fbffffff0400fbff0000fffffcff0300fbff0500feffffff00000000fefffdff0100020003000100fefffbff0000ffff0000fefffffffdfffdff020002000100070000000200fdff0600ffff0100ffffffff0300feff020003000400ffffffff0200fcff0100ffff0200fffffdfffdffffffffff02000400fdff0200fdfffffffaff04000300ffff010000000400000002000300ffff02000200fdfffeff0100fcff000000000200fbff0100fcffffff0100ffff0000000003000200010000000100fdfffefffcfffcff0000000001000300fffffbff06000200fdff0300fbff0500feff0100fefffefffffffcffffff02000000010002000100ffff04000400feff030002000100fffffefffaffffff04000000fcff0500feff02000300feff00000300fcff01000300ffff0000faff0100ffff0000fffffefffeff020000000100fcff06000100a620b486ac1046c6525cdd0bf862eedf
Cipher Text   : 408d099ab76c11ea31aae22ef1634eecb2674ac93312b337587ffe0d4500ffb6f4a475ba4997b4e17de0c152b20608281958eae3868717151e1c96dbe7bb07567476b06ff34e0ab1f855de82ec7043ec7be3a65d9667e8bc8896dad936e7f7e378dc248b011a30ffc05563ec1d2b728fe1046b78d2c359723fc4526eaa8d506914130a6cbfc016137cc290e828b6f1aa835beb15ffaad53e2b2670814fcc642346617b580552959c7bda8e5fbdea138d14860ce5e18013b96362c5624cd197235a4473fd76f77966542a44bace25b6e4197be8e78f422ea2ee092a59a3a2f1592d24382e7d7c8ec231451913b2fcc290d7479462bdf5e31796ac242d94e1552ea2334287b1757042685e693f1b7d3e8a65abca2406bd305ee6d1892c3b90494b4e3ee993fbb63e7ec2e42f97cbf2043f4c321efd56ba64491edd18f605d7c1ca4f70c2cec0ccf1338acf7dc1ae01ad363b4b3553ec7d28681b97723499fe12ff7149ca31788a3903454cfadf6d2364c2622369e9bdf662960f584416986e420dfb7dfa689b8aaf08b7eaa3aae5cc161ccd157b12e6903295a5b9009b292fd155022dba42459321765d29152869ffca829b54f835f94e5004c0fe8a9d32207eff2a1af0354cd6783e571152f64c497cfa3dee95efe065c867646336d8e2b0eafd196931bf08047be7d5808071598f1f5b2b05f63acc4cec76b7fd3dd0568e0ed1b4f36d654c79dd4afcc6d2664ba495a4e339b8c467bf1f5bec32c8b2ccb080a9c94253a294b1a10367de8712dc4483b3fc93ccbe479a6aa9bd7f24f0a57181e7c0a920f52e84735f7ab1ba553af4f74c1b6614a3bf6962f1b1ea6936c9678e9fe5e082c088449d943744a6242b4f9158bd9db015791098099f3366befd51aa9ac1293b71905da55b337b168b2d089663d8113091ab649b8f77f3a3a7f387d1ba331b605ad9292410fa33caed06386f25290f5d92f461b6633a1358a0003c00d3dd841fdaba4fe42d531f2c2ec22fb50b9308c4ef077d25fb320b85dae40af3ede89a11cd500fbc3dd5acb2c1110c2453003095c33870656e444fae9cfa5aff9238f138a7388c36027a9456f7443a65c7850ac3ad62671dfa541ea5529231a7b501f8b7971421c90f61cc3327499492ab96480d43441ec07ddba122e4325c256ddecd5af7aabd502c81938ec19c3276749dbf9084482b878cd906dbac41ae5075055339f9ae7b847d6a7d2ae29d49734c008d24975179f21e136b64d24132d2b8208229c4b44784da1914060aaa213050c3280b7877e6880981fac1e4d7f4d6eb25f607c2d9320d2a09173bb88d99adda89922db1d1c31771709a560d8b4b54e3b5772753248ba4917e3830aee72141259662196413659eea66f79b5d4c847a3170ae499ecd2304001cf3270714c50e9cda16b19febd9a5682e16797a34e6db46ec6f7d094d84132b8c2c984ff1feb10103b0d4733698a0a7b8be9787970be4bd25bd5b7e7d7388f34accf3d2ec78cecc3825109a49b4441f9944d3dac5e7b44334ce5dcbcb51547bd3c71ba494df1f0c29357dc3bc8dffd8173881e753caf8017f91811946973f7e6daa83efb431c07561fda78883f3865dc081edf22757859c518f643e144922ecc8320d5eb42b78686b3fadfb4165101cbd1033f5cf08cf802e801196727d288ac9238d0f6f8c3e3d33acc42154df298cf09d0395f664148da98c2982c6b9a18106c48ba25de6d734dd2948f6139953524774df5d0819468df087d25ee10ab64ffc1cecf7917e13228708d3cd75d319ed09ca65990af12818bf08e006e40e78408081a0406ae1a714dc073ec0e4ff7e4a0a18cb55c787354b6cb98bebbb1de2bbf7d05aa989e8d7be3dc28a5a0c2612b16a741dcdc603ae204e7a4b5958aa3221e49c6b99db1682a89a57b04f28461b12b5cf265a760ef17c8857f067c14abe33f4dc5a881c001f19b7bbd38744704ada37e70eb479aeb844be5169e74bb9212923ca8179dad6b981ee07ef1c6ac6b69c1af4ed540f30f3e3950b746266f8c7e912abc0a29525d861590229d08ca4a302415327a2be527f0045c85623e8e46b18c47dadb51301aa2b4c13499cbd2c76123807962df9e005220f9aebcb868af256b46aad7923cd033640917af3dc6f113795b4d159257db45eb8bd98b02b0151cce8f677febc9d735167434e71879add1ab45ec3dd5261ecf8cb8149b84cd71d3050c40d7a36933e58b17f560488587e9513f769e565a59f3e2c9d381f328136a64eaf875827e3963c50869edd93bb18dcdd94ee7bea8c14c3462fa3e3f45d6640b5148ad6e1e6b1776485410392f53cd459f8aa8f79a7dd75d092447a8a6b2e393c887015d0ecbc26f6cbab8aac421b30b5f21da7bae5d5393ad28ac29d2ce02a34110f69368167478a020b2557e73d14e6b34e998418926aacc1e71065e9871ba856b8cd754a5a78e80bf1e6e6f3dd7a0ad7012a0f05645576cf021f57aad3437caf2ac0cce95e167d892621ef050f7e48be7b885d9cdfc2ab4cd5e8dfdfb82f22f033c6eac0d27dbd66740dbd4c81e4385b3efec4d83f92a196f49cf01e9353c28313fad1fce27dbb0f39f6488162d9c94f204518f12a9449761cfc17113edb0bddfc50753af732a592cb2f7324a7f55842f7d197eaa4ae946e5ac326b9f091b3efb33d76553009240ee5d5cdaa6f5a0ff30ba8f77ff890a79e2510929c17f6000489d7f2d13616184519904ccbcdf18600c38a7f792bc400b4fe02bc7f3eb0fcaad5037aef72b55e8f1c08788956b4d7576cbfcbf8b567e25b15204278245070dce829d9ecabda139cd8200617e00ea2a1ba509947e05caa6957c258e00e52c0a01e56d0ec5dae45f0733ed8dca42370e3d24319c056ed2be78311ba7ca8bbb896a1087f36b472132bdb639ab35a8a3e36f0f006e4897c5129d3e767a9e95568ca4dc899c92e5ef3a3679d1efe1cb78588633b36631e64a5ea2524244bf2b9005ba2bf1ad138b16d498607f6df2e436d2175c1bb26af3c3fcd5af2af3c81367b295d6484ce99f624a52c4036b188bc2e22edf7bb3c92514f54d38d0b035a3c3c2dc820cdb5ac16dd6443b4c9c39beccabefb4193a68361f861709db46cf1e42b062ffbf0c0e412da6072cbf3fa0a65247cd116a76522096dfd4341077ebbdad1f6276d0eff5d697645b38b0e8ec3465f662f1f0ca51bd94dcab6eaf3f07d6dee078497be8cc52a68e4dbd4056af7d4c8140c346b5aff345630a90844f5d2e184b4c2e807fffb173734746dfe8b468fe350fbf5ecff11620021e86afd5cae380f40e08038db9db1c146e02a57f28a164b6ed9c4c5dd79e3c83c36a306411b15656a5a2de86ba7cae6cbdb0791e01909200aa69cf096fe3b14d1290eaf966de90a4db57d9548b67aec06e68ab0bbc1107b6df500a5d8b4764a929f02453b0a4d4f775e2cacb872da7ceae51cde120ebb4408fc02baf4ea06fa31a8d89b6834a232959cf97b2105670b8757783d4395cd167c1cb74f6d15f0fa3b2de89797bd7ecf81952175f29299e48a6097d5e19913d07a96f122e5bbc3329aacc1a15911e981c1e6963f09f16647127103a6529c3a2ca59658c380f1da434a40171a36fa13989f11a416ac1104e8f62dca52f17905e8c5d167341de02f3190a1e168fd192be47bc7840d50e1eb7fc4f990300f43e7fb3bca2b34b2a184d98d1d46a5e49642fdc758f722549862092b6de7b02b4f81487dac359c3d723c4e12f22464b1911f9616ec97b4e304e3794782e5b4f60f73fa5d417d400df160990f9e440e1e522e52d552f432c150786135f56013b8aefcf49780311fa53550d6fd0aae14eac8b7f8911da3516b34aa21e4dd6ff5ea75f2a816f53b036be954533e580e54446c43db83831941deef4c591982d55195250e13182cc36471aa742d1d177fdc4708e227a708cddcd8ace418ddec00ffda3a3089bcc6b350e1ade152fac699c3e2d9aef29d3f3f33b902ea0a2082b29def7567f66d6b8719849e40dd5c5fd8cd7a011ff89dacea32831271495530ef94d6d61101a90e4f484c77fb0430cec055e6efe9ee248df5ea8c92e638a3e7e827e746f50c92b4466825225a1b45aa3166ed2cc78536c5fcbcf622875a999667a67e56d08eb0f20e1aed9cad518f0a84768eda211c6cee843b0fc7a2f3644166df7db4d54a43ab4c70ff0bd44b806f2f8f4b25093faacdd44181be900b798d246edf6f9b387833410a1cbac56d939d61cf4d7ff1c72883ceda013ba2eb7392a71cb9c61bfb776402372a4d226a6609cb85a1c667fd3088356b41d594ad1ba08e34d146cb177f419f4787bcc16587bfac4ac35f7dea8f8e76fc2eca2ef99215efb62ca1be83bbaf105d763ee99a1802a92f7d3a0ba9343aea0b528a9ec0a75117055d85cd07fe207af43c07a542865236da2230872c4fc7b39fb1a65eefa4c6e96a4c930641ef9d2e6255e733bad1b6e3465081f0311fa6be90cdb5adca3350e3f0f8ccdbf957d01acab0c2652f7fcc771e4e2efdbbcd8dc8120093cc14a72350694921f6268bc95b4e054e7b04c43fa5fc658bcb7273b15946149b1c264d631df4e587ca33ecab857527b24b18dbafb21a82b2f13fa73e8f06a3fc6974b6fe510f3eaf37bfd060a0c3e9a2b8332eca8ad2a605d6fb011b71a8550a0336fa9c8ec1ad94190bb9e0327031f59e4868448f54c05eaefdef2c98c8cd5717dbf14de99d390655717929588ef5502865e6da082d6aa2c2f8bc3fd9aabffb13ddf5359f7a2a2f23d79e23814dcfd10453e224e588108c139d53f0dbf71fb3434055834bc9fd3aeff553e013e52b1e58c301e84dbac1ca385c71b02591f8f1411ce9695a7bc38cc305b6b19b8e1786babccf2ceedd71bc96fc2c7754c5e98da04b3b7dabe1205ead4997bbaa7ddb4edf06c2d0b7f77da36fb979549f3eacc81456e68db802d609527232bcec0c7da0f721a88e3ed3121f663dd8a6eb6019cf6905317880ebea9203bec496367c6d1db075214330e7963562f5b7a50cf950b58087186386f657c897d310be199cf2a5499e7ad71e4c2921faa1d70a864869c8e125d50fdb09b6590061fa84c2a9ae30fef57924476b7e118867026f8b3cea170d86386441ced1dcf8e47e1cbc67f5061d234167bdc97cc840b0bdf756b240ef5bc1edb680fb04d2bd889f347f8415d5cea270a5da0cc97b155e9ec5d8765673b363e30db59402bcca1ee2cf586ead81afcfb97ed078e1f843849261989dd5678ee4e004f2333e2378ede5974b8563894739aa84c697f8788390d1a9d564818e9de54981061f49cdd49c8d4a13b2b89e29f0ba3b2d3b64e65d3450e884ea39f2ee61954d2ebe70bffe0d9fc76d929aba4d633f48ab2206338c4cae25bed47d7369f673ced197bcfc3f11de273ce447e1b80e04591153d2533d4fbee5273aa816a132edba72ecf75cfbf3af9358e8d1be61f477c1706d3e1c2a6a69e831a090ff699ce2544296370709ffb834daa35ca4732a1381790016efd151dd6d1fee9082314761c8bc71ee070911953d620795b02ac0536b209222b504edd338a74a8f665f90d1ac1867705f5544ba9bdde5da4a9339ef09ac7d6af7fcdb10fdf8cbd5efa06b4a325e6c6002b8eb874c2c68f24aa3bcceebabb28db351f7b36033617dba57f4328c610f77c928fcbc66da9753bc4e5f5c92fdf0b7e8a48ca67a1e48db01d42c28c40088fc0c30d7a32b0552ec0f3968aee0650d1a6f48113e0c2c42b31539c0ac7ccf7a91d78d0a92d5a6eb985452f7f1332dd6a089e5f92e609f162055afca793eb80bc062542de98023c6565e898b33d5c384b622fd68997b40bd506f04cff7f0a73c0892db4749da2fe794254594c53a6dcd5a02b35e011b2d803dbb400699a7a9e85497918765f87d1468a6c5eac6735454765eac6046d87332903b33b646ef7d124c4a5258d766e597800ce6118e823068f2f1918092a457ffa0c66febe7d1da62e2265ce03b3ac024e828ce0d6327b826a8066c94fa10585f82471b94b2b1c281c1cb3a64d8693cad2ff869a4af664ef29edc2cfe2242cc7ab9fe8e8a530f7fc7e525f46c35480ede3826fb64d590347e2735d487b42ada147e2c772cf7072f952109569f54986560261eb056c52d30dd1377f9cfe675cca3e419f141e75fe81e37cae3f49f8e2a03eef322ba2f0dea29804896a961f3bb8c69716c9cb5262645c181af901934a569818d4bf2906afe7d9a714ccc46ec0d5340c107aac513ea96a41783700e8af7fc6223320a280750782df0fc463223fbaddd6517a3d62d8f1c4340fb701a3b1384107caa3020799bed6dbb71f474184d6f79d8a9fe6ec6d251ad415171135786b54c882e3df9b629c1cb97a3b7023df3a9784d3a9cba680d5b8c2c245fd61757065d7dd8375e99af2cf073a6b04226a51e6d45c9371328e7ae16b8baea74a3456ab2796562f3a38b30fe62a39e97dbf9aa9af7169ba5007b7c593b4f4297698e7f1ae9783ac54b5ba59fcd5e3ca5e3defc628b88e1b27c5a5d82023a9a7359686f66d052b0f48c5e31baea5197279f7e8b09102d1ad978cec07d698c31170fc72558aa42d82b192d1a11784400deb8a508624b6e91ea71ca6c6647a2ebaf8e6c9c4e8cfa75363dddc93513721bf88cbc31577b79d2bc19e5d0768c2db3ed8c0b039497fa2d7dd3d3b9b8ef85dac1f3e2adb807f3f0450095a0c3293f16d4384b09b737ce90c3a163d2db28e54f1f9f15feb0f9c111f7062e7227774aef7d5db75bf921dade60576fa09535408838f1d6da829e77c4e42892ab4d287aab2afdb9e62260e6c6454367c582b7737980247f89a2592227c63edde392f5947b055e53dbc72bae7165c3cf712a16a3e3011ee2d6998475d234cadd46f48be4e14b216be02c642741715220a88907efe7ae651fe57ff3d8687495a2741393cc5cb815167b3d7403aa016b8331484cdf4e4332d9c1be9159310abb593d5e07f61db9e051f4992cb719ebedf57b5379485c1dad57d29a526e3f68b10a4a4b4699690a8aaf9ff69f988242ae35636bedd8dffc9371a2f689dcc3881911b1853c85a0f087d4e1cab3b85e74f5a3f66009d33572bcf9655e4a809e9e6c84cb406fffec7a3b46d9010c4065351752c42e3da59b5f59e6ab2e1255c9cae105d65e00fe70f0c900f0366e457cf27b766a0c2205f653ab5cca36d95c71f0d1f58d88f83b4d59196adb2459a65f9dcc3a814427a3d6718225abeb6fa8dc26c06101d7ca5350322ae4166ffd8dd2109cd2b5ab8cd7658df4c9c97922e20411188d05c1c8ea108c049878dd93ecfd0e47a638b111dababc969ab0ffde8ab8a5845e270e433e8779b4ef174b8bf20249ff54e3f2bfa9e3ec1d27222107cf7d9cf17552980071f579f49fceb4a8b0e72f98420d2306778bd4b26436795bbbfa43a0907f92d27032addea78149fd8b419fb8e3dd11d33eb0dcfeb4f8bb2911b0cb79a7b1d7a62387e4c4358ba06cd36e4e6aeb8f74874867babc17931b2e3fe2e1eadcdaa9bd7da29c2829aa21a9805ea3966efb841a09177ed00d8aca7da53ea73c67e9d0d4bb2ab84daa2949da18e93c47db134b15c3bfc83c904177f2110f33262def9f91e01ce854e076f07c50afc06d176ea4498568bb7f55dc35b250ef8a057194d693c9c8b9f35fcedaca12691e73465f04563de803615f35efd9340c1dbc142b07cea383109148fe248911db8190c8363e087ef8f039f4341bea0f90fcaac77cd5213614f4750e8aea805003e5a44147b1da3a89fe8e08e984e4a24aa89ca3759fb0ea3594e808da09be3bc33ff5ceeb4f6f8a2594073bbf60b48704aeaf0fb7d749b13dbea5fdebcdb68acc5c81da1c6d5884c3d58c95ae5a881740a3329d1fd38b9ee25ed0f61bf8338ee1e70fed58fb0b5075deba126ac82f0fb0b84ac92435c009d088a93a6453cbd59325ffb1e71944dce6eb390824312d242c32d53a7bc5858f5795902388c583f021212d08eacd2434df38ada13fdeb0c0131e53ca63a3250ce5e1d65d8b3fe78138c66c95e3cad4cdc3e04bf896decf4b4ae439fea7b62fff6b258802e2226e0d4f0f5d3790853fcc9c2fc6c78b8e81328890afef5158fd7e2af7ae99340a08f2a60fc6060713b187de0f5e39e96f74c5a2049a187807c21583efe388dbf844997b4b4e6213a61a36b90aa5d826e79e33c8224c528e863af933266a060344e47a7f9abf3e20f95ac591d2cb4470f1109fb3995a6babdda59f77810073aed30ac17cff2bb441c7484ba3b7896d5fe6c956391e03a2307d18dc5fd6dde11a55e4b2b8a8505193d6a3b0e1eebf4ac3e19c1f4cb6003680fb55da6b845d0b49aafb25a2c5a25e6a8b695be7f3b2251851458a57d1ffe49dfe25e5917fd844961cfdcf7ea0c930544684be791c7fad057f6969a26c393d94a20ec6d808ebf9b2ce203d1570e9c8b53b9ccd6ce42f29f888a051190a6061faf5adbdf9eb1bb13c7b7ec2c5e28b1178dcd479bdfb9016cc28be199cb477575cd3de937bb1940de79c7c420df0a298f837160fb83bb4755be39c3b77a34e4da1db3fac215f976c2de00b95e45867386ec58c3950b31b3fa8a5dd8a9ffc40472c4c12bbaadd5e92cff6b3699f2337f8326c01b635bd4d6219834e6b815f2cfaf57e9af1ecb95a96895cd9d9947e7eef687b6ae62b4e441c883409cb96adc5a8a47efd505ee3a404e064fbb9369c5290ce9ee43c4520563b0395a3e74d7126c1d1f4233d2df1b1f422181b0fd760d0a6697224d27b7a548eb10a5e6ede95f5d21ec24c6dca0501adde7b96b5fa746196575f2907ec64beb82f587e50e2cdbfc4412f3ae214ff08543b82667a10c8affb514b2f16dc6606ab5047679100c3c5f94f3327e557663d17828381a7a7fed1d82ed953dd100ee8b83f9b7d7e89d07ac90b0b3c3450b7c7b0d49b40ec2b771cbf78424ef8d60beb67c61dbf5e34fac9e9e312e7aa55093db09e408019c8fdd737f30e61fb78dabfeb5dacba1d445b53f101f4b67418e9d3b9e54a2c44d8494b3278f108c33fad08f3bfdeca208bbbebb5c577d4e3a19d0e457fffca5980cc212ea2ac8d121023238cca6aa52ea4b756b75d6a2d6d3f6c555ee8175ed82a5c25d0cbd900a0b0ff3653f9cd0fcde2a8f290c2c4fb9d97fe6c6bdded37ea92a75598be26e288a3d87eadf22400181e01576ec8cb6504394d3e0f758740a6d6ca32561bc944b61ac9521059102fee3d90ac2375a6ca40a6fa673221e8fc464f4571a87ecb78eb9a737d4c73a2d587f60113cec54c5ac166273afd93025ec446a5b3da917ce382c9cccde9b98814693d1f16ddf137a69f63998a6e57855b5794e19f92c00f1f5440a62a589061917961b4b9946e23c5dad3d9515101ba5a15c8d1a817c3e799951e3261c451511c4b43c40ee4b8ee7c8a228517f144588d69df4454d1e1eb403477f796d942edb5819204597acf36cbe82a2ebf2f1fdfb5d65b998509cd6d252db41663b8164eb8e9b4deab8df6485856ba76e250b10fd7e61ff39c74adc30502a3f05a62152db3147d718edaf2b7b77a69b2d7538c212655451d0e879899dce8851dfb99a944b50e64217d3c1fec25300fdaa3f72b1dea217dd6c078a98feb8f8133a4b18f8316a06fa54e433bfc172f5d95a651ef77cc15c64cd01592b64dbbe62fe976f99cf6dc90c2e278e0babd0c8a27a1feae35cba6597e419a355014ec0daad9532efff3833302b18ba4ea85e12205ee24abed8eb96c7eaffd79d9d0848ec3a7d0f5fa350d5e35614d845ad3aa37e16bc32f9b3ba9e47e758ae13568a56bcda9958d4ee0bf6b3ef70b6f2f664ad249e2f143f1f83082fdea266a32b9696db6868db63ad2e110f453178e54f01cdd3c520b0c7e94c1eb1ae21ddefde64395792d040bcdb3f7a34ae0a643dd673ef276d3b3625cd0616f97c074bd61147b5da2b79c57422bb0bbb4f636386f7d697b91767e6062a4ab643174c5af9c1d50ab0eec5d58c26bf8677b0fbe85ae7ecb9631fa92c0a2949b5abff3af5dcd6ad8b60481851aeb24741e0df980c56d868f2b69d0ae3ac85cd54d461e1ecd80e0ada324b2fb165781092037f33d4215277d133eda01b96221a0d1c5ecebf0f9a76468db3e4c25d070a3ecab894662a86b4eee1f12ad9c524d1eee99a7c7c359c199ac232b73a8a30c966b57b6321351ce5f61354ae93f38bf7ab9d70dc23688d58edaf0122477f52b4fd5ac335aa2758723ab5d0a867243f6dbc9d4e7861e8569ccb10d1c236424c915635230a76e8824ced906d9ed33d26bab8fbc569d8ace19835772e7ea84a27b5f3e49a33480c97192a2a3488b07be0d3a56ddcb7e2db0074b4f22fa44dbae4172ccd0c9172dcad45b6714230dab76a1a8533a534365285765f66ca3f56c1306eea7733ed640cbd36f590208389a14a9ff339652835f96a94b84e51b05fd624b6a575e8572622f2c17327274158d228c2f56b5bc49b283ac2b64f5d9c762ecd4c5cb21c38faecd7e05a65a11ff78d083ad641954281b4c6b9f8ed72fe30887f405067c5b1dcfbc2f9136d551f22cbbd4ca431c774115c80e0a8048ceb497ffcf2656c4e7bf3f8b7ca5f2e40b388ebd06146340b9c27eff3869dc452cb742a8a86af0207ed6bc5176cdd1485bcbcdc61ea592454387c77a4953fd71450dddeea38e3cf1e6ba2ff9951cc8d6d27c4dbc5af71212efe6f5b8ed3a05d2687ed1289abc8f54b5920c5fa8a19e4a9f5c6bab12dc11e7747db21ee8ae207226a92cac5c51d058d6c8a481b1021eeee9d7dc4b6729205c02ba854f6c373e6a490cf743a9be010167d4ec54ce65b552ff83d092d38daf9bd3b47acdeb3b22837128ffcca2305cd92eedcb4a66ff2ab7fa79682e1b14a1aada976fffaba2c71e4f06925095e355cd15914cf8291449f8932026d1df9c2b4e04a98b52309678cab4c5b4e1459a0df384c45f7ca53b3e63dbbe527f6267707c0730a34ea8f888050a9267bf993ed4a80f09dcaf1f5be8b4b9591a1342d48912e448d01ebfa6bbbaef8a9c5b8a1c5ca2fdaafd76fe48d900b44930916a3d02ff8572e173375ee55197bdc5ad2c87c873640ee5b8e8cc782fe130c08d9d84b47c137d84107c9814daae796cea354196844ef34c6ee164a1870e5fddae6348054128a2b1179a41579a17194369730755549ac3ffd84503d63e80b50cc303aa59f5fe27f202114d807b33c32f8a09ab8bc5d327f5f4d02601dc4e5058898b4a289c85c6169990889efad3123ca815983f98618b15379674fbacd8b4265c66780aa7c217ff8fb95e78f474e7e51da780a5778fe955968c5225886e59193917cd9f4dda8829e369b798d77cdbe2ce98305fe3f383eb86ec081ddf1f950726059f7dd57bb3d8b56e989802ec4ce0d98638cc79d28a447c55dcf70f82610c8696ad7085aa078442e4f572721c0ec77d60f5d58c77e6b654f51af35ae1e697aab1fb1871cda0a4203042cff075a5387ee6bb8b3c42ecbfec57fd9f7a1ea034769566735ab15148c1b8da28ed8dae03ec700c2a3021b32d090622ef2637e2c4f21bf8a37b961e4a9c86a150da78bce1c869f6ea40ede8065597c8c541269d456287713c16e88a3f4d551919a48819a08dddc9900f5aea764dbde1ed1c8652faaa2c6c7d52d1c9221d22c4a99dd9383ff16c2574d07f578c9cd9af8b6dbc64ce7645475880ce3b1dcb68c7ff57113bcd93d9a804c42c0931948af193cb7105a21d39571b3f3b00b381c41058f5eb2d5ee15ef8cb032cbc4ce642e86ffc3690fbb10e62d9cf4647fde0eb8f9c83c1d90b138121977b6efacddedc4a1a8f0ed00c5ce7ba6e7b4666f24fd9a04240049dc650955d5432c3743a203308ab76f0a7696d5cf0e731b937a8d0e101fb6dff5622d84b516810d1d4ee6d6b44a9f180f131621de0e055ab4804984c57bed5dc67aae0cafd0d2a9ecd71fae17910e0f86bd96c66fd90104920c8fba93c1a4effe1149b36c5c5cf3750623d5a1ae3d168a1de5bb29a9f875cfc6031dfb3d13132df0b0f3a91aa2c7fe01d34c6db939069adb605faf5446f487242a41340172523a678bc94d62d5ce5132f07b9dd51a1347b73e56970595520816422142a3bd4842203d78cc7a62f193dba81e07552d27aae0be67a7ce79b16ffb04c931f6b12ed7e1fe1bd716b96d27f78ea3f5df64fff88064f79a92ef9b6ff6e71cde20570c0b1f1ec379f5206e1ddccea96cd9e8955c96cee43dbf841733dae7ec5f9f7904fad6509ef65de1209abdbb44417a2eb9c81225ae1550210c1f2f21f7d1ff7f244ca28044e68ae731c7869ac35e3d7b7eeb8b3b8277688dd33d6ac3701512963d0dab21713bed4cc88ae44a68f0d81ae4d1591893fb0c2e1a9b52b38b4ad2efbb1663046db11dc488da00a53d09c585421acd70e08f87c24e44bda5a2fb6be3fd9f59c08efa9069d1cd7073f5711ce65b37177b7199bfe469a231b32f1c43a030701c1e1c47f1f4b04304b69f780b72d0cfb004cd9483f0a39e8a5eeaecefca5336093d2a8ec6ea9e585c7d779e612d062c73d734239ae1b4217d7d37f214dc52ccf3b55037395a3e77a9e390cd792fd9ee27f48ff940f1602c524c1b47dbc0a81f54ff300fecc4ae81a744965e4c332b5fc378128908dbcf99eaf2db51d4373653a839240ddb2daa1be70355488866ac7ca557d11a6e5e4fb53d8c2747ad832d5ca5cb3b0fbbe878e73d733f4ac4f8806d59e4b13da211cfa32d1ad73c7d69a86940ab824424e590ce4373ffe28107099e14f08610ceb2598610772d3aa4b549a519a51551564984f6465177627bca6b5e6163660f24c134a27bf465089b58ce6c25080e323e1ae2b3d3e7f5c3ea53e497a6a18382a35bf50114ee14f7b25f689a08c07e6f75a4affd925b9534f3c63d38f684fc54dfcfd789ffef0d883cfc05791e084e8c1dbd3664e24d3b2180c083e5f4b7c8b3fdaf415a89b050420e5e8b744fbf9e1e55f4dd1dce8206e3a849d98042efa361407bbe15293c0e8c522a50cf098e0049f6b8c999b97292030b11bf0f140da3eece9079354620c40a8f9ea16b97c156245681f0ead3c8645f3d1b3703342f602b96e076be391abe207f02406a7eb28c706b67e88c7af831ae2aa5f7d25d22e82500e46fa666ede695cac96dd4ff90e9af9e6b90f62a94b82a02473011960abc190e3133943098cbe84edc575f697024371ed7c476a8fae929334550230c5bafbe749ce62a15ae8ec5e667ba4166455587411506cf6fb857fa6505fffbc8c2365fa8f1c175e1a80be987ab185e9a57ac8a3d25e17331264ba98052f9955208100c9f583770b16752a973fdcf5ae58f11d4b4a521508c414a59e57d5dbac11cf5d6fad9fb4cb9d06fb00312a1f13f6194e9f5067d83b3df01cf7bce89f39d8bbbcee86bb1a7da3ac9c6345b9c877a001fd3611b3719754cf31981baef26080b8c21400924b96d2e2013bf056d094cdfb3338f476d3ae05a70823a0174db644bcfd545df4d447c3bf5ffe98c1d284401b81020eb8c546f14bb09f49c7a8fdf569cdd2c1bc665ffa910477b978a618483a73104639d47d343af86b5315e6857eeb419ffe13fcf0a30ddfe5ffb81f86c03ea1522ef9996de253b4b59fe9fd712806ad2edfe3ce4e692af164cd12bbc01bd53bb4e16a5a8a280eef8a0b56964cf38af1dc104f36e776e9641044b58aaecca0b76243f2a56740e1fe631bd448e99488365b3ccb2c5c995184d4a0c56e5161ba165b1323f7ecda6c94e3
Shared Secret : ebad3b0a0a8b82188a75d3a415b405b
```

> [!CAUTION]
> Before you consider using Psuedo Random Number Generator which comes with this library implementation, I *strongly* advice you to go through [include/prng.hpp](./include/prng.hpp).

> [!NOTE]
> Looking at API documentation, in header files, can give you good idea of how to use FrodoKEM API. Note, this library doesn't expose any raw pointer based interface, rather everything is wrapped under statically defined `std::span` - which one can easily create from `std::{array, vector}`. I opt for using statically defined `std::span` based function interfaces because we always know, at compile-time, how many bytes the seeds/ keys/ cipher-texts/ shared-secrets are, for various different Frodo parameters. This gives much better type safety and compile-time error reporting.
