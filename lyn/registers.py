import platform
import enum

class Register_x86_64(enum.IntEnum):
    rax = 0
    r10 = 1
    r11 = 2
    r12 = 3
    rbx = 4
    r13 = 5
    r14 = 6
    r15 = 7
    r9 = 8
    r8 = 9
    rcx = 10
    rdx = 11
    rsi = 12
    rdi = 13
    rsp = 14
    rbp = 15
    xmm8 = 16
    xmm9 = 17
    xmm10 = 18
    xmm11 = 19
    xmm12 = 20
    xmm13 = 21
    xmm14 = 22
    xmm15 = 23
    xmm7 = 24
    xmm6 = 25
    xmm5 = 26
    xmm4 = 27
    xmm3 = 28
    xmm2 = 29
    xmm1 = 30
    xmm0 = 31
    st0 = 32
    st1 = 33
    st2 = 34
    st3 = 35
    st4 = 36
    st5 = 37
    st6 = 38
    st7 = 39
    noreg = 40

class Register(enum.IntEnum):
    if platform.machine() == "x86_64":
        r0 = Register_x86_64.rax
        r1 = Register_x86_64.r10
        r2 = Register_x86_64.r11
        r3 = Register_x86_64.r12

        v0 = Register_x86_64.rbx
        v1 = Register_x86_64.r13
        v2 = Register_x86_64.r14
        v3 = Register_x86_64.r15

        f0 = Register_x86_64.xmm8
        f1 = Register_x86_64.xmm9
        f2 = Register_x86_64.xmm10
        f3 = Register_x86_64.xmm11
        f4 = Register_x86_64.xmm12
        f5 = Register_x86_64.xmm13
        f6 = Register_x86_64.xmm14
        f7 = Register_x86_64.xmm15
    else:
        raise NotImplementedError("Machine %s not supported" %
                platform.machine())
