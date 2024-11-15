
rule Trojan_Win64_ZLoader_DA_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {45 58 43 45 50 54 49 4f 4e 3a 20 43 6f 64 65 3d 30 78 25 30 38 58 } //EXCEPTION: Code=0x%08X  1
		$a_80_1 = {72 61 78 3d 30 78 25 70 2c 20 72 62 78 3d 30 78 25 70 2c 20 72 64 78 3d 30 78 25 70 2c 20 72 63 78 3d 30 78 25 70 2c 20 72 73 69 3d 30 78 25 70 2c 20 72 64 69 3d 30 78 25 70 2c 20 72 62 70 3d 30 78 25 70 2c 20 72 73 70 3d 30 78 25 70 2c 20 72 69 70 3d 30 78 25 70 } //rax=0x%p, rbx=0x%p, rdx=0x%p, rcx=0x%p, rsi=0x%p, rdi=0x%p, rbp=0x%p, rsp=0x%p, rip=0x%p  1
		$a_80_2 = {5b 2d 5d 20 52 65 71 75 65 73 74 20 6c 69 6d 69 74 20 72 65 61 63 68 65 64 2e } //[-] Request limit reached.  1
		$a_80_3 = {7b 49 4e 4a 45 43 54 44 41 54 41 7d } //{INJECTDATA}  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}