
rule Backdoor_Win32_Nitol_DX_MTB{
	meta:
		description = "Backdoor:Win32/Nitol.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 44 1e 01 8a 14 39 46 32 d0 8b c1 88 14 39 99 bd 06 00 00 00 f7 fd 85 d2 75 02 33 f6 8b 44 24 18 41 3b c8 7c da } //1
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}