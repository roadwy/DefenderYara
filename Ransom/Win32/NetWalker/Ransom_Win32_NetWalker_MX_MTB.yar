
rule Ransom_Win32_NetWalker_MX_MTB{
	meta:
		description = "Ransom:Win32/NetWalker.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //expand 32-byte kexpand 16-byte k  1
		$a_80_1 = {75 6e 6c 6f 63 6b } //unlock  1
		$a_80_2 = {70 73 70 61 74 68 } //pspath  1
		$a_80_3 = {6d 70 72 2e 64 6c 6c } //mpr.dll  1
		$a_80_4 = {65 76 65 6e 74 76 77 72 2e 65 78 65 } //eventvwr.exe  1
		$a_80_5 = {6d 73 63 66 69 6c 65 } //mscfile  1
		$a_80_6 = {73 6c 75 69 2e 65 78 65 } //slui.exe  1
		$a_80_7 = {65 78 65 66 69 6c 65 } //exefile  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}