
rule Trojan_Win32_Dridex_GV_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 17 00 06 00 00 "
		
	strings :
		$a_02_0 = {2e 8b 74 24 ?? c6 06 54 8b 74 24 ?? 89 e7 89 37 c7 47 08 01 00 00 00 c7 47 04 00 00 00 00 8b 35 ?? ?? ?? ?? 89 44 24 ?? 89 4c 24 ?? 89 54 24 ?? ff d6 } //10
		$a_80_1 = {45 53 54 41 50 50 50 65 78 65 } //ESTAPPPexe  10
		$a_80_2 = {74 74 74 74 33 32 } //tttt32  10
		$a_80_3 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //OutputDebugStringA  1
		$a_80_4 = {43 72 65 61 74 65 50 6f 69 6e 74 65 72 4d 6f 6e 69 6b 65 72 } //CreatePointerMoniker  1
		$a_80_5 = {58 68 6f 74 } //Xhot  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=23
 
}