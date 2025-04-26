
rule Trojan_Win32_Dridex_GT_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 ce 03 c1 81 c7 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 bb ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 ?? 8d 14 29 8b 4c 24 ?? 83 c1 04 03 d0 89 15 ?? ?? ?? ?? 89 4c 24 ?? 81 f9 ?? ?? ?? ?? 73 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Dridex_GT_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 17 00 07 00 00 "
		
	strings :
		$a_02_0 = {54 89 e7 89 17 c7 47 ?? 01 00 00 00 c7 47 ?? 00 00 00 00 8b 15 ?? ?? ?? ?? 89 4c 24 ?? ff d2 } //10
		$a_02_1 = {cc cc 40 cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 } //10
		$a_80_2 = {45 53 54 41 50 50 50 65 78 65 } //ESTAPPPexe  10
		$a_80_3 = {74 74 74 74 33 32 } //tttt32  1
		$a_80_4 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //OutputDebugStringA  1
		$a_80_5 = {43 72 65 61 74 65 50 6f 69 6e 74 65 72 4d 6f 6e 69 6b 65 72 } //CreatePointerMoniker  1
		$a_80_6 = {58 68 6f 74 } //Xhot  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=23
 
}