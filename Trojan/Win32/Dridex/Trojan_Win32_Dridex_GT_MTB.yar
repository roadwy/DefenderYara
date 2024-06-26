
rule Trojan_Win32_Dridex_GT_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b7 ce 03 c1 81 c7 90 01 04 a3 90 01 04 89 3d 90 01 04 89 bb 90 01 04 8b 2d 90 01 04 a1 90 01 04 83 c0 90 01 01 8d 14 29 8b 4c 24 90 01 01 83 c1 04 03 d0 89 15 90 01 04 89 4c 24 90 01 01 81 f9 90 01 04 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GT_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 17 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {54 89 e7 89 17 c7 47 90 01 01 01 00 00 00 c7 47 90 01 01 00 00 00 00 8b 15 90 01 04 89 4c 24 90 01 01 ff d2 90 00 } //0a 00 
		$a_02_1 = {cc cc 40 cc eb 90 01 01 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 90 01 01 8b 44 24 90 01 01 ff 80 90 01 04 31 c0 c3 c3 90 00 } //0a 00 
		$a_80_2 = {45 53 54 41 50 50 50 65 78 65 } //ESTAPPPexe  01 00 
		$a_80_3 = {74 74 74 74 33 32 } //tttt32  01 00 
		$a_80_4 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //OutputDebugStringA  01 00 
		$a_80_5 = {43 72 65 61 74 65 50 6f 69 6e 74 65 72 4d 6f 6e 69 6b 65 72 } //CreatePointerMoniker  01 00 
		$a_80_6 = {58 68 6f 74 } //Xhot  00 00 
	condition:
		any of ($a_*)
 
}