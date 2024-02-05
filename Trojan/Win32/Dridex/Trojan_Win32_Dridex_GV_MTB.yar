
rule Trojan_Win32_Dridex_GV_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 17 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2e 8b 74 24 90 01 01 c6 06 54 8b 74 24 90 01 01 89 e7 89 37 c7 47 08 01 00 00 00 c7 47 04 00 00 00 00 8b 35 90 01 04 89 44 24 90 01 01 89 4c 24 90 01 01 89 54 24 90 01 01 ff d6 90 00 } //0a 00 
		$a_80_1 = {45 53 54 41 50 50 50 65 78 65 } //ESTAPPPexe  0a 00 
		$a_80_2 = {74 74 74 74 33 32 } //tttt32  01 00 
		$a_80_3 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //OutputDebugStringA  01 00 
		$a_80_4 = {43 72 65 61 74 65 50 6f 69 6e 74 65 72 4d 6f 6e 69 6b 65 72 } //CreatePointerMoniker  01 00 
		$a_80_5 = {58 68 6f 74 } //Xhot  00 00 
	condition:
		any of ($a_*)
 
}