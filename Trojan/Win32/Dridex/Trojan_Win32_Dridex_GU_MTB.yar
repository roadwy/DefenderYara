
rule Trojan_Win32_Dridex_GU_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 17 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {54 89 e6 89 16 c7 46 08 01 00 00 00 c7 46 04 00 00 00 00 8b 15 90 02 08 89 4c 24 90 01 01 ff d2 90 00 } //0a 00 
		$a_80_1 = {45 53 54 41 50 50 50 65 78 65 } //ESTAPPPexe  0a 00 
		$a_80_2 = {74 74 74 74 33 32 } //tttt32  01 00 
		$a_80_3 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //OutputDebugStringA  01 00 
		$a_80_4 = {43 72 65 61 74 65 50 6f 69 6e 74 65 72 4d 6f 6e 69 6b 65 72 } //CreatePointerMoniker  01 00 
		$a_80_5 = {58 68 6f 74 } //Xhot  00 00 
	condition:
		any of ($a_*)
 
}