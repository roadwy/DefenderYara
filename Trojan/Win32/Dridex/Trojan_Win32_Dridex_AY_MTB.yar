
rule Trojan_Win32_Dridex_AY_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_80_0 = {33 33 33 73 7a 41 63 53 4a 41 4d 72 54 75 4a 78 73 70 66 33 63 72 4e 54 64 46 4e 43 44 71 7a 62 4f 4d 49 6c 71 6b 42 34 57 47 30 67 79 67 56 64 } //333szAcSJAMrTuJxspf3crNTdFNCDqzbOMIlqkB4WG0gygVd  03 00 
		$a_80_1 = {50 78 43 70 79 49 36 34 } //PxCpyI64  03 00 
		$a_80_2 = {49 6d 6d 44 69 73 61 62 6c 65 49 4d 45 } //ImmDisableIME  03 00 
		$a_80_3 = {44 65 6c 65 74 65 45 6e 68 4d 65 74 61 46 69 6c 65 } //DeleteEnhMetaFile  03 00 
		$a_80_4 = {47 65 74 54 68 72 65 61 64 44 65 73 6b 74 6f 70 } //GetThreadDesktop  03 00 
		$a_80_5 = {47 65 74 53 74 6f 63 6b 4f 62 6a 65 63 74 } //GetStockObject  03 00 
		$a_80_6 = {49 73 43 68 61 72 41 6c 70 68 61 4e 75 6d 65 72 69 63 41 } //IsCharAlphaNumericA  03 00 
		$a_80_7 = {74 74 74 74 61 38 } //tttta8  00 00 
	condition:
		any of ($a_*)
 
}