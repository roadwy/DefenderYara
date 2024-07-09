
rule Trojan_Win64_CobaltStrike_DZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 0f b6 4c 24 ?? 33 c1 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a 90 13 0f b7 44 24 ?? 66 ff c0 66 89 44 24 ?? 0f b7 44 24 ?? 0f b7 4c 24 ?? 3b c1 7d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_DZ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 4d 61 69 6e } //10 DllMain
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_81_2 = {68 6f 76 69 74 64 7a 2e 64 6c 6c } //1 hovitdz.dll
		$a_81_3 = {62 69 76 79 79 79 63 70 73 75 6c 78 67 79 67 67 } //1 bivyyycpsulxgygg
		$a_81_4 = {64 68 6f 71 77 6c 77 64 6c 63 61 70 } //1 dhoqwlwdlcap
		$a_81_5 = {64 6a 65 72 7a 72 67 66 67 73 68 6c } //1 djerzrgfgshl
		$a_81_6 = {64 6e 71 66 69 63 66 69 69 72 77 64 79 } //1 dnqficfiirwdy
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=25
 
}