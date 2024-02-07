
rule Trojan_Win64_Cobaltstrike_DZ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 0a 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 4d 61 69 6e } //0a 00  DllMain
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_2 = {68 6f 76 69 74 64 7a 2e 64 6c 6c } //01 00  hovitdz.dll
		$a_81_3 = {62 69 76 79 79 79 63 70 73 75 6c 78 67 79 67 67 } //01 00  bivyyycpsulxgygg
		$a_81_4 = {64 68 6f 71 77 6c 77 64 6c 63 61 70 } //01 00  dhoqwlwdlcap
		$a_81_5 = {64 6a 65 72 7a 72 67 66 67 73 68 6c } //01 00  djerzrgfgshl
		$a_81_6 = {64 6e 71 66 69 63 66 69 69 72 77 64 79 } //00 00  dnqficfiirwdy
	condition:
		any of ($a_*)
 
}