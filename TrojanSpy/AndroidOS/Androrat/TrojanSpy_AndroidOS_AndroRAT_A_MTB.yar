
rule TrojanSpy_AndroidOS_AndroRAT_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/AndroRAT.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 54 4f 50 5f 4d 4f 4e 49 54 4f 52 5f 53 4d 53 } //01 00 
		$a_00_1 = {47 45 54 5f 43 41 4c 4c 5f 4c 4f 47 53 } //01 00 
		$a_00_2 = {44 41 54 41 5f 4d 4f 4e 49 54 4f 52 5f 43 41 4c 4c } //01 00 
		$a_00_3 = {41 43 4b 5f 47 49 56 45 5f 43 41 4c 4c } //01 00 
		$a_00_4 = {4b 45 59 5f 53 45 4e 44 5f 4d 4d 53 5f 4e 55 4d 42 45 52 } //00 00 
	condition:
		any of ($a_*)
 
}