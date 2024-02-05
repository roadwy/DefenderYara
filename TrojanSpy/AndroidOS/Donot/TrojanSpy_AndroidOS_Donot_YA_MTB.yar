
rule TrojanSpy_AndroidOS_Donot_YA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Donot.YA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 63 74 65 61 74 24 61 2e 72 75 6e 28 29 } //01 00 
		$a_00_1 = {52 55 68 46 53 45 5a 4a 55 6b 64 43 56 6b 5a 47 52 46 4e 42 } //01 00 
		$a_00_2 = {52 55 68 46 53 45 5a 4a 56 55 56 4a 52 6b 56 47 52 46 4e 42 } //01 00 
		$a_01_3 = {57 61 70 70 48 6f 6c 64 65 72 2e 74 78 74 } //01 00 
		$a_01_4 = {6b 65 79 73 2e 74 78 74 } //01 00 
		$a_01_5 = {43 61 6c 6c 4c 6f 67 73 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}