
rule TrojanSpy_AndroidOS_Marcher_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Marcher.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 5f 73 6d 73 } //01 00 
		$a_01_1 = {68 69 64 65 6d 65 } //01 00 
		$a_01_2 = {73 65 74 4f 6e 43 61 72 64 4e 75 6d 62 65 72 } //01 00 
		$a_01_3 = {69 3c 3c 6d 57 38 3e 3e 6e 3c 3c 6d 57 38 3e 3e 6a 3c 3c 6d 57 38 3e 3e 65 3c 3c 6d 57 38 3e 3e 63 3c 3c 6d 57 38 3e 3e 74 3c 3c 6d 57 38 3e 3e 73 3c 3c 6d 57 38 3e 3e 46 3c 3c 6d 57 38 3e 3e 69 3c 3c 6d 57 38 3e 3e 6c 3c 3c 6d 57 38 3e 3e 6c 3c 3c 6d 57 38 3e 3e 65 3c 3c 6d 57 38 3e 3e 64 3c 3c 6d 57 38 3e 3e } //01 00 
		$a_01_4 = {69 3c 3c 6d 57 38 3e 3e 6e 3c 3c 6d 57 38 3e 3e 74 3c 3c 6d 57 38 3e 3e 65 3c 3c 6d 57 38 3e 3e 6e 3c 3c 6d 57 38 3e 3e 74 3c 3c 6d 57 38 3e 3e 5f 3c 3c 6d 57 38 3e 3e 77 3c 3c 6d 57 38 3e 3e 69 3c 3c 6d 57 38 3e 3e 74 3c 3c 6d 57 38 3e 3e 68 3c 3c 6d 57 38 3e 3e 5f 3c 3c 6d 57 38 3e 3e 63 3c 3c 6d 57 38 3e 3e 61 3c 3c 6d 57 38 3e 3e 72 3c 3c 6d 57 38 3e 3e 64 3c 3c 6d 57 38 3e 3e } //01 00 
		$a_01_5 = {73 3c 3c 6d 57 38 3e 3e 65 3c 3c 6d 57 38 3e 3e 6e 3c 3c 6d 57 38 3e 3e 64 3c 3c 6d 57 38 3e 3e 5f 3c 3c 6d 57 38 3e 3e 63 3c 3c 6d 57 38 3e 3e 61 3c 3c 6d 57 38 3e 3e 72 3c 3c 6d 57 38 3e 3e 64 3c 3c 6d 57 38 3e 3e 5f 3c 3c 6d 57 38 3e 3e 6e 3c 3c 6d 57 38 3e 3e 75 3c 3c 6d 57 38 3e 3e 6d 3c 3c 6d 57 38 3e 3e 62 3c 3c 6d 57 38 3e 3e 65 3c 3c 6d 57 38 3e 3e 72 3c 3c 6d 57 38 3e 3e } //00 00 
	condition:
		any of ($a_*)
 
}