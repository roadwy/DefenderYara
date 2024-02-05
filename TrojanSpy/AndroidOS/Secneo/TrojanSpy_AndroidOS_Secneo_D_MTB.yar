
rule TrojanSpy_AndroidOS_Secneo_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Secneo.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 61 73 5f 66 69 6c 65 6f 62 73 65 72 76 65 72 } //01 00 
		$a_00_1 = {2f 63 6f 6d 2e 73 65 63 6e 65 6f 2e 74 6d 70 } //01 00 
		$a_00_2 = {63 6f 6d 2f 73 65 63 73 68 65 6c 6c 2f 73 65 63 44 61 74 61 2f 46 69 6c 65 73 46 69 6c 65 4f 62 73 65 72 76 65 72 } //01 00 
		$a_00_3 = {50 61 73 73 77 6f 72 64 4f 62 73 65 72 76 65 72 } //01 00 
		$a_00_4 = {63 6f 6d 2e 67 73 6f 66 74 2e 41 53 45 50 71 } //00 00 
	condition:
		any of ($a_*)
 
}