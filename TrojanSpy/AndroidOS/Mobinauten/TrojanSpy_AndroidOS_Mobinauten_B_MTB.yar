
rule TrojanSpy_AndroidOS_Mobinauten_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Mobinauten.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 69 6e 64 41 6e 64 53 65 6e 64 4c 6f 63 61 74 69 6f 6e } //01 00 
		$a_00_1 = {53 4d 53 53 50 59 } //01 00 
		$a_00_2 = {53 4d 53 5f 52 45 43 45 49 56 45 44 } //01 00 
		$a_00_3 = {6f 6e 53 74 61 72 74 43 6f 6d 6d 61 6e 64 } //01 00 
		$a_00_4 = {63 6f 6d 2f 64 65 2f 6d 6f 62 69 6e 61 75 74 65 6e 2f 73 6d 73 73 70 79 } //00 00 
	condition:
		any of ($a_*)
 
}