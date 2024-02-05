
rule TrojanSpy_AndroidOS_Banker_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 53 6d 73 49 6e 74 65 72 63 65 70 74 69 6f 6e 43 6f 6d 6d 61 6e 64 45 78 65 63 75 74 65 64 } //01 00 
		$a_01_1 = {67 65 74 43 61 6c 6c 4c 69 73 74 43 6f 6d 6d 61 6e 64 } //01 00 
		$a_01_2 = {6c 61 75 6e 63 68 41 70 70 43 6f 6d 6d 61 6e 64 45 78 65 63 75 74 65 64 } //01 00 
		$a_01_3 = {62 6f 74 5f 69 64 } //01 00 
		$a_01_4 = {73 65 6e 64 44 61 74 61 54 6f 53 65 72 76 65 72 } //01 00 
		$a_01_5 = {73 65 74 41 64 6d 69 6e 43 6f 6d 6d 61 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}