
rule TrojanDropper_AndroidOS_Ingopack_E_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Ingopack.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 6f 63 6c 61 73 73 6c 6f 61 64 65 72 2e 64 65 78 } //01 00 
		$a_00_1 = {2e 70 61 63 6b 65 72 } //01 00 
		$a_00_2 = {6c 69 62 64 65 78 6c 6f 61 64 } //01 00 
		$a_00_3 = {61 74 74 61 63 68 42 61 73 65 43 6f 6e 74 65 78 74 74 00 } //01 00 
		$a_00_4 = {43 48 45 43 4b 50 4f 49 4e 54 20 33 00 64 61 6c 76 69 6b 2f 73 79 73 74 65 6d 2f 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 00 } //01 00 
		$a_00_5 = {69 6d 61 67 69 6e 67 2f 70 6e 67 2f 50 6e 67 4d 65 74 61 64 61 74 61 52 65 61 64 65 72 } //00 00 
		$a_00_6 = {5d 04 00 00 } //64 12 
	condition:
		any of ($a_*)
 
}