
rule TrojanDropper_AndroidOS_Ingopack_D_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Ingopack.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 6d 61 67 6d 61 6d 6f 62 69 6c 65 2f 61 70 70 2f 6c 61 2f 63 6f 6e 6a 75 67 61 69 73 6f 6e } //0a 00 
		$a_02_1 = {63 6f 6d 2f 74 6f 75 74 61 70 70 72 65 6e 64 72 65 2f 90 02 10 41 70 70 6c 69 63 61 74 69 6f 6e 90 00 } //01 00 
		$a_00_2 = {2f 62 6f 6f 74 6c 6f 61 64 65 72 2e 64 65 78 } //01 00 
		$a_00_3 = {2f 2e 70 61 63 6b 65 72 } //01 00 
		$a_00_4 = {42 4f 4f 54 53 54 52 41 50 50 45 52 } //00 00 
	condition:
		any of ($a_*)
 
}