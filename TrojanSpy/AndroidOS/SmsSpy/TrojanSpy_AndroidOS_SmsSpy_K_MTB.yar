
rule TrojanSpy_AndroidOS_SmsSpy_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsSpy.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6d 73 62 6f 6d 62 65 72 } //01 00 
		$a_01_1 = {63 6f 6d 2f 64 72 6e 75 6c 6c 2f 66 63 6d 2f 73 6d 73 52 65 63 65 69 76 65 72 } //01 00 
		$a_01_2 = {68 69 64 65 61 6c 6c } //01 00 
		$a_01_3 = {50 4f 53 54 5f 4e 4f 54 4f 46 4f 43 41 54 49 4f 4e 53 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_AndroidOS_SmsSpy_K_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmsSpy.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 6f 67 72 61 70 68 2e 61 6e 64 72 6f 69 64 2e 61 67 65 6e 74 } //01 00 
		$a_01_1 = {46 61 6b 65 20 41 72 63 68 } //01 00 
		$a_01_2 = {67 65 74 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_01_3 = {67 65 74 52 75 6e 6e 69 6e 67 5f 70 61 63 6b 61 67 65 73 } //01 00 
		$a_01_4 = {67 65 74 4d 65 73 73 61 67 65 } //01 00 
		$a_01_5 = {69 6e 73 74 61 6c 6c 4e 65 74 77 6f 72 6b 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_01_6 = {61 64 64 4c 6f 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}