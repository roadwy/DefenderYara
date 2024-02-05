
rule TrojanSpy_AndroidOS_Gugi_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Gugi.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {72 75 2e 64 72 69 6e 6b 2e 6c 69 6d 65 } //01 00 
		$a_00_1 = {73 65 74 5f 73 6d 73 5f 73 74 61 74 75 73 } //01 00 
		$a_00_2 = {73 65 74 5f 74 61 73 6b 5f 73 74 61 74 75 73 } //01 00 
		$a_00_3 = {38 30 2e 38 37 2e 32 30 35 2e 31 32 36 } //01 00 
		$a_00_4 = {65 78 69 73 74 5f 62 61 6e 6b 5f 61 70 70 } //01 00 
		$a_00_5 = {72 2e 64 2e 6c 2e 73 6d 73 5f 73 65 6e 74 } //01 00 
		$a_00_6 = {63 6c 69 65 6e 74 5f 70 61 73 73 77 6f 72 64 } //00 00 
	condition:
		any of ($a_*)
 
}