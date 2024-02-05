
rule TrojanSpy_AndroidOS_InfoStealer_AS_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4e 75 6d 43 6f 72 65 73 70 6f 6e 64 65 6e 74 3a 3a } //01 00 
		$a_00_1 = {44 65 76 69 63 65 49 4d 45 49 3d } //01 00 
		$a_00_2 = {55 53 45 5f 55 52 4c 5f 53 4d 53 } //01 00 
		$a_00_3 = {4f 62 6e 69 6c 69 6d 20 72 69 64 } //01 00 
		$a_00_4 = {49 6e 63 6f 6d 69 6e 67 20 53 4d 53 20 66 69 78 65 64 } //01 00 
		$a_00_5 = {53 45 4c 45 43 54 20 5f 69 64 2c 20 6d 73 67 64 61 74 61 2c 20 73 65 6e 64 65 64 20 46 52 4f 4d 20 6d 65 73 73 61 67 65 73 20 57 48 45 52 45 20 73 65 6e 64 65 64 3d 30 } //00 00 
	condition:
		any of ($a_*)
 
}