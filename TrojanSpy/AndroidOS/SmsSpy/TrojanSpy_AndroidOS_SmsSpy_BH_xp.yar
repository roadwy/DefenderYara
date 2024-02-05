
rule TrojanSpy_AndroidOS_SmsSpy_BH_xp{
	meta:
		description = "TrojanSpy:AndroidOS/SmsSpy.BH!xp,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {6f 72 67 2f 72 65 64 2f 63 75 74 65 2f 61 63 74 69 76 69 74 79 } //01 00 
		$a_00_1 = {2f 41 6e 64 72 6f 69 64 2f 53 6d 61 2f 4c 6f 67 } //01 00 
		$a_00_2 = {53 6d 73 55 70 6c 6f 61 64 4d 61 6e 61 67 65 72 20 72 65 73 70 6f 6e 73 65 ef bc 9a } //01 00 
		$a_00_3 = {47 65 74 50 61 63 6b 61 67 65 4e 61 6d 65 53 65 72 76 69 63 65 } //01 00 
		$a_00_4 = {43 61 6c 6c 4c 6f 67 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_00_5 = {53 6d 73 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_00_6 = {43 6f 6e 74 61 63 74 55 70 6c 6f 61 64 4d 61 6e 61 67 65 72 20 72 65 73 70 6f 6e 73 65 ef bc 9a } //00 00 
		$a_00_7 = {5d 04 00 } //00 3d 
	condition:
		any of ($a_*)
 
}