
rule TrojanSpy_AndroidOS_SmsThief_W_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.W!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {47 45 54 5f 41 4c 4c 5f 50 48 4f 5f 41 4e 44 5f 53 45 4e 54 53 4d 53 5f 4d 53 47 } //01 00 
		$a_00_1 = {63 6f 6e 74 61 63 74 5f 69 64 20 3d 20 } //01 00 
		$a_00_2 = {49 73 55 6e 69 73 74 61 6c 6c 65 72 } //01 00 
		$a_00_3 = {43 4f 4e 54 52 4f 4c 5f 4e 55 4d 42 45 52 } //01 00 
		$a_00_4 = {69 73 41 63 74 69 76 65 4e 65 74 77 6f 72 6b 4d 65 74 65 72 65 64 } //01 00 
		$a_00_5 = {73 65 6e 74 5f 73 6d 73 5f 61 63 74 69 6f 6e } //01 00 
		$a_00_6 = {49 73 46 69 72 73 74 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}