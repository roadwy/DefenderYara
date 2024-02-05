
rule TrojanSpy_AndroidOS_SmsThief_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 61 76 65 5f 73 6d 73 2e 70 68 70 } //02 00 
		$a_00_1 = {65 78 74 72 61 63 74 4d 65 73 73 61 67 65 73 } //01 00 
		$a_01_2 = {52 45 51 55 45 53 54 5f 43 4f 44 45 5f 53 4d 53 5f 50 45 52 4d 49 53 53 49 4f 4e } //03 00 
		$a_00_3 = {62 72 2f 63 6f 6d 2f 68 65 6c 70 64 65 76 2f 6b 79 63 66 6f 72 6d 2f 72 65 63 65 69 76 65 72 2f 53 4d 53 52 65 63 65 69 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_AndroidOS_SmsThief_F_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 70 73 69 70 68 6f 6e 33 2f 66 69 72 65 62 61 73 65 6d 65 73 73 61 67 69 6e 67 } //01 00 
		$a_00_1 = {67 65 74 4c 61 73 74 53 6d 73 } //01 00 
		$a_00_2 = {67 65 74 41 6c 6c 53 4d 53 } //01 00 
		$a_00_3 = {67 65 74 63 6f 6e 74 61 63 74 73 } //01 00 
		$a_00_4 = {73 6d 63 6f 6e 74 61 63 74 73 } //01 00 
		$a_00_5 = {68 69 64 65 41 70 70 49 63 6f 6e } //01 00 
		$a_00_6 = {69 72 61 6e 2d 70 6f 74 2e 74 6b 2f 73 69 67 68 } //01 00 
		$a_00_7 = {74 65 73 74 2e 74 65 73 74 } //00 00 
		$a_00_8 = {5d 04 00 00 } //cd fa 
	condition:
		any of ($a_*)
 
}