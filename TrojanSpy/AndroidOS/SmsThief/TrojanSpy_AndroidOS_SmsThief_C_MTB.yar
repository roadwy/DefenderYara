
rule TrojanSpy_AndroidOS_SmsThief_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 6e 65 64 50 68 6f 6e 65 } //01 00 
		$a_00_1 = {73 69 6d 75 6c 61 74 65 4b 65 79 73 74 72 6f 6b 65 } //01 00 
		$a_00_2 = {6d 61 69 6c 4d 73 67 } //01 00 
		$a_00_3 = {67 65 74 43 6f 6e 74 61 63 74 4e 61 6d 65 46 72 6f 6d 50 68 6f 6e 65 4e 75 6d } //01 00 
		$a_00_4 = {67 65 74 53 65 6e 64 53 65 72 76 65 72 53 6d 73 } //01 00 
		$a_00_5 = {73 65 6e 64 4b 65 79 44 6f 77 6e 55 70 53 79 6e 63 } //01 00 
		$a_00_6 = {73 6d 74 70 2e 71 71 2e 63 6f 6d } //00 00 
		$a_00_7 = {5d 04 00 00 40 9f } //04 80 
	condition:
		any of ($a_*)
 
}