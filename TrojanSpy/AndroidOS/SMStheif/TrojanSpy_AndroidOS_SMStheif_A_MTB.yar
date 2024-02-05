
rule TrojanSpy_AndroidOS_SMStheif_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMStheif.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 68 6f 6e 65 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_00_1 = {53 4d 53 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_00_2 = {67 65 74 53 6d 73 49 6e 50 68 6f 6e 65 } //01 00 
		$a_00_3 = {67 65 74 43 61 6c 6c 52 65 63 6f 72 64 49 6e 50 68 6f 6e 65 } //01 00 
		$a_00_4 = {53 65 6e 64 53 6d 73 52 65 63 65 69 76 65 72 } //01 00 
		$a_00_5 = {75 70 6c 6f 61 64 52 65 63 6f 72 64 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}