
rule TrojanSpy_AndroidOS_SMSAgnt_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSAgnt.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 62 79 73 73 61 6c 61 72 6d 79 2f 67 61 6c 6c 65 72 79 65 79 65 2f 47 61 6c 6c 65 72 79 45 79 65 55 69 } //01 00 
		$a_01_1 = {41 55 54 4f 46 49 4c 4c 5f 48 49 4e 54 5f 43 52 45 44 49 54 5f 43 41 52 44 5f 53 45 43 55 52 49 54 59 5f 43 4f 44 45 } //01 00 
		$a_01_2 = {67 65 6e 65 72 61 74 65 53 6d 73 4f 74 70 48 69 6e 74 46 6f 72 43 68 61 72 61 63 74 65 72 50 6f 73 69 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}