
rule TrojanSpy_AndroidOS_FakeCalls_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeCalls.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 79 4c 6f 67 5f 4d 61 69 6e 5f } //01 00 
		$a_01_1 = {4b 45 59 5f 55 50 4c 4f 41 44 5f 31 } //01 00 
		$a_01_2 = {4b 45 59 5f 53 52 43 5f 4e 55 4d 42 45 52 } //01 00 
		$a_01_3 = {4b 45 59 5f 54 45 4c 45 43 4f 4d 53 5f 4e 41 4d 45 31 } //01 00 
		$a_01_4 = {64 65 6c 65 74 65 53 4d 53 } //00 00 
	condition:
		any of ($a_*)
 
}