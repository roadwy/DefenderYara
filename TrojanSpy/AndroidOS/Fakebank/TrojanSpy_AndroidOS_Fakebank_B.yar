
rule TrojanSpy_AndroidOS_Fakebank_B{
	meta:
		description = "TrojanSpy:AndroidOS/Fakebank.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 5f 70 68 6f 6e 65 5f 69 6e 74 65 72 63 65 70 74 00 } //01 00  浣彤桰湯彥湩整捲灥t
		$a_01_1 = {63 6d 64 5f 73 74 61 72 74 5f 62 61 6e 6b 00 } //01 00 
		$a_01_2 = {63 6d 64 5f 62 61 6e 6b 5f 49 6e 74 65 72 63 65 70 74 00 } //02 00 
		$a_01_3 = {2d 2d 64 77 6f 6e 20 66 69 6e 69 73 68 65 64 2d 2d 00 } //02 00  ⴭ睤湯映湩獩敨ⵤ-
		$a_01_4 = {3a 38 38 38 38 2f 68 61 6e 61 2e 61 70 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}