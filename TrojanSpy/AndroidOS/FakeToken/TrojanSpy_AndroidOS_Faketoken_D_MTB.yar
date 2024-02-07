
rule TrojanSpy_AndroidOS_Faketoken_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Faketoken.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {35 30 11 00 13 03 19 00 6e 20 90 01 02 32 00 0a 03 8d 33 d8 03 03 61 8d 33 4f 03 01 00 d8 00 00 01 28 ef 22 00 59 00 70 20 90 01 02 10 00 11 00 90 00 } //01 00 
		$a_01_1 = {2f 73 65 72 76 69 63 65 2e 70 68 70 } //01 00  /service.php
		$a_01_2 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f } //00 00  content://sms/
	condition:
		any of ($a_*)
 
}