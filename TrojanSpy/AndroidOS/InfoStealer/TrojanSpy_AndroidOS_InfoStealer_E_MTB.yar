
rule TrojanSpy_AndroidOS_InfoStealer_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 74 73 66 73 61 74 73 61 67 2f } //01 00  Lcom/tsfsatsag/
		$a_00_1 = {71 75 65 72 79 43 6f 6e 74 61 63 74 50 68 6f 6e 65 4e 75 6d 62 65 72 } //01 00  queryContactPhoneNumber
		$a_00_2 = {65 6e 63 72 79 70 74 50 61 73 73 77 6f 72 64 } //01 00  encryptPassword
		$a_00_3 = {73 6d 73 5f 73 74 72 } //00 00  sms_str
		$a_00_4 = {5d 04 00 } //00 42 
	condition:
		any of ($a_*)
 
}