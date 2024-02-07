
rule TrojanSpy_AndroidOS_SmsThief_CA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.CA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 74 77 75 2e 69 6e 66 6f } //01 00  com.twu.info
		$a_00_1 = {53 6d 73 4f 62 73 65 72 76 65 72 } //01 00  SmsObserver
		$a_00_2 = {67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //01 00  getAllContacts
		$a_00_3 = {67 65 74 53 6d 73 49 6e 50 68 6f 6e 65 } //01 00  getSmsInPhone
		$a_00_4 = {43 73 69 6e 66 6f } //00 00  Csinfo
	condition:
		any of ($a_*)
 
}