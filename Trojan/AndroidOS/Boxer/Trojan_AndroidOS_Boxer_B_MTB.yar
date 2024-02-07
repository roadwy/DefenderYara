
rule Trojan_AndroidOS_Boxer_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Boxer.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 73 6f 66 74 77 61 72 65 2e 61 64 75 6c 74 } //02 00  com.software.adult
		$a_00_1 = {4b 45 59 5f 57 41 53 5f 4f 50 45 4e 45 44 } //01 00  KEY_WAS_OPENED
		$a_00_2 = {55 53 53 44 45 78 74 4e 65 74 53 76 63 } //01 00  USSDExtNetSvc
		$a_00_3 = {31 37 38 35 33 33 31 37 36 38 32 36 } //00 00  178533176826
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Boxer_B_MTB_2{
	meta:
		description = "Trojan:AndroidOS/Boxer.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 45 59 5f 4d 53 47 5f 44 41 54 41 5f 54 45 58 54 } //01 00  KEY_MSG_DATA_TEXT
		$a_01_1 = {62 65 67 69 6e 53 65 6e 64 69 6e 67 } //01 00  beginSending
		$a_01_2 = {73 63 68 65 64 75 6c 65 53 65 6e 64 69 6e 67 } //01 00  scheduleSending
		$a_01_3 = {73 65 6e 64 4f 70 65 6e 69 6e 67 } //01 00  sendOpening
		$a_01_4 = {73 6d 73 44 61 74 61 } //01 00  smsData
		$a_01_5 = {41 63 74 69 76 61 74 6f 72 53 65 72 76 69 63 65 } //01 00  ActivatorService
		$a_01_6 = {41 63 74 53 65 72 76 69 63 65 } //00 00  ActService
	condition:
		any of ($a_*)
 
}