
rule Trojan_AndroidOS_Rewardsteal_B{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 75 62 6d 69 74 43 6f 6e 74 61 63 74 4d 73 67 44 61 74 61 } //02 00  submitContactMsgData
		$a_01_1 = {47 65 74 4d 73 67 41 6e 64 43 6f 6e 74 61 63 74 41 63 74 69 76 69 74 79 } //02 00  GetMsgAndContactActivity
		$a_01_2 = {53 4d 53 72 65 63 65 69 76 65 72 4e 65 77 } //00 00  SMSreceiverNew
	condition:
		any of ($a_*)
 
}