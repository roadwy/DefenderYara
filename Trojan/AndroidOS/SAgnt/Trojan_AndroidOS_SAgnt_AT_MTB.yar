
rule Trojan_AndroidOS_SAgnt_AT_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AT!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 65 73 73 53 65 6e 64 53 6d 73 } //01 00  messSendSms
		$a_01_1 = {4c 69 6e 6b 48 61 79 41 6e 64 72 6f 69 64 41 63 74 69 76 69 74 79 } //01 00  LinkHayAndroidActivity
		$a_01_2 = {68 65 61 72 64 53 6d 73 37 } //01 00  heardSms7
		$a_01_3 = {74 6f 74 61 6c 73 6d 73 2e 74 78 74 } //01 00  totalsms.txt
		$a_01_4 = {63 6f 75 6e 74 53 65 6e 64 53 6d 73 } //01 00  countSendSms
		$a_01_5 = {73 65 6e 64 53 4d 53 } //00 00  sendSMS
	condition:
		any of ($a_*)
 
}