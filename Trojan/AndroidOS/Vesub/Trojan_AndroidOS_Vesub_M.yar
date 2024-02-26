
rule Trojan_AndroidOS_Vesub_M{
	meta:
		description = "Trojan:AndroidOS/Vesub.M,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 79 73 2e 6d 6f 64 6f 62 6f 6d 2e 73 6d 73 32 2e 73 65 72 76 69 63 65 73 } //01 00  sys.modobom.sms2.services
		$a_01_1 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 50 75 73 68 4d 61 73 73 61 67 65 } //00 00  NotificationPushMassage
	condition:
		any of ($a_*)
 
}