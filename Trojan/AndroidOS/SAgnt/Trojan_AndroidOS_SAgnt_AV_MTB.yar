
rule Trojan_AndroidOS_SAgnt_AV_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AV!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 6e 64 72 65 73 7a 73 2e 73 6d 73 72 65 63 65 69 76 65 } //01 00  com.andreszs.smsreceive
		$a_01_1 = {53 4d 53 43 6f 6d 6d 75 6e 69 63 61 74 6f 72 } //01 00  SMSCommunicator
		$a_01_2 = {2f 61 70 69 2f 75 73 65 72 73 6d 73 2f 63 72 65 61 74 65 76 32 3f 75 73 65 72 49 64 3d } //01 00  /api/usersms/createv2?userId=
		$a_01_3 = {43 6f 6d 70 6f 73 65 53 4d 53 41 63 74 69 76 69 74 79 } //00 00  ComposeSMSActivity
	condition:
		any of ($a_*)
 
}