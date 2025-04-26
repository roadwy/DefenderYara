
rule Trojan_AndroidOS_Vidro_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Vidro.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {76 69 64 34 64 72 6f 69 64 2e 63 6f 6d 2f 70 69 6e 67 2f } //1 vid4droid.com/ping/
		$a_00_1 = {66 65 61 74 75 72 65 5f 73 6d 73 } //1 feature_sms
		$a_00_2 = {73 65 78 67 6f 65 73 6d 6f 62 69 6c 65 2e 6e 65 74 } //1 sexgoesmobile.net
		$a_00_3 = {66 6f 72 63 65 5f 75 70 64 61 74 65 } //1 force_update
		$a_00_4 = {42 69 6c 6c 69 67 4d 61 6e 61 67 65 72 } //1 BilligManager
		$a_00_5 = {4c 63 6f 6d 2f 76 69 64 34 64 72 6f 69 64 2f 53 6d 73 52 65 63 65 69 76 65 72 } //1 Lcom/vid4droid/SmsReceiver
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}