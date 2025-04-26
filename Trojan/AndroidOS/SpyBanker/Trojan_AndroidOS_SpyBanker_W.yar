
rule Trojan_AndroidOS_SpyBanker_W{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.W,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {4f 72 67 51 75 65 72 79 53 74 61 72 74 54 65 6d 70 44 61 74 65 } //2 OrgQueryStartTempDate
		$a_01_1 = {53 65 6e 64 50 68 6f 74 6f 41 6c 61 72 6d 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //2 SendPhotoAlarmBroadcastReceiver
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}