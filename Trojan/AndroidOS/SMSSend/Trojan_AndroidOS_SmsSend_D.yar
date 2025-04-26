
rule Trojan_AndroidOS_SmsSend_D{
	meta:
		description = "Trojan:AndroidOS/SmsSend.D,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 56 4d 6f 62 41 64 5f 41 70 70 5f 4b 65 79 } //1 PVMobAd_App_Key
		$a_00_1 = {53 45 4e 44 5f 43 45 4e 54 45 52 5f 43 4f 44 45 } //1 SEND_CENTER_CODE
		$a_00_2 = {6d 61 6b 65 53 75 72 65 55 70 64 61 74 65 } //1 makeSureUpdate
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}