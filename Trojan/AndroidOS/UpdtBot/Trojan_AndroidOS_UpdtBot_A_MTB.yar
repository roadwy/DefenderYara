
rule Trojan_AndroidOS_UpdtBot_A_MTB{
	meta:
		description = "Trojan:AndroidOS/UpdtBot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {61 69 6d 53 6d 73 } //1 aimSms
		$a_01_1 = {49 6e 74 65 72 66 61 63 65 2f 47 65 74 41 6e 64 72 6f 69 64 53 6d 73 2e 61 73 68 78 } //1 Interface/GetAndroidSms.ashx
		$a_00_2 = {6e 6f 6b 69 61 2d 75 70 67 72 61 64 65 2e 63 6f 6d } //1 nokia-upgrade.com
		$a_01_3 = {47 65 74 41 6e 64 72 6f 69 64 43 61 6c 6c } //1 GetAndroidCall
		$a_01_4 = {54 52 41 4e 53 41 43 54 49 4f 4e 5f 67 65 74 43 61 6c 6c 53 74 61 74 65 } //1 TRANSACTION_getCallState
		$a_00_5 = {73 6d 73 74 65 6c 70 68 6f 6e 65 61 70 70 } //1 smstelphoneapp
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}