
rule TrojanSpy_AndroidOS_Banker_AI_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AI!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 61 6e 6b 31 32 2e 70 68 70 3f 6d 3d 41 70 69 26 61 3d 53 6d 73 26 69 6d 73 69 3d } //1 bank12.php?m=Api&a=Sms&imsi=
		$a_01_1 = {53 4d 53 52 65 63 65 69 76 65 72 } //1 SMSReceiver
		$a_01_2 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } //1 setComponentEnabledSetting
		$a_01_3 = {62 61 6e 6b 63 61 72 64 } //1 bankcard
		$a_01_4 = {62 61 6e 6b 70 77 } //1 bankpw
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}