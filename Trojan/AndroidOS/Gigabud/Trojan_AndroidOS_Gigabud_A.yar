
rule Trojan_AndroidOS_Gigabud_A{
	meta:
		description = "Trojan:AndroidOS/Gigabud.A,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 74 69 6e 67 53 61 66 65 50 77 64 41 63 74 69 76 69 74 79 } //2 SettingSafePwdActivity
		$a_01_1 = {57 61 69 74 43 68 65 63 6b 41 63 74 69 76 69 74 79 } //2 WaitCheckActivity
		$a_01_2 = {71 75 65 72 79 50 65 72 6d 69 73 73 69 6f 6e 53 74 61 74 75 73 41 6e 64 53 74 61 72 74 4e 65 78 74 51 75 65 72 79 } //2 queryPermissionStatusAndStartNextQuery
		$a_01_3 = {69 73 48 61 76 65 53 65 6e 64 4d 73 67 } //2 isHaveSendMsg
		$a_01_4 = {63 6f 6e 74 72 6f 6c 6c 65 72 2f 54 6f 75 63 68 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 } //2 controller/TouchAccessibilityService
		$a_01_5 = {53 68 6f 77 42 61 6e 6b 44 46 } //2 ShowBankDF
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=10
 
}