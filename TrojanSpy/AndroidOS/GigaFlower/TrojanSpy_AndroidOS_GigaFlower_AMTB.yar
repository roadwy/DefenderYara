
rule TrojanSpy_AndroidOS_GigaFlower_AMTB{
	meta:
		description = "TrojanSpy:AndroidOS/GigaFlower!AMTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 4c 6f 63 6b 53 63 72 65 65 6e 50 61 73 73 77 6f 72 64 52 65 71 75 65 73 74 } //2 sendLockScreenPasswordRequest
		$a_01_1 = {31 38 2e 31 34 30 2e 34 2e 34 } //2 18.140.4.4
		$a_81_2 = {72 65 61 64 41 6e 64 53 65 6e 64 53 6d 73 } //1 readAndSendSms
		$a_81_3 = {4c 6f 61 64 41 70 70 73 49 6e 66 6f 54 61 73 6b } //1 LoadAppsInfoTask
		$a_81_4 = {69 73 41 63 63 65 73 73 69 62 69 6c 69 74 79 45 6e 61 62 6c 65 64 } //1 isAccessibilityEnabled
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}