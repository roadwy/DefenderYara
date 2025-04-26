
rule Backdoor_AndroidOS_Xhunter_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Xhunter.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 78 68 75 6e 74 65 72 2f 63 6c 69 65 6e 74 } //1 Lcom/xhunter/client
		$a_01_1 = {73 65 6e 64 44 61 74 61 54 6f 53 65 72 76 65 72 } //1 sendDataToServer
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 57 68 61 74 73 61 70 70 44 61 74 61 62 61 73 65 } //1 downloadWhatsappDatabase
		$a_01_3 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 41 70 70 73 } //1 getInstalledApps
		$a_01_4 = {78 68 75 6e 74 65 72 54 65 73 74 } //1 xhunterTest
		$a_01_5 = {73 6c 61 63 6b 68 6f 6f 6b } //1 slackhook
		$a_01_6 = {73 65 6e 64 53 4d 53 } //1 sendSMS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}