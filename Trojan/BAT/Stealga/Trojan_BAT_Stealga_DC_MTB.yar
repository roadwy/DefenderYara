
rule Trojan_BAT_Stealga_DC_MTB{
	meta:
		description = "Trojan:BAT/Stealga.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffa0 00 ffffffa0 00 07 00 00 "
		
	strings :
		$a_81_0 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //100 api.telegram.org/bot
		$a_81_1 = {44 65 63 72 79 70 74 } //10 Decrypt
		$a_81_2 = {55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 45 78 74 65 6e 73 69 6f 6e 20 53 65 74 74 69 6e 67 73 } //10 User Data\Default\Local Extension Settings
		$a_81_3 = {63 68 61 74 5f 69 64 } //10 chat_id
		$a_81_4 = {63 68 72 6f 6d 65 2e 65 78 65 } //10 chrome.exe
		$a_81_5 = {6d 73 65 64 67 65 2e 65 78 65 } //10 msedge.exe
		$a_81_6 = {62 72 61 76 65 2e 65 78 65 } //10 brave.exe
	condition:
		((#a_81_0  & 1)*100+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*10) >=160
 
}