
rule Trojan_BAT_SpyNoon_NITs_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.NITs!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6f 70 79 46 72 6f 6d 53 63 72 65 65 6e } //2 CopyFromScreen
		$a_01_1 = {43 61 70 74 75 72 65 41 6e 64 53 65 6e 64 53 63 72 65 65 6e 73 68 6f 74 } //2 CaptureAndSendScreenshot
		$a_01_2 = {53 65 6e 64 54 6f 44 69 73 63 6f 72 64 57 65 62 68 6f 6f 6b 41 73 79 6e 63 } //2 SendToDiscordWebhookAsync
		$a_01_3 = {47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 } //1 GetProcessesByName
		$a_01_4 = {74 61 72 67 65 74 50 72 6f 63 65 73 73 4e 61 6d 65 73 } //1 targetProcessNames
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}