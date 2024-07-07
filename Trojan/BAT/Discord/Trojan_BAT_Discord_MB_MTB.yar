
rule Trojan_BAT_Discord_MB_MTB{
	meta:
		description = "Trojan:BAT/Discord.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {fa 01 33 00 16 90 01 02 01 90 01 03 36 90 01 03 05 90 01 03 0a 90 01 03 0f 90 01 03 07 90 01 03 4e 90 01 03 13 90 00 } //10
		$a_81_1 = {48 74 74 70 43 6c 69 65 6e 74 } //3 HttpClient
		$a_81_2 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //3 SecurityProtocolType
		$a_81_3 = {53 79 73 74 65 6d 2e 4e 65 74 } //3 System.Net
		$a_81_4 = {73 65 74 5f 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //3 set_SecurityProtocol
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=22
 
}
rule Trojan_BAT_Discord_MB_MTB_2{
	meta:
		description = "Trojan:BAT/Discord.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_03_0 = {0a 06 1f 20 28 90 01 03 2b 28 90 01 03 2b 0b 06 1f 20 28 90 01 03 2b 1f 20 28 90 01 03 2b 28 90 01 03 2b 0c 06 1f 40 28 90 01 03 2b 06 8e 69 1f 40 59 28 90 01 03 2b 28 90 01 03 2b 0d 03 07 20 e8 03 00 00 73 90 01 03 0a 13 04 90 00 } //1
		$a_01_1 = {59 00 4e 00 76 00 43 00 35 00 37 00 6c 00 57 00 31 00 7a 00 38 00 65 00 61 00 31 00 43 00 53 00 42 00 } //1 YNvC57lW1z8ea1CSB
		$a_01_2 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_6 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_7 = {73 65 6e 64 44 69 73 63 6f 72 64 57 65 62 68 6f 6f 6b } //1 sendDiscordWebhook
		$a_01_8 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_9 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}