
rule Trojan_Win64_Shlem_EH_MTB{
	meta:
		description = "Trojan:Win64/Shlem.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_81_0 = {4e 6a 63 7a 5a 54 46 68 4e 44 41 77 59 7a 59 7a 4e 6d 45 33 4e 44 4a 69 59 6a 6b 79 4d 44 51 34 59 54 4e 68 4f 47 4a 6b 4f 54 5a 6a 5a 54 6b 31 } //10 NjczZTFhNDAwYzYzNmE3NDJiYjkyMDQ4YTNhOGJkOTZjZTk1
		$a_81_1 = {59 32 56 6b 5a 57 4d 33 5a 6a 59 30 4f 57 51 79 4e 7a 45 77 4e 6a 64 6c 4d 47 56 6a 59 6a 41 35 59 6d 55 79 59 32 45 7a 59 6d 59 } //10 Y2VkZWM3ZjY0OWQyNzEwNjdlMGVjYjA5YmUyY2EzYmY
		$a_01_2 = {57 44 6e 73 4e 61 6d 65 43 6f 6d 70 61 72 65 } //1 WDnsNameCompare
		$a_01_3 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 5a 61 6e 61 62 61 7a 61 72 5f 53 71 75 61 72 65 } //1 TerminateProcessZanabazar_Square
		$a_01_4 = {61 64 78 61 65 73 61 76 78 65 6e 64 66 69 6e 66 6d 61 67 63 } //1 adxaesavxendfinfmagc
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}