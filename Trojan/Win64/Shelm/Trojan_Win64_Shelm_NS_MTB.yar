
rule Trojan_Win64_Shelm_NS_MTB{
	meta:
		description = "Trojan:Win64/Shelm.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {73 68 65 6c 6c 63 6f 64 65 } //2 shellcode
		$a_81_1 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_81_2 = {4c 64 72 70 44 6c 6c 4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 } //1 LdrpDllNotificationList
		$a_81_3 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_81_4 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 72 65 67 69 73 74 65 72 65 64 20 64 75 6d 6d 79 20 63 61 6c 6c 62 61 63 6b } //1 Successfully registered dummy callback
		$a_81_5 = {74 72 61 6d 70 6f 6c 69 6e 65 20 68 61 73 20 62 65 65 6e 20 77 72 69 74 74 65 6e 20 74 6f 20 72 65 6d 6f 74 65 20 70 72 6f 63 65 73 73 } //1 trampoline has been written to remote process
		$a_81_6 = {53 68 65 6c 6c 63 6f 64 65 20 68 61 73 20 62 65 65 6e 20 77 72 69 74 74 65 6e 20 74 6f 20 72 65 6d 6f 74 65 20 70 72 6f 63 65 73 73 } //1 Shellcode has been written to remote process
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}