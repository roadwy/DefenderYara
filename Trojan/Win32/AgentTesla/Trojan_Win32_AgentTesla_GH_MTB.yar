
rule Trojan_Win32_AgentTesla_GH_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 41 } //1 SetEnvironmentVariableA
		$a_01_1 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //1 GetWindowsDirectoryA
		$a_01_2 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //1 GetTempPathA
		$a_01_3 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_01_4 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //1 SeShutdownPrivilege
		$a_01_5 = {5c 54 65 6d 70 } //1 \Temp
		$a_01_6 = {49 6e 69 74 69 61 74 65 53 68 75 74 64 6f 77 6e 41 } //1 InitiateShutdownA
		$a_00_7 = {67 00 61 00 64 00 65 00 74 00 65 00 61 00 74 00 72 00 65 00 6e 00 65 00 73 00 20 00 6b 00 65 00 6d 00 69 00 6b 00 61 00 6c 00 69 00 65 00 61 00 66 00 66 00 61 00 6c 00 64 00 73 00 64 00 65 00 70 00 6f 00 74 00 65 00 74 00 } //1 gadeteatrenes kemikalieaffaldsdepotet
		$a_00_8 = {73 00 75 00 66 00 66 00 6c 00 61 00 74 00 65 00 20 00 63 00 61 00 72 00 70 00 65 00 6e 00 74 00 65 00 72 00 69 00 6e 00 67 00 } //1 sufflate carpentering
		$a_00_9 = {73 00 6c 00 65 00 74 00 66 00 69 00 6c 00 65 00 6e 00 65 00 } //1 sletfilene
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=10
 
}