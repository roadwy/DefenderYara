
rule VirTool_Win64_Freyjaz_A_MTB{
	meta:
		description = "VirTool:Win64/Freyjaz.A!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 5f 65 78 65 63 75 74 6f 72 2e 52 75 6e } //1 powershell_executor.Run
		$a_01_1 = {63 6d 64 5f 65 78 65 63 75 74 6f 72 2e 52 75 6e } //1 cmd_executor.Run
		$a_01_2 = {4d 79 74 68 69 63 55 55 49 44 } //1 MythicUUID
		$a_01_3 = {53 65 6e 64 46 69 6c 65 54 6f 4d 79 74 68 69 63 } //1 SendFileToMythic
		$a_01_4 = {2e 53 65 74 4d 79 74 68 69 63 49 44 } //1 .SetMythicID
		$a_01_5 = {2e 53 65 74 53 6c 65 65 70 4a 69 74 74 65 72 } //1 .SetSleepJitter
		$a_01_6 = {2e 47 65 74 50 72 6f 63 65 73 73 4e 61 6d 65 } //1 .GetProcessName
		$a_01_7 = {73 6f 63 6b 73 2e 52 75 6e } //1 socks.Run
		$a_01_8 = {2e 4b 65 79 6c 6f 67 } //1 .Keylog
		$a_01_9 = {2e 49 73 45 6c 65 76 61 74 65 64 } //1 .IsElevated
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}