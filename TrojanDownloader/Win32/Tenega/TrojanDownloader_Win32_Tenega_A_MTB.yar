
rule TrojanDownloader_Win32_Tenega_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tenega.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 05 00 00 "
		
	strings :
		$a_02_0 = {72 75 6e 67 2e 6b 72 2f 44 4f 57 4e 2f 90 02 0f 2e 65 78 65 90 00 } //20
		$a_81_1 = {53 65 63 75 72 69 74 79 48 65 61 6c 74 68 } //1 SecurityHealth
		$a_81_2 = {41 56 74 79 70 65 5f 69 6e 66 6f } //1 AVtype_info
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_02_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=24
 
}