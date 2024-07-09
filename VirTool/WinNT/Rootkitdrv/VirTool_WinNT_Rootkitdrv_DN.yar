
rule VirTool_WinNT_Rootkitdrv_DN{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.DN,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 07 00 00 "
		
	strings :
		$a_00_0 = {41 00 70 00 70 00 49 00 6e 00 69 00 74 00 5f 00 44 00 4c 00 4c 00 73 00 } //10 AppInit_DLLs
		$a_00_1 = {5a 77 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65 } //10 ZwQueryInformationFile
		$a_00_2 = {4e 44 49 53 5f 42 55 46 46 45 52 5f 54 4f 5f 53 50 41 4e 5f 50 41 47 45 53 } //10 NDIS_BUFFER_TO_SPAN_PAGES
		$a_00_3 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 75 00 73 00 65 00 72 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //10 \SystemRoot\System32\user32.dll
		$a_00_4 = {45 00 6e 00 66 00 6f 00 72 00 63 00 65 00 57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //10 EnforceWriteProtection
		$a_00_5 = {80 7a 01 ff 75 06 80 7a 02 25 74 05 } //1
		$a_02_6 = {80 3c 3b e9 75 ?? 8b 44 3b 01 8d 74 38 05 80 3e e9 75 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1) >=52
 
}