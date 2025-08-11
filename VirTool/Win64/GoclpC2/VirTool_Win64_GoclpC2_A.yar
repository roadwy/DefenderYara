
rule VirTool_Win64_GoclpC2_A{
	meta:
		description = "VirTool:Win64/GoclpC2.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 } //1 .executeCommand
		$a_01_1 = {2e 67 65 74 50 72 6f 63 65 73 73 4c 69 73 74 } //1 .getProcessList
		$a_01_2 = {2e 4e 65 77 43 6c 69 65 6e 74 } //1 .NewClient
		$a_01_3 = {2e 4e 65 77 4b 65 79 6c 6f 67 67 65 72 } //1 .NewKeylogger
		$a_01_4 = {2e 64 65 74 65 63 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 } //1 .detectEnvironment
		$a_01_5 = {2e 74 65 73 74 43 6c 69 70 62 6f 61 72 64 52 65 64 69 72 65 63 74 69 6f 6e } //1 .testClipboardRedirection
		$a_01_6 = {2e 63 61 70 74 75 72 65 53 63 72 65 65 6e 73 68 6f 74 } //1 .captureScreenshot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}