
rule TrojanDownloader_Win32_Agent_OR{
	meta:
		description = "TrojanDownloader:Win32/Agent.OR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 52 6f 6f 74 53 79 73 74 65 6d 25 5c 68 6f 6f 6b 2e 64 6c 6c } //1 %RootSystem%\hook.dll
		$a_01_1 = {2f 2f 78 63 2e 31 31 35 2e 62 7a 2f 74 6f 6f 6c 73 2e 65 78 65 } //1 //xc.115.bz/tools.exe
		$a_01_2 = {5c 75 73 65 72 69 6e 69 74 2e 65 78 65 } //1 \userinit.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}