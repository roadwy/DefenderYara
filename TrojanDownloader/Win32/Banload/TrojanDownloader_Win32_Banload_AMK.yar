
rule TrojanDownloader_Win32_Banload_AMK{
	meta:
		description = "TrojanDownloader:Win32/Banload.AMK,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 48 73 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 00 00 00 01 01 00 8c 53 65 6e 64 00 00 00 00 01 00 00 52 65 73 70 6f 6e 73 65 54 65 78 74 } //5
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 6d 73 6e 67 72 2e 65 78 65 } //1 Software\Classes\Applications\msngr.exe
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 } //1 SOFTWARE\Microsoft\Security Center
		$a_01_3 = {49 64 65 6e 74 69 74 79 20 50 72 6f 74 65 63 74 69 6f 6e 5c 41 67 65 6e 74 5c 42 69 6e 5c 41 56 47 49 44 53 41 67 65 6e 74 2e 65 78 65 } //1 Identity Protection\Agent\Bin\AVGIDSAgent.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}