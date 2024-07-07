
rule TrojanDownloader_Win32_Hancitor_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Hancitor.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 43 72 61 63 6b 55 72 6c 41 } //1 InternetCrackUrlA
		$a_01_1 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {6b 72 72 65 77 69 61 6f 67 33 75 34 6e 70 63 67 2e 6f 6e 69 6f 6e 2e 74 6f 2f 73 6c 2f 67 61 74 65 2e 70 68 70 } //3 krrewiaog3u4npcg.onion.to/sl/gate.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*3) >=8
 
}