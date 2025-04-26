
rule TrojanDownloader_Win32_Agent_AHF{
	meta:
		description = "TrojanDownloader:Win32/Agent.AHF,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {25 73 52 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 25 73 22 2c 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 %sRundll32.exe "%s%s",DllCanUnloadNow
		$a_00_1 = {52 55 4e 44 4c 4c 33 32 20 22 25 73 22 20 20 53 74 61 72 74 } //1 RUNDLL32 "%s"  Start
		$a_01_2 = {74 73 70 6f 70 2e 73 79 73 00 74 73 62 68 6f 2e 64 6c 6c 00 74 73 70 6f 70 64 6c 6c 2e 63 61 62 00 74 73 70 6f 70 73 79 73 2e 63 61 62 00 74 73 62 68 6f 2e 63 61 62 } //1
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_4 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //1 SYSTEM\CurrentControlSet\Services\%s
		$a_01_5 = {64 69 6e 73 74 6e 6f 77 } //1 dinstnow
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}