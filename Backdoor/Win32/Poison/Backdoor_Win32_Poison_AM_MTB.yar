
rule Backdoor_Win32_Poison_AM_MTB{
	meta:
		description = "Backdoor:Win32/Poison.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 41 64 77 61 2e 65 78 65 } //1 AntiAdwa.exe
		$a_01_1 = {32 32 32 2e 65 78 65 } //1 222.exe
		$a_01_2 = {31 39 34 2e 31 34 36 00 00 00 00 00 2e 38 34 2e 33 } //1
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_4 = {50 72 6f 67 72 61 00 00 00 00 00 00 00 6d 44 61 74 61 5c 73 76 63 00 00 00 00 00 00 00 68 6f 73 74 2e 74 78 74 } //1
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}