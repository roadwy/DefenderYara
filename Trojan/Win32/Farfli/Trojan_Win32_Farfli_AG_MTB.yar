
rule Trojan_Win32_Farfli_AG_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 6d 73 65 73 2e 65 78 65 } //01 00  C:\WINDOWS\smses.exe
		$a_01_1 = {43 6f 6e 73 79 73 32 31 2e 64 6c 6c } //01 00  Consys21.dll
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_3 = {44 65 62 75 67 42 72 65 61 6b } //01 00  DebugBreak
		$a_01_4 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //01 00  QueryPerformanceCounter
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}